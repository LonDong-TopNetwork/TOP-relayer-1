package eth2top

import (
	"context"
	"fmt"
	"io/ioutil"
	"math/big"
	"strings"
	"sync"
	"time"
	"toprelayer/base"
	"toprelayer/contract/topbridge"
	"toprelayer/relayer/eth2top/ethashapp"
	"toprelayer/sdk/ethsdk"
	"toprelayer/sdk/topsdk"
	"toprelayer/util"
	"toprelayer/wallet"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/wonderivan/logger"
)

const (
	METHOD_GETBRIDGESTATE = "getCurrentBlockHeight"
	SYNCHEADERS           = "syncBlockHeader"

	SUCCESSDELAY int64 = 5  //mainnet 120
	FATALTIMEOUT int64 = 24 //hours
	FORKDELAY    int64 = 5  //mainnet 10000 seconds
	ERRDELAY     int64 = 10
	CONFIRMDELAY int64 = 5

	BLOCKS_PER_EPOCH       uint64 = 30000
	BLOCKS_TO_END_OF_EPOCH uint64 = 5000
)

type Eth2TopRelayer struct {
	context.Context
	contract        common.Address
	chainId         uint64
	wallet          wallet.IWallet
	topsdk          *topsdk.TopSdk
	ethsdk          *ethsdk.EthSdk
	certaintyBlocks int
	subBatch        int
	verifyBlock     bool
	abi             abi.ABI
}

func (et *Eth2TopRelayer) Init(topUrl, ethUrl, keypath, pass, abipath string, chainid uint64, contract common.Address, batch, cert int, verify bool) error {
	topsdk, err := topsdk.NewTopSdk(topUrl)
	if err != nil {
		return err
	}
	ethsdk, err := ethsdk.NewEthSdk(ethUrl)
	if err != nil {
		return err
	}

	et.topsdk = topsdk
	et.ethsdk = ethsdk
	et.contract = contract
	et.chainId = chainid
	et.subBatch = batch
	et.certaintyBlocks = cert
	et.verifyBlock = verify

	w, err := wallet.NewWallet(topUrl, keypath, pass, chainid)
	if err != nil {
		return err
	}
	et.wallet = w
	a, err := initABI(abipath)
	if err != nil {
		return err
	}
	et.abi = a
	return nil
}

func initABI(abifile string) (abi.ABI, error) {
	abidata, err := ioutil.ReadFile(abifile)
	if err != nil {
		return abi.ABI{}, err
	}
	return abi.JSON(strings.NewReader(string(abidata)))
}

func (et *Eth2TopRelayer) ChainId() uint64 {
	return et.chainId
}

func (et *Eth2TopRelayer) submitEthHeader(header []byte, nonce uint64) (*types.Transaction, error) {
	logger.Info("Eth2TopRelayer submitEthHeader length: %v,chainid: %v", len(header), et.chainId)
	gaspric, err := et.wallet.GasPrice(context.Background())
	if err != nil {
		return nil, err
	}

	gaslimit, err := et.estimateGas(gaspric, header)
	if err != nil {
		logger.Error("estimateGas error:", err)
		return nil, err
	}

	capfee := big.NewInt(0).SetUint64(gaspric.Uint64())
	logger.Info("account[%v] nonce:%v,gaslimit:%v,capfee:%v", et.wallet.CurrentAccount().Address, nonce, gaslimit, capfee)

	//must init ops as bellow
	ops := &bind.TransactOpts{
		From:      et.wallet.CurrentAccount().Address,
		Nonce:     big.NewInt(0).SetUint64(nonce),
		GasLimit:  gaslimit,
		GasFeeCap: capfee,
		GasTipCap: big.NewInt(0),
		Signer:    et.signTransaction,
		Context:   context.Background(),
		NoSend:    true, //false: Send the transaction to the target chain by default; true: don't send
	}

	contractcaller, err := topbridge.NewTopBridgeTransactor(et.contract, et.topsdk)
	if err != nil {
		return nil, err
	}

	sigTx, err := contractcaller.SyncBlockHeader(ops, header) //AddLightClientBlock(ops, header)
	if err != nil {
		logger.Error("Eth2TopRelayer AddLightClientBlock:%v", err)
		return nil, err
	}
	// {
	// 	byt, err := sigTx.MarshalBinary()
	// 	if err != nil {
	// 		logger.Error("MarshalBinary error:", err)
	// 	}
	// 	logger.Debug("rawtx:", hexutil.Encode(byt))
	// }

	if ops.NoSend {
		err = util.VerifyEthSignature(sigTx)
		if err != nil {
			logger.Error("Eth2TopRelayer VerifyEthSignature error:", err)
			return nil, err
		}

		err := et.topsdk.SendTransaction(ops.Context, sigTx)
		if err != nil {
			logger.Error("Eth2TopRelayer SendTransaction error:", err)
			return nil, err
		}
	}

	logger.Debug("hash:%v", sigTx.Hash())
	return sigTx, nil
}

//callback function to sign tx before send.
func (et *Eth2TopRelayer) signTransaction(addr common.Address, tx *types.Transaction) (*types.Transaction, error) {
	acc := et.wallet.CurrentAccount()
	if strings.EqualFold(acc.Address.Hex(), addr.Hex()) {
		stx, err := et.wallet.SignTx(tx)
		if err != nil {
			return nil, err
		}
		return stx, nil
	}
	return nil, fmt.Errorf("address:%v not available", addr)
}

func (et *Eth2TopRelayer) getTopBridgeCurrentHeight() (uint64, error) {
	input, err := et.abi.Pack(METHOD_GETBRIDGESTATE, et.chainId)
	if err != nil {
		return 0, err
	}

	msg := ethereum.CallMsg{
		From: et.wallet.CurrentAccount().Address,
		To:   &et.contract,
		Data: input,
	}
	ret, err := et.topsdk.CallContract(context.Background(), msg, nil)
	if err != nil {
		return 0, err
	}

	return big.NewInt(0).SetBytes(ret).Uint64(), nil
}

func (et *Eth2TopRelayer) StartRelayer(wg *sync.WaitGroup) error {
	logger.Info("Start Eth2TopRelayer relayer... chainid: %v, subBatch: %v certaintyBlocks: %v", et.chainId, et.subBatch, et.certaintyBlocks)
	defer wg.Done()

	done := make(chan struct{})
	defer close(done)

	go func(done chan struct{}) {
		timeoutDuration := time.Duration(FATALTIMEOUT) * time.Hour
		timeout := time.NewTimer(timeoutDuration)
		defer timeout.Stop()
		logger.Info("Eth2TopRelayer set timeout: %v hours", FATALTIMEOUT)
		var delay time.Duration = time.Duration(1)

		for {
			time.Sleep(time.Second * delay)
			select {
			case <-timeout.C:
				done <- struct{}{}
				return
			default:
				destHeight, err := et.getTopBridgeCurrentHeight()
				if err != nil {
					logger.Error(err)
					delay = time.Duration(ERRDELAY)
					break
				}
				logger.Info("Eth2TopRelayer to destHeight: %v", destHeight)
				if destHeight == 0 {
					if set := timeout.Reset(timeoutDuration); !set {
						logger.Error("reset timeout falied!")
						delay = time.Duration(ERRDELAY)
						break
					}
					logger.Debug("eth2top not init yet")
					delay = time.Duration(ERRDELAY)
					break
				}
				srcHeight, err := et.ethsdk.BlockNumber(context.Background())
				if err != nil {
					logger.Error(err)
					delay = time.Duration(ERRDELAY)
					break
				}
				logger.Info("Eth2TopRelayer from ethHeight: %v", srcHeight)

				if destHeight+1+uint64(et.certaintyBlocks) > srcHeight {
					if set := timeout.Reset(timeoutDuration); !set {
						logger.Error("reset timeout falied!")
						delay = time.Duration(ERRDELAY)
						break
					}
					logger.Debug("height not satisfied, delay")
					delay = time.Duration(ERRDELAY)
					break
				}

				syncStartHeight := destHeight + 1
				syncNum := srcHeight - uint64(et.certaintyBlocks) - destHeight
				delay = time.Duration(SUCCESSDELAY)
				if syncNum > uint64(et.subBatch) {
					syncNum = uint64(et.subBatch)
					delay = time.Duration(CONFIRMDELAY)
				}
				syncEndHeight := syncStartHeight + syncNum - 1
				logger.Info("Eth2TopRelayer sync block header from %v to %v", syncStartHeight, syncEndHeight)

				hashes, err := et.signAndSendTransactions(syncStartHeight, syncEndHeight)
				if len(hashes) > 0 {
					if set := timeout.Reset(timeoutDuration); !set {
						logger.Error("reset timeout falied!")
						delay = time.Duration(ERRDELAY)
						break
					}
					logger.Info("Eth2TopRelayer sync finish", syncStartHeight, syncEndHeight)
					delay = time.Duration(SUCCESSDELAY)
					break
				}
				if err != nil {
					logger.Error("Eth2TopRelayer signAndSendTransactions failed:%v", err)
					delay = time.Duration(ERRDELAY)
					break
				}
				//eth fork?
				logger.Warn("eth chain reverted?,syncStartHeight[%v] > ethConfirmedBlockHeight[%v]", syncStartHeight, syncEndHeight)
				delay = time.Duration(FORKDELAY)
			}
		}
	}(done)

	<-done
	logger.Error("relayer [%v] timeout.", et.chainId)
	return nil
}

func (et *Eth2TopRelayer) batch(headers []*types.Header, nonce uint64) (common.Hash, error) {
	// logger.Info("batch headers number:", len(headers))
	if et.chainId == base.TOP && et.verifyBlock {
		for _, header := range headers {
			et.verifyBlocks(header)
		}
	}
	data, err := base.EncodeHeaders(headers)
	if err != nil {
		logger.Error("Eth2TopRelayer EncodeHeaders failed:", err)
		return common.Hash{}, err
	}
	tx, err := et.submitEthHeader(data, nonce)
	if err != nil {
		logger.Error("Eth2TopRelayer submitHeaders failed:", err)
		return common.Hash{}, err
	}
	return tx.Hash(), nil
}

// func (et *Eth2TopRelayer) ethashProofs(h uint64, header *types.Header) (Output, error) {
// 	// var header *types.Header
// 	// if err := rlp.DecodeBytes(rlpheader, &header); err != nil {
// 	// 	logger.Error("RLP decoding of header failed: ", err)
// 	// 	return Output{}, err
// 	// }
// 	epoch := h / BLOCKS_PER_EPOCH
// 	cache, err := ethashproof.LoadCache(int(epoch))
// 	if err != nil {
// 		logger.Info("Cache is missing, calculate dataset merkle tree to create the cache first...")
// 		_, err = ethashproof.CalculateDatasetMerkleRoot(epoch, true)
// 		if err != nil {
// 			logger.Error("Creating cache failed: ", err)
// 			return Output{}, err
// 		}
// 		cache, err = ethashproof.LoadCache(int(epoch))
// 		if err != nil {
// 			logger.Error("Getting cache failed after trying to create it, abort: ", err)
// 			return Output{}, err
// 		}
// 	}

// 	// Remove outdated epoch
// 	if epoch > 1 {
// 		outdatedEpoch := epoch - 2
// 		err = os.Remove(ethash.PathToDAG(outdatedEpoch, ethash.DefaultDir))
// 		if err != nil {
// 			if os.IsNotExist(err) {
// 				logger.Info("DAG for previous epoch does not exist, nothing to remove: ", outdatedEpoch)
// 			} else {
// 				logger.Error("Remove DAG: ", err)
// 			}
// 		}

// 		err = os.Remove(ethashproof.PathToCache(outdatedEpoch))
// 		if err != nil {
// 			if os.IsNotExist(err) {
// 				logger.Info("Cache for previous epoch does not exist, nothing to remove: ", outdatedEpoch)
// 			} else {
// 				logger.Error("Remove cache error: ", err)
// 			}
// 		}
// 	}

// 	logger.Debug("SealHash: ", ethash.Instance.SealHash(header))
// 	indices := ethash.Instance.GetVerificationIndices(
// 		h,
// 		ethash.Instance.SealHash(header),
// 		header.Nonce.Uint64(),
// 	)
// 	logger.Debug("Proof length: ", cache.ProofLength)
// 	bytes, err := rlp.EncodeToBytes(header)
// 	if err != nil {
// 		logger.Error("RLP decoding of header failed: ", err)
// 		return Output{}, err
// 	}
// 	output := Output{
// 		HeaderRLP:    hexutil.Encode(bytes),
// 		MerkleRoot:   cache.RootHash.Hex(),
// 		Elements:     []string{},
// 		MerkleProofs: []string{},
// 		ProofLength:  cache.ProofLength,
// 	}
// 	for _, index := range indices {
// 		element, proof, err := ethashproof.CalculateProof(h, index, cache)
// 		if err != nil {
// 			logger.Error("calculating the proofs failed for index: %d, error: %s", index, err)
// 			return Output{}, err
// 		}
// 		es := element.ToUint256Array()
// 		for _, e := range es {
// 			output.Elements = append(output.Elements, hexutil.EncodeBig(e))
// 		}
// 		allProofs := []*big.Int{}
// 		for _, be := range mtree.HashesToBranchesArray(proof) {
// 			allProofs = append(allProofs, be.Big())
// 		}
// 		for _, pr := range allProofs {
// 			output.MerkleProofs = append(output.MerkleProofs, hexutil.EncodeBig(pr))
// 		}
// 	}

// 	return output, nil
// }

func (et *Eth2TopRelayer) detailsByNumber(h uint64, header *types.Header) (ethashapp.Output, error) {
	// currentEpoch := h / BLOCKS_PER_EPOCH
	// remBlocksToEndOfEpoch := BLOCKS_PER_EPOCH - (h % BLOCKS_PER_EPOCH)
	// nextEpoch := currentEpoch + 1

	return ethashapp.EthashWithProofs(h, header)
}

func (et *Eth2TopRelayer) signAndSendTransactions(lo, hi uint64) ([]common.Hash, error) {
	logger.Info("signAndSendTransactions height from:%v,to:%v", lo, hi)
	var batchHeaders []*types.Header
	var hashes []common.Hash
	nonce, err := et.wallet.GetNonce(et.wallet.CurrentAccount().Address)
	if err != nil {
		logger.Error(err)
		return hashes, err
	}
	h := lo
	for ; h <= hi; h++ {
		header, err := et.ethsdk.HeaderByNumber(context.Background(), big.NewInt(0).SetUint64(h))
		if err != nil {
			logger.Error(err)
			return hashes, err
		}
		// ethashproof, err := ethashapp.EthashWithProofs(h, header)
		// if err != nil {
		// 	logger.Error(err)
		// 	return hashes, err
		// }
		// // fmt.Printf("ethashproof: %v", ethashproof)
		// // os.Exit(0)
		batchHeaders = append(batchHeaders, header)
	}
	hash, err := et.batch(batchHeaders, nonce)
	if err != nil {
		return hashes, err
	}

	hashes = append(hashes, hash)
	return hashes, nil
}

func (et *Eth2TopRelayer) verifyBlocks(header *types.Header) error {
	return nil
}

func (et *Eth2TopRelayer) estimateGas(gasprice *big.Int, data []byte) (uint64, error) {
	input, err := et.abi.Pack(SYNCHEADERS, data)
	if err != nil {
		return 0, err
	}

	// capfee := big.NewInt(0).SetUint64(base.GetChainGasCapFee(et.chainId))
	callmsg := ethereum.CallMsg{
		From:      et.wallet.CurrentAccount().Address,
		To:        &et.contract,
		GasPrice:  gasprice,
		Gas:       0,
		GasFeeCap: nil,
		GasTipCap: nil,
		Data:      input,
	}

	return et.topsdk.EstimateGas(context.Background(), callmsg)
}
