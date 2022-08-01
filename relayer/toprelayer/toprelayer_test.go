package toprelayer

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"testing"
	"time"
	"toprelayer/config"
	"toprelayer/contract/top/ethclient"
	"toprelayer/relayer/toprelayer/ethashapp"
	"toprelayer/sdk/ethsdk"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/wonderivan/logger"
	"golang.org/x/crypto/sha3"
)

// main net
// https://api.mycryptoapi.com/eth
// https://web3.1inch.exchange/
// https://eth-mainnet.gateway.pokt.network/v1/5f3453978e354ab992c4da79
// https://eth-mainnet.token.im

// testnet
// https://ropsten.infura.io/v3/fb2a09e82a234971ad84203e6f75990e

// const ethUrl string = "https://eth-mainnet.token.im"
const ethUrl = "https://http-mainnet.hecochain.com"
const topChainId uint64 = 1023
const defaultPass = "asd123"

func TestGetHeaderRlp(t *testing.T) {
	var height uint64 = 17275820

	ethsdk, err := ethsdk.NewEthSdk(ethUrl)
	if err != nil {
		t.Fatal("NewEthSdk: ", err)
	}
	header, err := ethsdk.HeaderByNumber(context.Background(), big.NewInt(0).SetUint64(height))
	if err != nil {
		t.Fatal("HeaderByNumber: ", err)
	}
	data, err := rlp.EncodeToBytes(header)
	if err != nil {
		t.Fatal("EncodeToBytes: ", err)
	}
	t.Log("headers hex data:", common.Bytes2Hex(data))
}

func TestGetHeadersWithProofsRlp(t *testing.T) {
	var start_height uint64 = 12970000
	var sync_num uint64 = 1

	ethsdk, err := ethsdk.NewEthSdk(ethUrl)
	if err != nil {
		t.Fatal("NewEthSdk: ", err)
	}

	var batch []byte
	for h := start_height; h <= start_height+sync_num-1; h++ {
		header, err := ethsdk.HeaderByNumber(context.Background(), big.NewInt(0).SetUint64(h))
		if err != nil {
			t.Fatal("HeaderByNumber: ", err)
		}
		out, err := ethashapp.EthashWithProofs(h, header)
		if err != nil {
			t.Fatal("HeaderByNumber: ", err)
		}
		rlp_bytes, err := rlp.EncodeToBytes(out)
		if err != nil {
			t.Fatal("rlp encode error: ", err)
		}
		batch = append(batch, rlp_bytes...)
	}
	fmt.Println("rlp output: ", common.Bytes2Hex(batch))
}

func TestGetInitTxData(t *testing.T) {
	var height uint64 = 12622433

	ethsdk, err := ethsdk.NewEthSdk(ethUrl)
	if err != nil {
		t.Fatal("NewEthSdk: ", err)
	}
	header, err := ethsdk.HeaderByNumber(context.Background(), big.NewInt(0).SetUint64(height))
	if err != nil {
		t.Fatal("HeaderByNumber: ", err)
	}
	rlp_bytes, err := rlp.EncodeToBytes(header)
	if err != nil {
		t.Fatal("EncodeToBytes: ", err)
	}
	logger.Debug("rlp_bytes:", common.Bytes2Hex(rlp_bytes))
	input, err := ethclient.PackSyncParam(rlp_bytes)
	if err != nil {
		t.Fatal(err)
	}
	logger.Debug("data:", common.Bytes2Hex(input))
}

func TestGetSyncTxData(t *testing.T) {
	// changable
	var start_height uint64 = 12970000
	var sync_num uint64 = 1

	ethsdk, err := ethsdk.NewEthSdk(ethUrl)
	if err != nil {
		t.Fatal("NewEthSdk: ", err)
	}
	var batch []byte
	for h := start_height; h <= start_height+sync_num-1; h++ {
		header, err := ethsdk.HeaderByNumber(context.Background(), big.NewInt(0).SetUint64(h))
		if err != nil {
			t.Fatal("HeaderByNumber: ", err)
		}
		out, err := ethashapp.EthashWithProofs(h, header)
		if err != nil {
			t.Fatal("HeaderByNumber: ", err)
		}
		rlp_bytes, err := rlp.EncodeToBytes(out)
		if err != nil {
			t.Fatal("rlp encode error: ", err)
		}
		batch = append(batch, rlp_bytes...)
	}
	input, err := ethclient.PackSyncParam(batch)
	if err != nil {
		t.Fatal(err)
	}
	logger.Debug("data:", common.Bytes2Hex(input))
}

func TestGetHeightTxData(t *testing.T) {
	input, err := ethclient.PackGetHeightParam()
	if err != nil {
		t.Fatal(err)
	}
	logger.Debug("data:", common.Bytes2Hex(input))
}

func TestGetIsConfirmedTxData(t *testing.T) {
	height := big.NewInt(12970000)
	hash := common.HexToHash("13049bb8cfd97fe2333829f06df37c569db68d42c23097fbac64f2c61471f281")
	input, err := ethclient.PackIsKnownParam(height, hash)
	if err != nil {
		t.Fatal(err)
	}
	logger.Debug("data:", common.Bytes2Hex(input))
}

func TestSync(t *testing.T) {
	// changable
	var height uint64 = 12970030
	var topUrl string = "http://192.168.50.167:8080"
	var keyPath = "../../.relayer/wallet/top"

	cfg := &config.Relayer{
		Url:     topUrl,
		ChainId: topChainId,
		KeyPath: keyPath,
	}
	topRelayer := &TopRelayer{}
	err := topRelayer.Init(config.ETH_CHAIN, cfg, ethUrl, defaultPass)
	if err != nil {
		t.Fatal(err)
	}
	for h := height; h < 12970100; h++ {
		err = topRelayer.signAndSendTransactions(h, h)
		if err != nil {
			t.Fatal("submitEthHeader:", err)
		}
		time.Sleep(time.Second * 30)
	}
}

func TestSyncHeaderWithProofsRlpGas(t *testing.T) {
	// changable
	var height uint64 = 12970000
	var topUrl string = "http://192.168.30.200:8080"
	var keyPath = "../../.relayer/wallet/top"

	cfg := &config.Relayer{
		Url:     topUrl,
		ChainId: topChainId,
		KeyPath: keyPath,
	}
	topRelayer := &TopRelayer{}
	err := topRelayer.Init(config.ETH_CHAIN, cfg, ethUrl, defaultPass)
	if err != nil {
		t.Fatal(err)
	}
	header, err := topRelayer.ethsdk.HeaderByNumber(context.Background(), big.NewInt(0).SetUint64(height))
	if err != nil {
		t.Fatal("HeaderByNumber: ", err)
	}
	out, err := ethashapp.EthashWithProofs(height, header)
	if err != nil {
		t.Fatal("HeaderByNumber: ", err)
	}
	rlp_bytes, err := rlp.EncodeToBytes(out)
	if err != nil {
		t.Fatal("rlp encode error: ", err)
	}
	gaspric, err := topRelayer.wallet.GasPrice(context.Background())
	if err != nil {
		logger.Fatal(err)
	}
	packHeader, err := ethclient.PackSyncParam(rlp_bytes)
	if err != nil {
		logger.Fatal(err)
	}
	gaslimit, err := topRelayer.wallet.EstimateGas(context.Background(), &topRelayer.contract, gaspric, packHeader)
	if err != nil {
		logger.Fatal(err)
	}
	fmt.Println("gaslimit: ", gaslimit)
}

func TestGetEthClientHeight(t *testing.T) {
	// changable
	var topUrl string = "http://192.168.30.200:8080"
	var keyPath = "../../.relayer/wallet/top"

	cfg := &config.Relayer{
		Url:     topUrl,
		ChainId: topChainId,
		KeyPath: keyPath,
	}
	topRelayer := &TopRelayer{}
	err := topRelayer.Init(config.ETH_CHAIN, cfg, ethUrl, defaultPass)
	if err != nil {
		t.Fatal(err)
	}
	destHeight, err := topRelayer.callerSession.GetHeight()
	if err != nil {
		t.Fatal(err)
	}
	t.Log("current height:", destHeight)
}

type Snapshot struct {
	Number     uint64                      `json:"number"`     // Block number where the snapshot was created
	Hash       common.Hash                 `json:"hash"`       // Block hash where the snapshot was created
	Validators map[common.Address]struct{} `json:"validators"` // Set of authorized validators at this moment
	Recents    map[uint64]common.Address   `json:"recents"`    // Set of recent validators for spam protections
}

type SnapshotOut struct {
	HeaderRLP     []byte
	Number        uint64
	Hash          []byte
	ValidatorsNum uint64
	Validators    [][]byte
	RecentsNum    uint64
	Recents       [][]byte
}

type InitOut struct {
	HeaderRLP []byte
	Hash      []byte
}

func TestGetInitOutData(t *testing.T) {
	snap := new(InitOut)
	snap.HeaderRLP = common.Hex2Bytes("f9025fa08dc59c44d8f2b880dd15645b02192e590604fe0da2a36e9cb4aedb72a63bd8dea01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794140a9c525b8825b4d2a9f665ddfafb404fc7c4f5a0c006bb1297601f52e4180d35c00b8b5a7a09ee57e17b53ec9537998e8040859fa02a6645b4bd5de63016c3f9e7170a96c6a8e4b802ec4a9b7a9aeac5faef2a6819a04cf972ed0f20c06233dd8012e24bf8d22a1ffaffa55d4220f63d3c6603de3ccab901000100120000000000400010000020000100000000084000000000100008200080430050000000000028100004201002000000020084020000001000001031000100002000000240040020002d0022800000001080010000000280047500004880000000000210000020000000000208100100010208040002000000b04800000000000080000000000840000000040a00002004800002142420004800800200004210002110000004000000100000004000000000c421000040001000000009000000000200000000010000000c0000000041120420000001400000000800610080100000000000e0000005000000002002080000000000102000000400020001028401079bac8402625a00831e338f8462de153ab861d883010202846765746888676f312e31372e33856c696e757800000000000000029a82e55d1d25a1354533a1bc75717d6de318bc0d84df37e3e333eb97479a7160bb67013d6b2fdec39e7e6262a812c8b3f28861dcfb07ac7d6237b0843ab6b201a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080")
	snap.Hash = common.HexToHash("0x9b253032f692647599d53f2fe1418538431752872b307042e09994c31f14ba53").Bytes()
	b, err := rlp.EncodeToBytes(snap)
	if err != nil {
		t.Fatal(err)
	}

	logger.Debug("data:", common.Bytes2Hex(b))
}

func TestGetSnapShot(t *testing.T) {
	snap := new(SnapshotOut)
	snap.HeaderRLP = common.Hex2Bytes("f9025fa08dc59c44d8f2b880dd15645b02192e590604fe0da2a36e9cb4aedb72a63bd8dea01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794140a9c525b8825b4d2a9f665ddfafb404fc7c4f5a0c006bb1297601f52e4180d35c00b8b5a7a09ee57e17b53ec9537998e8040859fa02a6645b4bd5de63016c3f9e7170a96c6a8e4b802ec4a9b7a9aeac5faef2a6819a04cf972ed0f20c06233dd8012e24bf8d22a1ffaffa55d4220f63d3c6603de3ccab901000100120000000000400010000020000100000000084000000000100008200080430050000000000028100004201002000000020084020000001000001031000100002000000240040020002d0022800000001080010000000280047500004880000000000210000020000000000208100100010208040002000000b04800000000000080000000000840000000040a00002004800002142420004800800200004210002110000004000000100000004000000000c421000040001000000009000000000200000000010000000c0000000041120420000001400000000800610080100000000000e0000005000000002002080000000000102000000400020001028401079bac8402625a00831e338f8462de153ab861d883010202846765746888676f312e31372e33856c696e757800000000000000029a82e55d1d25a1354533a1bc75717d6de318bc0d84df37e3e333eb97479a7160bb67013d6b2fdec39e7e6262a812c8b3f28861dcfb07ac7d6237b0843ab6b201a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080")
	snap.Number = 17275820
	snap.Hash = common.HexToHash("0x9b253032f692647599d53f2fe1418538431752872b307042e09994c31f14ba53").Bytes()
	snap.ValidatorsNum = 3
	snap.Validators = append(snap.Validators, common.HexToAddress("0xff00000000000000000000000000000000000002").Bytes())
	snap.Validators = append(snap.Validators, common.HexToAddress("0xff00000000000000000000000000000000000003").Bytes())
	snap.Validators = append(snap.Validators, common.HexToAddress("0xff00000000000000000000000000000000000004").Bytes())
	snap.RecentsNum = 3
	var buf = make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(998))
	snap.Recents = append(snap.Recents, buf)
	snap.Recents = append(snap.Recents, common.HexToAddress("0xff00000000000000000000000000000000000002").Bytes())
	binary.BigEndian.PutUint64(buf, uint64(999))
	snap.Recents = append(snap.Recents, buf)
	snap.Recents = append(snap.Recents, common.HexToAddress("0xff00000000000000000000000000000000000003").Bytes())
	binary.BigEndian.PutUint64(buf, uint64(1000))
	snap.Recents = append(snap.Recents, buf)
	snap.Recents = append(snap.Recents, common.HexToAddress("0xff00000000000000000000000000000000000004").Bytes())

	b, err := rlp.EncodeToBytes(snap)
	if err != nil {
		t.Fatal(err)
	}

	logger.Debug("data:", common.Bytes2Hex(b))
}

const extraSeal = 64 + 1

func encodeSigHeader(w io.Writer, header *types.Header) {
	err := rlp.Encode(w, []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra[:len(header.Extra)-crypto.SignatureLength], // Yes, this will panic if extra is too short
		header.MixDigest,
		header.Nonce,
	})
	if err != nil {
		panic("can't encode: " + err.Error())
	}
}

// SealHash returns the hash of a block prior to it being sealed.
func SealHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()
	encodeSigHeader(hasher, header)
	hasher.Sum(hash[:0])
	return hash
}

func ecrecover(header *types.Header) (common.Address, error) {
	// Retrieve the signature from the header extra-data
	if len(header.Extra) < extraSeal {
		return common.Address{}, fmt.Errorf("error header")
	}
	signature := header.Extra[len(header.Extra)-extraSeal:]

	logger.Debug("sig:", signature)
	seal_hash := SealHash(header)
	logger.Debug("seal_hash:", seal_hash)
	// Recover the public key and the Ethereum address
	pubkey, err := crypto.Ecrecover(seal_hash.Bytes(), signature)
	if err != nil {
		return common.Address{}, err
	}
	logger.Debug("pub_key:", pubkey)
	var validator common.Address
	copy(validator[:], crypto.Keccak256(pubkey[1:])[12:])

	return validator, nil
}

func TestEcrecover(t *testing.T) {
	rlp_bytes := common.Hex2Bytes("f9025fa08dc59c44d8f2b880dd15645b02192e590604fe0da2a36e9cb4aedb72a63bd8dea01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794140a9c525b8825b4d2a9f665ddfafb404fc7c4f5a0c006bb1297601f52e4180d35c00b8b5a7a09ee57e17b53ec9537998e8040859fa02a6645b4bd5de63016c3f9e7170a96c6a8e4b802ec4a9b7a9aeac5faef2a6819a04cf972ed0f20c06233dd8012e24bf8d22a1ffaffa55d4220f63d3c6603de3ccab901000100120000000000400010000020000100000000084000000000100008200080430050000000000028100004201002000000020084020000001000001031000100002000000240040020002d0022800000001080010000000280047500004880000000000210000020000000000208100100010208040002000000b04800000000000080000000000840000000040a00002004800002142420004800800200004210002110000004000000100000004000000000c421000040001000000009000000000200000000010000000c0000000041120420000001400000000800610080100000000000e0000005000000002002080000000000102000000400020001028401079bac8402625a00831e338f8462de153ab861d883010202846765746888676f312e31372e33856c696e757800000000000000029a82e55d1d25a1354533a1bc75717d6de318bc0d84df37e3e333eb97479a7160bb67013d6b2fdec39e7e6262a812c8b3f28861dcfb07ac7d6237b0843ab6b201a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080")

	header := new(types.Header)
	rlp.DecodeBytes(rlp_bytes, &header)

	addr, err := ecrecover(header)
	if err != nil {
		t.Fatal(err)
	}
	logger.Debug("address:", addr)
}
