package base

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

type TopElectBlockHeader struct {
	Hash        common.Hash `json:"hash"`
	BlockNumber uint64      `json:"blockNumber"`
}

func EncodeHeader(header interface{}) ([]byte, error) {
	return rlp.EncodeToBytes(header)
}

func EncodeHeaders(headers interface{}) ([]byte, error) {
	return rlp.EncodeToBytes(headers)
}

func DecodeHeaders(data []byte, v interface{}) error {
	return rlp.DecodeBytes(data, v)
}

type BridgeState struct {
	LatestConfirmedHeight *big.Int `json:"latestconfrimedheight"`
	LatestSyncedHeight    *big.Int `json:"latestsyncedheight"`
	ConfirmState          string   `json:"confirmstate"`
	Msg                   string   `json:"errormsg"`
}
