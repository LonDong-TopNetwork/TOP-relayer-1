package toprelayer

import (
	"context"
	"fmt"
	"math/big"
	"strconv"
	"toprelayer/relayer/toprelayer/beaconrpc"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	primitives "github.com/prysmaticlabs/prysm/v3/consensus-types/primitives"
	eth "github.com/prysmaticlabs/prysm/v3/proto/prysm/v1alpha1"
	"github.com/wonderivan/logger"
)

type ExtendedBeaconBlockHeader struct {
	Header             *beaconrpc.BeaconBlockHeader
	BeaconBlockRoot    []byte
	ExecutionBlockHash []byte
}

func (h *ExtendedBeaconBlockHeader) Encode() ([]byte, error) {
	headerBytes, err := h.Header.Encode()
	if err != nil {
		return nil, err
	}
	b1, err := rlp.EncodeToBytes(headerBytes)
	if err != nil {
		return nil, err
	}
	b2, err := rlp.EncodeToBytes(h.BeaconBlockRoot)
	if err != nil {
		return nil, err
	}
	b3, err := rlp.EncodeToBytes(h.ExecutionBlockHash)
	if err != nil {
		return nil, err
	}
	var rlpBytes []byte
	rlpBytes = append(rlpBytes, b1...)
	rlpBytes = append(rlpBytes, b2...)
	rlpBytes = append(rlpBytes, b3...)
	return rlpBytes, nil
}

type InitInput struct {
	FinalizedExecutionHeader *types.Header
	FinalizedBeaconHeader    *ExtendedBeaconBlockHeader
	CurrentSyncCommittee     *eth.SyncCommittee
	NextSyncCommittee        *eth.SyncCommittee
}

func (init *InitInput) Encode() ([]byte, error) {
	exeHeader, err := rlp.EncodeToBytes(init.FinalizedExecutionHeader)
	if err != nil {
		return nil, err
	}
	b1, err := rlp.EncodeToBytes(exeHeader)
	if err != nil {
		return nil, err
	}
	finHeader, err := init.FinalizedBeaconHeader.Encode()
	if err != nil {
		return nil, err
	}
	b2, err := rlp.EncodeToBytes(finHeader)
	if err != nil {
		return nil, err
	}
	cur, err := rlp.EncodeToBytes(init.CurrentSyncCommittee)
	if err != nil {
		return nil, err
	}
	b3, err := rlp.EncodeToBytes(cur)
	if err != nil {
		return nil, err
	}
	next, err := rlp.EncodeToBytes(init.NextSyncCommittee)
	if err != nil {
		return nil, err
	}
	b4, err := rlp.EncodeToBytes(next)
	if err != nil {
		return nil, err
	}
	var rlpBytes []byte
	rlpBytes = append(rlpBytes, b1...)
	rlpBytes = append(rlpBytes, b2...)
	rlpBytes = append(rlpBytes, b3...)
	rlpBytes = append(rlpBytes, b4...)
	return rlpBytes, nil
}

func (relayer *Eth2TopRelayerV2) Eth2InitInputData() {
	lastSlot, err := relayer.beaconrpcclient.GetLastFinalizedSlotNumber()
	if err != nil {
		logger.Error("GetLastFinalizedSlotNumber error:", err)
		return
	}
	lastPeriod := beaconrpc.GetPeriodForSlot(lastSlot)
	lastUpdate, err := relayer.beaconrpcclient.GetLightClientUpdate(lastPeriod)
	if err != nil {
		logger.Error("GetLightClientUpdate error:", err)
		return
	}
	prevUpdate, err := relayer.beaconrpcclient.GetLightClientUpdate(lastPeriod - 1)
	if err != nil {
		logger.Error("GetLightClientUpdate error:", err)
		return
	}

	var beaconHeader eth.BeaconBlockHeader
	beaconHeader.Slot = primitives.Slot(lastUpdate.FinalizedUpdate.HeaderUpdate.BeaconHeader.Slot)
	beaconHeader.ProposerIndex = primitives.ValidatorIndex(lastUpdate.FinalizedUpdate.HeaderUpdate.BeaconHeader.ProposerIndex)
	beaconHeader.BodyRoot = lastUpdate.FinalizedUpdate.HeaderUpdate.BeaconHeader.BodyRoot
	beaconHeader.ParentRoot = lastUpdate.FinalizedUpdate.HeaderUpdate.BeaconHeader.ParentRoot
	beaconHeader.StateRoot = lastUpdate.FinalizedUpdate.HeaderUpdate.BeaconHeader.StateRoot
	root, err := beaconHeader.HashTreeRoot()
	if err != nil {
		logger.Error("HashTreeRoot error:", err)
		return
	}
	finalizedHeader := new(ExtendedBeaconBlockHeader)
	finalizedHeader.BeaconBlockRoot = root[:]
	finalizedHeader.Header = lastUpdate.FinalizedUpdate.HeaderUpdate.BeaconHeader
	finalizedHeader.ExecutionBlockHash = lastUpdate.FinalizedUpdate.HeaderUpdate.ExecutionBlockHash

	finalitySlot := lastUpdate.FinalizedUpdate.HeaderUpdate.BeaconHeader.Slot
	finalizeBody, err := relayer.beaconrpcclient.GetBeaconBlockBodyForBlockId(strconv.FormatUint(finalitySlot, 10))
	if err != nil {
		logger.Error("GetBeaconBlockBodyForBlockId error:", err)
		return
	}
	number := finalizeBody.GetExecutionPayload().BlockNumber

	header, err := relayer.ethrpcclient.HeaderByNumber(context.Background(), big.NewInt(0).SetUint64(number))
	if err != nil {
		logger.Error("HeaderByNumber error:", err)
		return
	}

	initParam := new(InitInput)
	initParam.FinalizedExecutionHeader = header
	initParam.FinalizedBeaconHeader = finalizedHeader
	initParam.NextSyncCommittee = lastUpdate.NextSyncCommitteeUpdate.NextSyncCommittee
	initParam.CurrentSyncCommittee = prevUpdate.NextSyncCommitteeUpdate.NextSyncCommittee

	bytes, err := initParam.Encode()
	if err != nil {
		logger.Error("initParam.Encode error:", err)
		return
	}
	fmt.Println(common.Bytes2Hex(bytes))
}
