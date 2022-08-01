package congress

import (
	"context"
	"math/big"
	"testing"
	"time"
	"toprelayer/sdk/ethsdk"

	"github.com/ethereum/go-ethereum/common"
)

const hecoUrl = "https://http-mainnet.hecochain.com"

func TestCheckValidatorsNum(t *testing.T) {
	var height uint64 = 17276000

	ethsdk, err := ethsdk.NewEthSdk(hecoUrl)
	if err != nil {
		t.Fatal("NewEthSdk: ", err)
	}
	header, err := ethsdk.HeaderByNumber(context.Background(), big.NewInt(0).SetUint64(height))
	if err != nil {
		t.Fatal("HeaderByNumber: ", err)
	}
	validators := make([]common.Address, (len(header.Extra)-extraVanity-extraSeal)/common.AddressLength)
	for i := 0; i < len(validators); i++ {
		copy(validators[i][:], header.Extra[extraVanity+i*common.AddressLength:])
	}
	for _, v := range validators {
		t.Log("validator:", v)
	}
	t.Log("validator num:", len(validators))
}

func TestInit(t *testing.T) {
	var height uint64 = 17276000

	con := New()
	ethsdk, err := ethsdk.NewEthSdk(hecoUrl)
	if err != nil {
		t.Fatal("NewEthSdk: ", err)
	}
	header, err := ethsdk.HeaderByNumber(context.Background(), big.NewInt(0).SetUint64(height))
	if err != nil {
		t.Fatal("HeaderByNumber: ", err)
	}
	_, err = con.Init(header)
	if err != nil {
		t.Fatal(err)
	}

	for i := height + 1; i < height+200; i += 1 {
		header, err := ethsdk.HeaderByNumber(context.Background(), big.NewInt(0).SetUint64(i))
		if err != nil {
			t.Fatal("HeaderByNumber: ", err)
		}
		// fmt.Println("OUT Stored checkpoint snapshot to disk", "number", header.Number, "hash", header.Hash())
		snap, err := con.VerifyHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		t.Log(snap)
		err = con.Apply(snap, header)
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond * 100)
	}
}
