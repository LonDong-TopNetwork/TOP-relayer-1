package congress

import (
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	lru "github.com/hashicorp/golang-lru"
	"golang.org/x/crypto/sha3"
)

const (
	checkpointInterval = 1024 // Number of blocks after which to save the vote snapshot to the database
	inmemorySnapshots  = 128  // Number of recent vote snapshots to keep in memory
	inmemorySignatures = 4096 // Number of recent block signatures to keep in memory

	wiggleTime    = 500 * time.Millisecond // Random delay (per validator) to allow concurrent validators
	maxValidators = 21                     // Max validators allowed to seal.

	inmemoryBlacklist = 21 // Number of recent blacklist snapshots to keep in memory
)

// Congress proof-of-stake-authority protocol constants.
var (
	epochLength = uint64(30000) // Default number of blocks after which to checkpoint and reset the pending votes

	extraVanity = 32                     // Fixed number of extra-data prefix bytes reserved for validator vanity
	extraSeal   = crypto.SignatureLength // Fixed number of extra-data suffix bytes reserved for validator seal

	uncleHash = types.CalcUncleHash(nil) // Always Keccak256(RLP([])) as uncles are meaningless outside of PoW.

	diffInTurn = big.NewInt(2) // Block difficulty for in-turn signatures
	diffNoTurn = big.NewInt(1) // Block difficulty for out-of-turn signatures
)

// Various error messages to mark blocks invalid. These should be private to
// prevent engine specific errors from being referenced in the remainder of the
// codebase, inherently breaking if the engine is swapped out. Please put common
// error types into the consensus package.
var (
	// errUnknownBlock is returned when the list of validators is requested for a block
	// that is not part of the local blockchain.
	errUnknownBlock = errors.New("unknown block")

	// errMissingVanity is returned if a block's extra-data section is shorter than
	// 32 bytes, which is required to store the validator vanity.
	errMissingVanity = errors.New("extra-data 32 byte vanity prefix missing")

	// errMissingSignature is returned if a block's extra-data section doesn't seem
	// to contain a 65 byte secp256k1 signature.
	errMissingSignature = errors.New("extra-data 65 byte signature suffix missing")

	// errExtraValidators is returned if non-checkpoint block contain validator data in
	// their extra-data fields.
	errExtraValidators = errors.New("non-checkpoint block contains extra validator list")

	// errInvalidExtraValidators is returned if validator data in extra-data field is invalid.
	errInvalidExtraValidators = errors.New("Invalid extra validators in extra data field")

	// errInvalidCheckpointValidators is returned if a checkpoint block contains an
	// invalid list of validators (i.e. non divisible by 20 bytes).
	errInvalidCheckpointValidators = errors.New("invalid validator list on checkpoint block")

	// errMismatchingCheckpointValidators is returned if a checkpoint block contains a
	// list of validators different than the one the local node calculated.
	errMismatchingCheckpointValidators = errors.New("mismatching validator list on checkpoint block")

	// errInvalidMixDigest is returned if a block's mix digest is non-zero.
	errInvalidMixDigest = errors.New("non-zero mix digest")

	// errInvalidUncleHash is returned if a block contains an non-empty uncle list.
	errInvalidUncleHash = errors.New("non empty uncle hash")

	// errInvalidDifficulty is returned if the difficulty of a block neither 1 or 2.
	errInvalidDifficulty = errors.New("invalid difficulty")

	// errWrongDifficulty is returned if the difficulty of a block doesn't match the
	// turn of the validator.
	errWrongDifficulty = errors.New("wrong difficulty")

	// errInvalidTimestamp is returned if the timestamp of a block is lower than
	// the previous block's timestamp + the minimum block period.
	errInvalidTimestamp = errors.New("invalid timestamp")

	// ErrInvalidTimestamp is returned if the timestamp of a block is lower than
	// the previous block's timestamp + the minimum block period.
	ErrInvalidTimestamp = errors.New("invalid timestamp")

	// errInvalidVotingChain is returned if an authorization list is attempted to
	// be modified via out-of-range or non-contiguous headers.
	errInvalidVotingChain = errors.New("invalid voting chain")

	// errUnauthorizedValidator is returned if a header is signed by a non-authorized entity.
	errUnauthorizedValidator = errors.New("unauthorized validator")

	// errRecentlySigned is returned if a header is signed by an authorized entity
	// that already signed a header recently, thus is temporarily not allowed to.
	errRecentlySigned = errors.New("recently signed")

	// errInvalidValidatorLen is returned if validators length is zero or bigger than maxValidators.
	errInvalidValidatorsLength = errors.New("Invalid validators length")

	// errInvalidCoinbase is returned if the coinbase isn't the validator of the block.
	errInvalidCoinbase = errors.New("Invalid coin base")

	errInvalidSysGovCount = errors.New("invalid system governance tx count")
)

// TODO: add db
type Congress struct {
	recents    *lru.ARCCache // Snapshots for recent block to speed up reorgs
	signatures *lru.ARCCache // Signatures of recent blocks to speed up mining

	validator common.Address // Ethereum address of the signing key

	// The fields below are for testing only
	fakeDiff bool // Skip difficulty verifications
}

// New creates a Congress proof-of-stake-authority consensus engine with the initial
// validators set to the ones provided by the user.
func New() *Congress {
	// Allocate the snapshot caches and create the engine
	recents, _ := lru.NewARC(inmemorySnapshots)
	signatures, _ := lru.NewARC(inmemorySignatures)

	return &Congress{
		recents:    recents,
		signatures: signatures,
	}
}

func (c *Congress) Init(header *types.Header) (*Snapshot, error) {
	var snap *Snapshot

	number := header.Number.Uint64()
	if number%Epoch != 0 {
		return nil, fmt.Errorf("init with header not epoch")
	}
	hash := header.Hash()

	validators := make([]common.Address, (len(header.Extra)-extraVanity-extraSeal)/common.AddressLength)
	for i := 0; i < len(validators); i++ {
		copy(validators[i][:], header.Extra[extraVanity+i*common.AddressLength:])
	}
	snap = newSnapshot(c.signatures, number, hash, validators)
	c.recents.Add(snap.Hash, snap)
	// fmt.Println("Stored checkpoint snapshot to disk", "number", number, "hash", hash)

	// signer, err := ecrecover(header, c.signatures)
	// if err != nil {
	// 	return nil, err
	// }
	// fmt.Println("signer:", signer)
	return snap, nil
}

func (c *Congress) VerifyHeader(header *types.Header) (*Snapshot, error) {
	// All basic checks passed, verify the seal and return
	return c.verifySeal(header)
}

// verifySeal checks whether the signature contained in the header satisfies the
// consensus protocol requirements. The method accepts an optional list of parent
// headers that aren't yet part of the local blockchain to generate the snapshots
// from.
func (c *Congress) verifySeal(header *types.Header) (*Snapshot, error) {
	// Verifying the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return nil, errUnknownBlock
	}
	// Retrieve the snapshot needed to verify this header and cache it
	// snap, err := c.snapshot(number-1, header.ParentHash)
	// if err != nil {
	// 	return nil, err
	// }
	s, ok := c.recents.Get(header.ParentHash)
	if !ok {
		return nil, fmt.Errorf("parent not found")
	}
	// // Resolve the authorization key and check against validators
	// signer, err := ecrecover(header, c.signatures)
	// if err != nil {
	// 	return nil, err
	// }
	// if signer != header.Coinbase {
	// 	return nil, errInvalidCoinbase
	// }

	// if _, ok := snap.Validators[signer]; !ok {
	// 	return nil, errUnauthorizedValidator
	// }

	// for seen, recent := range snap.Recents {
	// 	if recent == signer {
	// 		// Validator is among recents, only fail if the current block doesn't shift it out
	// 		if limit := uint64(len(snap.Validators)/2 + 1); seen > number-limit {
	// 			return nil, errRecentlySigned
	// 		}
	// 	}
	// }

	// // Ensure that the difficulty corresponds to the turn-ness of the signer
	// if !c.fakeDiff {
	// 	inturn := snap.inturn(header.Number.Uint64(), signer)
	// 	if inturn && header.Difficulty.Cmp(diffInTurn) != 0 {
	// 		return nil, errWrongDifficulty
	// 	}
	// 	if !inturn && header.Difficulty.Cmp(diffNoTurn) != 0 {
	// 		return nil, errWrongDifficulty
	// 	}
	// }

	return s.(*Snapshot), nil
}

// // snapshot retrieves the authorization snapshot at a given point in time.
// func (c *Congress) snapshot(number uint64, hash common.Hash) (*Snapshot, error) {
// 	// Search for a snapshot in memory or on disk for checkpoints
// 	var (
// 		// headers []*types.Header
// 		snap *Snapshot
// 	)
// 	// If an in-memory snapshot was found, use that
// 	if s, ok := c.recents.Get(hash); ok {
// 		snap = s.(*Snapshot)
// 	} else {
// 		return nil, fmt.Errorf("parent not found")
// 	}
// 	// headers = append(headers, header)
// 	// snap, err := snap.apply(headers)
// 	// if err != nil {
// 	// 	return nil, err
// 	// }
// 	// c.recents.Add(snap.Hash, snap)
// 	// // log.Info("Stored checkpoint snapshot to disk", "number", header.Number, "hash", hash)
// 	// fmt.Println("Stored checkpoint snapshot to disk", "number", header.Number, "hash", header.Hash())

// 	return snap, nil
// }

func (c *Congress) Apply(snap *Snapshot, header *types.Header) error {
	var headers []*types.Header
	headers = append(headers, header)
	snap, err := snap.apply(headers)
	if err != nil {
		return err
	}
	c.recents.Add(snap.Hash, snap)
	return nil
}

// ecrecover extracts the Ethereum account address from a signed header.
func ecrecover(header *types.Header, sigcache *lru.ARCCache) (common.Address, error) {
	// If the signature's already cached, return that
	hash := header.Hash()
	if address, known := sigcache.Get(hash); known {
		return address.(common.Address), nil
	}
	// Retrieve the signature from the header extra-data
	if len(header.Extra) < extraSeal {
		return common.Address{}, errMissingSignature
	}
	signature := header.Extra[len(header.Extra)-extraSeal:]

	// Recover the public key and the Ethereum address
	pubkey, err := crypto.Ecrecover(SealHash(header).Bytes(), signature)
	if err != nil {
		return common.Address{}, err
	}
	var validator common.Address
	copy(validator[:], crypto.Keccak256(pubkey[1:])[12:])

	sigcache.Add(hash, validator)
	return validator, nil
}

// SealHash returns the hash of a block prior to it being sealed.
func SealHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()
	encodeSigHeader(hasher, header)
	hasher.Sum(hash[:0])
	return hash
}

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
