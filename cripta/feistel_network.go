package cripta

import (
	"fmt"
)

type FeistelNetwork struct {
	keySchedule   IKeySchedule
	roundFunction IRoundFunction

	blockSize   int
	roundsCount int

	currentKey []uint8
	roundKeys  [][]uint8
}

func NewFeistelNetwork(
	keyScheduleImpl IKeySchedule,
	roundFunctionImpl IRoundFunction,
	blockSize int,
	roundsCount int,
) (*FeistelNetwork, error) {

	if keyScheduleImpl == nil {
		return nil, fmt.Errorf("key schedule implementation cannot be nil")
	}
	if roundFunctionImpl == nil {
		return nil, fmt.Errorf("round function implementation cannot be nil")
	}
	if blockSize%2 != 0 {
		return nil, fmt.Errorf("block size must be even for Feistel network")
	}

	fBlockSize := blockSize
	if fBlockSize == 0 {
		fBlockSize = 8
	}

	fRoundsCount := roundsCount
	if fRoundsCount == 0 {
		fRoundsCount = 16
	}

	return &FeistelNetwork{
		keySchedule:   keyScheduleImpl,
		roundFunction: roundFunctionImpl,
		blockSize:     fBlockSize,
		roundsCount:   fRoundsCount,
	}, nil
}

func (fn *FeistelNetwork) GetBlockSize() (int, error) {
	return fn.blockSize, nil
}

func (fn *FeistelNetwork) GetRoundsCount() (int, error) {
	return fn.roundsCount, nil
}

func (fn *FeistelNetwork) splitBlock(block []uint8) ([]uint8, []uint8, error) {
	if len(block) == 0 {
		return nil, nil, fmt.Errorf("block cannot be empty")
	}
	if len(block)%2 != 0 {
		return nil, nil, fmt.Errorf("block size must be even for splitting")
	}
	
	halfSize := len(block) / 2
	left := make([]uint8, halfSize)
	copy(left, block[:halfSize])
	right := make([]uint8, halfSize)
	copy(right, block[halfSize:])
	return left, right, nil
}

func (fn *FeistelNetwork) combineBlocks(left []uint8, right []uint8) ([]uint8, error) {
	if left == nil || right == nil {
		return nil, fmt.Errorf("left and right blocks cannot be nil")
	}
	
	combined := make([]uint8, len(left)+len(right))
	copy(combined, left)
	copy(combined[len(left):], right)
	return combined, nil
}

func (fn *FeistelNetwork) xorBlocks(left []uint8, right []uint8) ([]uint8, error) {
	if left == nil || right == nil {
		return nil, fmt.Errorf("left and right blocks cannot be nil")
	}
	
	minSize := len(left)
	if len(right) < minSize {
		minSize = len(right)
	}
	
	if minSize == 0 {
		return nil, fmt.Errorf("blocks cannot be empty")
	}
	
	result := make([]uint8, minSize)
	for i := 0; i < minSize; i++ {
		result[i] = left[i] ^ right[i]
	}
	return result, nil
}

func (fn *FeistelNetwork) SetKey(key []uint8) error {
	if key == nil {
		return fmt.Errorf("key cannot be nil")
	}
	if len(key) == 0 {
		return fmt.Errorf("key cannot be empty")
	}

	fn.currentKey = make([]uint8, len(key))
	copy(fn.currentKey, key)

	roundKeys, err := fn.keySchedule.GenerateRoundKeys(key)
	if err != nil {
		return fmt.Errorf("failed to generate round keys: %w", err)
	}

	fn.roundKeys = roundKeys

	if len(fn.roundKeys) < fn.roundsCount {
		return fmt.Errorf("key schedule generated insufficient round keys: got %d, need %d", 
			len(fn.roundKeys), fn.roundsCount)
	}

	return nil
}

func (fn *FeistelNetwork) EncryptBlock(plainBlock []uint8) ([]uint8, error) {
	if plainBlock == nil {
		return nil, fmt.Errorf("plain block cannot be nil")
	}
	if len(plainBlock) != fn.blockSize {
		return nil, fmt.Errorf("plain block size must match configured block size: got %d, need %d", 
			len(plainBlock), fn.blockSize)
	}

	if len(fn.roundKeys) == 0 {
		return nil, fmt.Errorf("key not set. Call SetKey() before encryption")
	}

	left, right, err := fn.splitBlock(plainBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to split block: %w", err)
	}

	for round := 0; round < fn.roundsCount; round++ {
		newLeft := make([]uint8, len(right))
		copy(newLeft, right)

		functionOutput, err := fn.roundFunction.Apply(right, fn.roundKeys[round])
		if err != nil {
			return nil, fmt.Errorf("round function error in round %d: %w", round, err)
		}

		newRight, err := fn.xorBlocks(left, functionOutput)
		if err != nil {
			return nil, fmt.Errorf("xor operation failed in round %d: %w", round, err)
		}

		left = newLeft
		right = newRight
	}

	result, err := fn.combineBlocks(left, right)
	if err != nil {
		return nil, fmt.Errorf("failed to combine blocks: %w", err)
	}

	return result, nil
}

func (fn *FeistelNetwork) DecryptBlock(cipherBlock []uint8) ([]uint8, error) {
	if cipherBlock == nil {
		return nil, fmt.Errorf("cipher block cannot be nil")
	}
	if len(cipherBlock) != fn.blockSize {
		return nil, fmt.Errorf("cipher block size must match configured block size: got %d, need %d", 
			len(cipherBlock), fn.blockSize)
	}

	if len(fn.roundKeys) == 0 {
		return nil, fmt.Errorf("key not set. Call SetKey() before decryption")
	}

	left, right, err := fn.splitBlock(cipherBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to split block: %w", err)
	}

	for round := fn.roundsCount - 1; round >= 0; round-- {
		newRight := make([]uint8, len(left))
		copy(newRight, left)

		functionOutput, err := fn.roundFunction.Apply(left, fn.roundKeys[round])
		if err != nil {
			return nil, fmt.Errorf("round function error in round %d: %w", round, err)
		}

		newLeft, err := fn.xorBlocks(right, functionOutput)
		if err != nil {
			return nil, fmt.Errorf("xor operation failed in round %d: %w", round, err)
		}

		left = newLeft
		right = newRight
	}

	result, err := fn.combineBlocks(left, right)
	if err != nil {
		return nil, fmt.Errorf("failed to combine blocks: %w", err)
	}

	return result, nil
}