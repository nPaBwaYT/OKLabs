package cripta

import (
	"fmt"
)

type DEALKeySchedule struct {
	keyLength int
	numRounds int
}

var FIXED_KEY = []uint8{
	0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
}

func NewDEALKeySchedule(keyLength int) (*DEALKeySchedule, error) {
	if keyLength != 16 && keyLength != 24 && keyLength != 32 {
		return nil, fmt.Errorf("DEAL key length must be 128, 192, or 256 bits (16, 24, or 32 bytes)")
	}

	numRounds := 6
	if keyLength == 32 {
		numRounds = 8
	}

	return &DEALKeySchedule{
		keyLength: keyLength,
		numRounds: numRounds,
	}, nil
}

func (dks *DEALKeySchedule) GenerateRoundKeys(masterKey []uint8) ([][]uint8, error) {
	if len(masterKey) != dks.keyLength {
		return nil, fmt.Errorf("master key size doesn't match configured key length: got %d, need %d", len(masterKey), dks.keyLength)
	}

	roundKeys := make([][]uint8, dks.numRounds)

	keyBlocks := make([][]uint8, 0)
	for i := 0; i < len(masterKey); i += 8 {
		end := i + 8
		if end > len(masterKey) {
			end = len(masterKey)
		}
		block := make([]uint8, 8)
		copy(block, masterKey[i:end])
		
		keyBlocks = append(keyBlocks, block)
	}

	for round := 0; round < dks.numRounds; round++ {
		des, err := NewDESCipher()
		if err != nil {
			return nil, fmt.Errorf("failed to create DES cipher: %w", err)
		}

		err = des.SetKey(FIXED_KEY)
		if err != nil {
			return nil, fmt.Errorf("failed to set fixed DES key: %w", err)
		}

		blockIdx := round % len(keyBlocks)
		roundKey := make([]uint8, 8)
		copy(roundKey, keyBlocks[blockIdx])

		for i := 0; i < len(roundKey); i++ {
			roundKey[i] ^= uint8(round + 1)
		}

		encryptedKey, err := des.EncryptBlock(roundKey)
		if err != nil {
			return nil, fmt.Errorf("DES encryption failed for round key %d: %w", round, err)
		}

		roundKeys[round] = encryptedKey
	}

	return roundKeys, nil
}