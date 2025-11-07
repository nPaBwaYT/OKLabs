package cripta

import "fmt"

type DESCipher struct {
	feistel    *FeistelNetwork
	currentKey []uint8
}

var IP = []int{
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
	64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17, 9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7,
}

var FP = []int{
	40, 8, 48, 16, 56, 24, 64, 32,
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41, 9, 49, 17, 57, 25,
}

func NewDESCipher() (*DESCipher, error) {
	keySchedule := &DESKeySchedule{}
	roundFunction := &DESRoundFunction{}

	feistel, err := NewFeistelNetwork(
		keySchedule,
		roundFunction,
		8,
		16,
	)
	if err != nil {
		return nil, err
	}

	return &DESCipher{
		feistel: feistel,
	}, nil
}

func (des *DESCipher) SetKey(key []uint8) error {
	if len(key) != 8 {
		return fmt.Errorf("DES key must be 8 bytes (64 bits)")
	}

	des.currentKey = make([]uint8, len(key))
	copy(des.currentKey, key)

	err := des.feistel.SetKey(key)
	if err != nil {
		return fmt.Errorf("failed to set key in feistel network: %w", err)
	}

	return nil
}

func (des *DESCipher) EncryptBlock(plainBlock []uint8) ([]uint8, error) {
	if len(plainBlock) != 8 {
		return nil, fmt.Errorf("DES block must be 8 bytes (64 bits)")
	}

	permuted, err := PermuteBits(plainBlock, IP, false, 1)
	if err != nil {
		return nil, fmt.Errorf("IP permutation failed: %w", err)
	}

	feistelOutput, err := des.feistel.EncryptBlock(permuted)
	if err != nil {
		return nil, fmt.Errorf("feistel encryption failed: %w", err)
	}

	cipherBlock, err := PermuteBits(feistelOutput, FP, false, 1)
	if err != nil {
		return nil, fmt.Errorf("FP permutation failed: %w", err)
	}

	return cipherBlock, nil
}

func (des *DESCipher) DecryptBlock(cipherBlock []uint8) ([]uint8, error) {
	if len(cipherBlock) != 8 {
		return nil, fmt.Errorf("DES block must be 8 bytes (64 bits)")
	}

	permuted, err := PermuteBits(cipherBlock, IP, false, 1)
	if err != nil {
		return nil, fmt.Errorf("IP permutation failed: %w", err)
	}

	feistelOutput, err := des.feistel.DecryptBlock(permuted)
	if err != nil {
		return nil, fmt.Errorf("feistel decryption failed: %w", err)
	}

	plainBlock, err := PermuteBits(feistelOutput, FP, false, 1)
	if err != nil {
		return nil, fmt.Errorf("FP permutation failed: %w", err)
	}

	return plainBlock, nil
}