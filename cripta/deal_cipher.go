package cripta

import (
	"fmt"
)

type DEALCipher struct {
	feistel    *FeistelNetwork
	currentKey []uint8
	keyLength  int
}

func NewDEALCipher(keyLength int) (*DEALCipher, error) {
	if keyLength != 16 && keyLength != 24 && keyLength != 32 {
		return nil, fmt.Errorf("DEAL key length must be 128, 192, or 256 bits (16, 24, or 32 bytes)")
	}

	numRounds := 6
	if keyLength == 32 {
		numRounds = 8
	}

	keySchedule, err := NewDEALKeySchedule(keyLength)
	if err != nil {
		return nil, fmt.Errorf("failed to create round keys: %w", err)
	}
	roundFunction, err := NewDEALRoundFunction()
	if err != nil {
		return nil, fmt.Errorf("failed to create round function: %w", err)
	}

	feistel, err := NewFeistelNetwork(
		keySchedule,
		roundFunction,
		16,
		numRounds,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Feistel network: %w", err)
	}

	return &DEALCipher{
		feistel:   feistel,
		keyLength: keyLength,
	}, nil
}

func (deal *DEALCipher) SetKey(key []uint8) error {
	if len(key) != deal.keyLength {
		return fmt.Errorf("key size must match configured DEAL key length: got %d, need %d", len(key), deal.keyLength)
	}

	deal.currentKey = make([]uint8, len(key))
	copy(deal.currentKey, key)

	err := deal.feistel.SetKey(key)
	if err != nil {
		return fmt.Errorf("failed to set key in feistel network: %w", err)
	}

	return nil
}

func (deal *DEALCipher) EncryptBlock(plainBlock []uint8) ([]uint8, error) {
    if len(plainBlock) != 16 {
        return nil, fmt.Errorf("DEAL block must be 16 bytes (128 bits), got %d", len(plainBlock))
    }

    // Если блок больше 16 байт, обрабатываем по частям
    if len(plainBlock) > 16 {
        result := make([]uint8, 0, len(plainBlock))
        for i := 0; i < len(plainBlock); i += 16 {
            end := i + 16
            if end > len(plainBlock) {
                end = len(plainBlock)
            }
            block := plainBlock[i:end]
            if len(block) < 16 {
                // Дополняем последний блок если нужно
                block = append(block, make([]uint8, 16-len(block))...)
            }
            encrypted, err := deal.feistel.EncryptBlock(block)
            if err != nil {
                return nil, err
            }
            result = append(result, encrypted...)
        }
        return result, nil
    }

    cipherBlock, err := deal.feistel.EncryptBlock(plainBlock)
    if err != nil {
        return nil, fmt.Errorf("feistel encryption failed: %w", err)
    }

    return cipherBlock, nil
}

func (deal *DEALCipher) DecryptBlock(cipherBlock []uint8) ([]uint8, error) {
	if len(cipherBlock) != 16 {
		return nil, fmt.Errorf("DEAL block must be 16 bytes (128 bits), got %d", len(cipherBlock))
	}

	plainBlock, err := deal.feistel.DecryptBlock(cipherBlock)
	if err != nil {
		return nil, fmt.Errorf("feistel decryption failed: %w", err)
	}

	return plainBlock, nil
}

func (deal *DEALCipher) GetKeyLength() (int, error) {
	return deal.keyLength, nil
}