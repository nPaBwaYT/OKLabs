package cripta

import (
	"fmt"
	"sync"
)

type DEALRoundFunction struct {
	desPool sync.Pool
}

func NewDEALRoundFunction() (*DEALRoundFunction, error) {
	des, err := NewDESCipher()
	if err != nil {
		return nil, fmt.Errorf("failed to create DES cipher: %w", err)
	}

	drf := &DEALRoundFunction{
		desPool: sync.Pool{
			New: func() interface{} {
				des, _ := NewDESCipher()
				return des
			},
		},
	}

	drf.desPool.Put(des)

	return drf, nil
}

func (drf *DEALRoundFunction) Apply(inputBlock []uint8, roundKey []uint8) ([]uint8, error) {
	if inputBlock == nil {
		return nil, fmt.Errorf("input block cannot be nil")
	}
	if len(inputBlock) != 8 {
		return nil, fmt.Errorf("DEAL round function input must be 8 bytes, got %d", len(inputBlock))
	}

	if roundKey == nil {
		return nil, fmt.Errorf("round key cannot be nil")
	}
	if len(roundKey) != 8 {
		return nil, fmt.Errorf("DEAL round key must be 8 bytes, got %d", len(roundKey))
	}

	des := drf.desPool.Get().(*DESCipher)
	defer drf.desPool.Put(des)

	err := des.SetKey(roundKey)
	if err != nil {
		return nil, fmt.Errorf("failed to set round key: %w", err)
	}

	output, err := des.EncryptBlock(inputBlock)
	if err != nil {
		return nil, fmt.Errorf("DES encryption failed: %w", err)
	}

	if len(output) != 8 {
		return nil, fmt.Errorf("DES output size is incorrect: got %d bytes, expected 8", len(output))
	}

	return output, nil
}