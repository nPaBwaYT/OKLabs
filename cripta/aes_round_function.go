package cripta

import "fmt"

// RijndaelRoundFunction реализует раундовую функцию для Rijndael
type RijndaelRoundFunction struct {
	cipher *RijndaelCipher
}

// Apply применяет раундовую функцию
func (rrf *RijndaelRoundFunction) Apply(inputBlock []byte, roundKey []byte) ([]byte, error) {
	if len(inputBlock) != rrf.cipher.blockSize {
		return nil, fmt.Errorf("input block size must be %d bytes", rrf.cipher.blockSize)
	}

	if len(roundKey) != rrf.cipher.blockSize {
		return nil, fmt.Errorf("round key size must be %d bytes", rrf.cipher.blockSize)
	}

	// Копируем входной блок
	state := make([]byte, len(inputBlock))
	copy(state, inputBlock)

	// Применяем преобразования раунда
	rrf.cipher.subBytes(state)
	rrf.cipher.shiftRows(state)
	rrf.cipher.mixColumns(state)
	
	// Добавляем раундовый ключ
	for i := 0; i < len(state); i++ {
		state[i] ^= roundKey[i]
	}

	return state, nil
}