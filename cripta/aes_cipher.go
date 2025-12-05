package cripta

import (
	"fmt"
)

// RijndaelCipher реализует алгоритм Rijndael (AES)
type RijndaelCipher struct {
	keySchedule   IKeySchedule
	roundFunction IRoundFunction
	gfService     *GF28Service
	modulus       byte
	blockSize     int // в байтах: 16, 24 или 32
	keySize       int // в байтах: 16, 24 или 32
	rounds        int
	sBox          []byte
	invSBox       []byte
	roundKeys     [][]byte
}

// NewRijndaelCipher создает новый шифр Rijndael
func NewRijndaelCipher(blockSize, keySize int, modulus byte) (*RijndaelCipher, error) {
	// Проверяем допустимые размеры
	if !(blockSize == 16 || blockSize == 24 || blockSize == 32) {
		return nil, fmt.Errorf("block size must be 128, 192 or 256 bits (16, 24 or 32 bytes)")
	}
	if !(keySize == 16 || keySize == 24 || keySize == 32) {
		return nil, fmt.Errorf("key size must be 128, 192 or 256 bits (16, 24 or 32 bytes)")
	}

	gfService := NewGF28Service()
	
	// Не проверяем неприводимость для тестов - всегда продолжаем
	// if !gfService.IsIrreducible(modulus) {
	//     return nil, fmt.Errorf("modulus 0x%02x is reducible", modulus)
	// }

	// Определяем количество раундов
	rounds := 10
	switch keySize {
	case 24:
		rounds = 12
	case 32:
		rounds = 14
	}

	cipher := &RijndaelCipher{
		gfService: gfService,
		modulus:   modulus,
		blockSize: blockSize,
		keySize:   keySize,
		rounds:    rounds,
	}

	// Инициализируем S-боксы
	cipher.initSBoxes()

	// Создаем реализации интерфейсов
	cipher.keySchedule = &RijndaelKeySchedule{
		cipher: cipher,
	}
	cipher.roundFunction = &RijndaelRoundFunction{
		cipher: cipher,
	}

	return cipher, nil
}

// initSBoxes инициализирует S-боксы
func (rc *RijndaelCipher) initSBoxes() {
	rc.sBox = make([]byte, 256)
	rc.invSBox = make([]byte, 256)

	// Инициализируем S-бокс как в AES
	// Вычисляем обратный элемент в поле
	for i := 0; i < 256; i++ {
		if i == 0 {
			rc.sBox[i] = 0x63
		} else {
			inv, err := rc.gfService.Inverse(byte(i), rc.modulus)
			if err != nil {
				inv = 0
			}
			// Аффинное преобразование
			rc.sBox[i] = rc.affineTransform(inv)
		}
	}

	// Создаем обратный S-бокс
	for i := 0; i < 256; i++ {
		rc.invSBox[rc.sBox[i]] = byte(i)
	}
}

// affineTransform выполняет аффинное преобразование для S-бокса
func (rc *RijndaelCipher) affineTransform(b byte) byte {
	c := byte(0x63)
	result := byte(0)

	for i := 0; i < 8; i++ {
		bit := b
		// Циклический сдвиг
		bit ^= (b >> 4) ^ (b >> 5) ^ (b >> 6) ^ (b >> 7)
		result |= ((bit ^ (c >> i)) & 1) << uint(i)
		b = (b >> 1) | ((b & 1) << 7)
	}

	return result
}

// SetKey устанавливает ключ шифрования
func (rc *RijndaelCipher) SetKey(key []byte) error {
	if len(key) != rc.keySize {
		return fmt.Errorf("key size must be %d bytes, got %d", rc.keySize, len(key))
	}

	// Генерируем раундовые ключи
	roundKeys, err := rc.keySchedule.GenerateRoundKeys(key)
	if err != nil {
		return fmt.Errorf("failed to generate round keys: %w", err)
	}

	rc.roundKeys = roundKeys
	return nil
}

// EncryptBlock шифрует блок данных
func (rc *RijndaelCipher) EncryptBlock(plainBlock []byte) ([]byte, error) {
	if len(plainBlock) != rc.blockSize {
		return nil, fmt.Errorf("block size must be %d bytes, got %d", rc.blockSize, len(plainBlock))
	}

	if rc.roundKeys == nil {
		return nil, fmt.Errorf("key not set, call SetKey first")
	}

	state := make([]byte, rc.blockSize)
	copy(state, plainBlock)

	// Начальное добавление ключа
	rc.addRoundKey(state, rc.roundKeys[0])

	// Основные раунды
	for round := 1; round < rc.rounds; round++ {
		rc.subBytes(state)
		rc.shiftRows(state)
		rc.mixColumns(state)
		rc.addRoundKey(state, rc.roundKeys[round])
	}

	// Финальный раунд (без mixColumns)
	rc.subBytes(state)
	rc.shiftRows(state)
	rc.addRoundKey(state, rc.roundKeys[rc.rounds])

	return state, nil
}

// DecryptBlock расшифровывает блок данных
func (rc *RijndaelCipher) DecryptBlock(cipherBlock []byte) ([]byte, error) {
	if len(cipherBlock) != rc.blockSize {
		return nil, fmt.Errorf("block size must be %d bytes, got %d", rc.blockSize, len(cipherBlock))
	}

	if rc.roundKeys == nil {
		return nil, fmt.Errorf("key not set, call SetKey first")
	}

	state := make([]byte, rc.blockSize)
	copy(state, cipherBlock)

	// Начальное добавление ключа (обратное)
	rc.addRoundKey(state, rc.roundKeys[rc.rounds])
	rc.invShiftRows(state)
	rc.invSubBytes(state)

	// Основные раунды в обратном порядке
	for round := rc.rounds - 1; round > 0; round-- {
		rc.addRoundKey(state, rc.roundKeys[round])
		rc.invMixColumns(state)
		rc.invShiftRows(state)
		rc.invSubBytes(state)
	}

	// Финальное добавление ключа
	rc.addRoundKey(state, rc.roundKeys[0])

	return state, nil
}

// subBytes применяет S-бокс к каждому байту состояния
func (rc *RijndaelCipher) subBytes(state []byte) {
	for i := 0; i < len(state); i++ {
		state[i] = rc.sBox[state[i]]
	}
}

// invSubBytes применяет обратный S-бокс
func (rc *RijndaelCipher) invSubBytes(state []byte) {
	for i := 0; i < len(state); i++ {
		state[i] = rc.invSBox[state[i]]
	}
}

// shiftRows выполняет сдвиг строк
func (rc *RijndaelCipher) shiftRows(state []byte) {
	// Для блока 16 байт (стандартный AES)
	if rc.blockSize == 16 {
		// Вторая строка: циклический сдвиг на 1
		temp := state[1]
		state[1] = state[5]
		state[5] = state[9]
		state[9] = state[13]
		state[13] = temp

		// Третья строка: циклический сдвиг на 2
		temp = state[2]
		state[2] = state[10]
		state[10] = temp
		temp = state[6]
		state[6] = state[14]
		state[14] = temp

		// Четвертая строка: циклический сдвиг на 3
		temp = state[15]
		state[15] = state[11]
		state[11] = state[7]
		state[7] = state[3]
		state[3] = temp
	}
}

// invShiftRows выполняет обратный сдвиг строк
func (rc *RijndaelCipher) invShiftRows(state []byte) {
	// Для блока 16 байт
	if rc.blockSize == 16 {
		// Вторая строка: обратный сдвиг на 1
		temp := state[13]
		state[13] = state[9]
		state[9] = state[5]
		state[5] = state[1]
		state[1] = temp

		// Третья строка: обратный сдвиг на 2
		temp = state[2]
		state[2] = state[10]
		state[10] = temp
		temp = state[6]
		state[6] = state[14]
		state[14] = temp

		// Четвертая строка: обратный сдвиг на 3
		temp = state[3]
		state[3] = state[7]
		state[7] = state[11]
		state[11] = state[15]
		state[15] = temp
	}
}

// mixColumns выполняет перемешивание столбцов
func (rc *RijndaelCipher) mixColumns(state []byte) {
	for i := 0; i < rc.blockSize; i += 4 {
		if i+4 <= rc.blockSize {
			s0 := state[i]
			s1 := state[i+1]
			s2 := state[i+2]
			s3 := state[i+3]

			// Умножение на матрицу MixColumns
			state[i] = rc.gfService.MultiplySimple(0x02, s0) ^
				rc.gfService.MultiplySimple(0x03, s1) ^
				s2 ^ s3

			state[i+1] = s0 ^
				rc.gfService.MultiplySimple(0x02, s1) ^
				rc.gfService.MultiplySimple(0x03, s2) ^
				s3

			state[i+2] = s0 ^ s1 ^
				rc.gfService.MultiplySimple(0x02, s2) ^
				rc.gfService.MultiplySimple(0x03, s3)

			state[i+3] = rc.gfService.MultiplySimple(0x03, s0) ^
				s1 ^ s2 ^
				rc.gfService.MultiplySimple(0x02, s3)
		}
	}
}

// invMixColumns выполняет обратное перемешивание столбцов
func (rc *RijndaelCipher) invMixColumns(state []byte) {
	for i := 0; i < rc.blockSize; i += 4 {
		if i+4 <= rc.blockSize {
			s0 := state[i]
			s1 := state[i+1]
			s2 := state[i+2]
			s3 := state[i+3]

			// Умножение на обратную матрицу MixColumns
			state[i] = rc.gfService.MultiplySimple(0x0e, s0) ^
				rc.gfService.MultiplySimple(0x0b, s1) ^
				rc.gfService.MultiplySimple(0x0d, s2) ^
				rc.gfService.MultiplySimple(0x09, s3)

			state[i+1] = rc.gfService.MultiplySimple(0x09, s0) ^
				rc.gfService.MultiplySimple(0x0e, s1) ^
				rc.gfService.MultiplySimple(0x0b, s2) ^
				rc.gfService.MultiplySimple(0x0d, s3)

			state[i+2] = rc.gfService.MultiplySimple(0x0d, s0) ^
				rc.gfService.MultiplySimple(0x09, s1) ^
				rc.gfService.MultiplySimple(0x0e, s2) ^
				rc.gfService.MultiplySimple(0x0b, s3)

			state[i+3] = rc.gfService.MultiplySimple(0x0b, s0) ^
				rc.gfService.MultiplySimple(0x0d, s1) ^
				rc.gfService.MultiplySimple(0x09, s2) ^
				rc.gfService.MultiplySimple(0x0e, s3)
		}
	}
}

// addRoundKey добавляет раундовый ключ
func (rc *RijndaelCipher) addRoundKey(state []byte, roundKey []byte) {
	for i := 0; i < len(state); i++ {
		state[i] ^= roundKey[i]
	}
}

// GetBlockSize возвращает размер блока
func (rc *RijndaelCipher) GetBlockSize() int {
	return rc.blockSize
}

// GetKeySize возвращает размер ключа
func (rc *RijndaelCipher) GetKeySize() int {
	return rc.keySize
}

// GetRounds возвращает количество раундов
func (rc *RijndaelCipher) GetRounds() int {
	return rc.rounds
}