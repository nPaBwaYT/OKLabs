package cripta

// RijndaelKeySchedule реализует расписание ключей для Rijndael/AES
type RijndaelKeySchedule struct {
	cipher *RijndaelCipher
}

// GenerateRoundKeys генерирует раундовые ключи
func (rks *RijndaelKeySchedule) GenerateRoundKeys(masterKey []byte) ([][]byte, error) {
	keySize := rks.cipher.keySize
	blockSize := rks.cipher.blockSize
	rounds := rks.cipher.rounds

	// Количество слов в ключе (4 байта на слово)
	nk := keySize / 4
	// Количество слов в блоке
	nb := blockSize / 4
	// Количество раундовых ключей
	nr := rounds

	// Инициализируем массив раундовых ключей
	roundKeys := make([][]byte, nr+1)
	for i := 0; i <= nr; i++ {
		roundKeys[i] = make([]byte, blockSize)
	}

	// Копируем мастер-ключ в первые nk слов
	for i := 0; i < nk; i++ {
		if i*4 < len(masterKey) && i*4 < blockSize {
			copy(roundKeys[0][i*4:], masterKey[i*4:min((i+1)*4, len(masterKey))])
		}
	}

	// Генерируем остальные раундовые ключи
	for i := 1; i <= nr; i++ {
		prevKey := roundKeys[i-1]
		currentKey := roundKeys[i]

		// Первое слово нового раундового ключа
		temp := make([]byte, 4)
		startIdx := (i-1)*nk*4 + (nk-1)*4
		if startIdx+4 <= len(prevKey) {
			copy(temp, prevKey[startIdx:startIdx+4])
		} else {
			copy(temp, prevKey[len(prevKey)-4:])
		}

		if i%nk == 0 {
			// Применяем RotWord, SubWord и Rcon
			// RotWord: циклический сдвиг влево
			tempByte := temp[0]
			temp[0] = temp[1]
			temp[1] = temp[2]
			temp[2] = temp[3]
			temp[3] = tempByte

			// SubWord: применяем S-бокс
			for j := 0; j < 4; j++ {
				temp[j] = rks.cipher.sBox[temp[j]]
			}

			// Rcon: добавляем константу раунда
			rcon := rks.rcon(i/nk)
			temp[0] ^= rcon
		} else if nk > 6 && i%nk == 4 {
			// Для ключей 256 бит: дополнительное преобразование
			for j := 0; j < 4; j++ {
				temp[j] = rks.cipher.sBox[temp[j]]
			}
		}

		// Генерируем первое слово нового ключа
		for j := 0; j < 4; j++ {
			if j < len(prevKey) && j < len(currentKey) {
				currentKey[j] = prevKey[j] ^ temp[j]
			}
		}

		// Генерируем остальные слова нового ключа
		for word := 1; word < nb; word++ {
			for j := 0; j < 4; j++ {
				idx := word*4 + j
				if idx < len(currentKey) && idx-4 >= 0 && idx-4 < len(prevKey) {
					currentKey[idx] = prevKey[idx] ^ currentKey[idx-4]
				}
			}
		}
	}

	return roundKeys, nil
}

// rcon возвращает константу раунда
func (rks *RijndaelKeySchedule) rcon(round int) byte {
	rcon := byte(1)
	for i := 1; i < round; i++ {
		rcon = rks.cipher.gfService.MultiplySimple(rcon, 0x02)
	}
	return rcon
}

// min возвращает минимальное из двух чисел
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}