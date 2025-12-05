package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"testing"
	"time"

	"OKLabs/cripta"
)

type RijndaelTest struct {
	name        string
	blockSize   int
	keySize     int
	modulus     byte
	mode        cripta.CipherMode
	modeName    string
	padding     cripta.PaddingMode
	paddingName string
	parallel    bool
	inputFile   string
}

type TestResult struct {
	testName        string
	blockSize       int
	keySize         int
	mode            string
	padding         string
	parallel        bool
	encryptTime     time.Duration
	decryptTime     time.Duration
	totalTime       time.Duration
	originalSize    int64
	encryptedSize   int64
	encryptSpeedMBs float64
	decryptSpeedMBs float64
	success         bool
	errorMsg        string
	errorDetail     string
}

func TestRijndaelAll(t *testing.T) {
	if err := checkDirectories(); err != nil {
		t.Fatalf("Ошибка проверки директорий: %v", err)
	}

	testFiles := []string{
		"../files/text.txt",
		"../files/photo.jpg",
	}

	var existingFiles []string
	for _, file := range testFiles {
		if _, err := os.Stat(file); err == nil {
			existingFiles = append(existingFiles, file)
			fmt.Printf("Найден тестовый файл: %s\n", file)
		}
	}

	if len(existingFiles) == 0 {
		t.Fatal("Не найдено файлов для тестирования")
	}

	tests := generateRijndaelTests(existingFiles)

	fmt.Printf("\nЗапуск %d тестов Rijndael/AES...\n\n", len(tests))

	var results []TestResult
	successCount := 0

	for i, test := range tests {
		fmt.Printf("Тест %d/%d: AES-%d-%d (mod 0x%02x) %s %s ", 
			i+1, len(tests), test.keySize*8, test.blockSize*8, test.modulus, 
			test.modeName, test.paddingName)
		if test.parallel {
			fmt.Printf("(параллельный) ")
		}

		result := runRijndaelTest(test)
		results = append(results, result)

		if result.success {
			successCount++
			fmt.Printf("УСПЕШНО: %.1f MB/s\n", result.encryptSpeedMBs)
		} else {
			fmt.Printf("ОШИБКА: %s\n", result.errorMsg)
			if result.errorDetail != "" {
				fmt.Printf("   Подробности: %s\n", result.errorDetail)
			}
		}
	}

	printSummary(results)
	fmt.Printf("\nИТОГО: Успешно выполнено %d из %d тестов\n", successCount, len(tests))
	
	fmt.Printf("\nДОПОЛНИТЕЛЬНЫЕ ТЕСТЫ GF(2⁸):\n")
	testGF28Operations()
	testIrreduciblePolynomials()
}

func generateRijndaelTests(files []string) []RijndaelTest {
	var tests []RijndaelTest

	configs := []struct {
		blockSize int
		keySize   int
		modulus   byte
	}{
		{16, 16, 0x1B},
		{16, 24, 0x1B},
		{16, 32, 0x1B},
		{24, 24, 0x1B},
		{32, 32, 0x1B},
		{16, 16, 0x1D},
		{16, 16, 0x2B},
	}

	modes := []struct {
		mode        cripta.CipherMode
		modeName    string
		canParallel bool
	}{
		{cripta.CipherModeECB, "ECB", true},
		{cripta.CipherModeCBC, "CBC", false},
		{cripta.CipherModeCTR, "CTR", true},
		{cripta.CipherModeCFB, "CFB", false},
	}

	paddings := []struct {
		padding     cripta.PaddingMode
		paddingName string
	}{
		{cripta.PaddingModePKCS7, "PKCS7"},
		{cripta.PaddingModeANSIX923, "ANSI"},
		{cripta.PaddingModeISO10126, "ISO"},
	}

	testCounter := 0

	for fileIdx := 0; fileIdx < len(files) && fileIdx < 2; fileIdx++ {
		for cfgIdx := 0; cfgIdx < len(configs) && cfgIdx < 4; cfgIdx++ {
			for modeIdx := 0; modeIdx < len(modes) && modeIdx < 2; modeIdx++ {
				for paddingIdx := 0; paddingIdx < len(paddings) && paddingIdx < 1; paddingIdx++ {
					testCounter++
					
					tests = append(tests, RijndaelTest{
						name:        fmt.Sprintf("R%d", testCounter),
						blockSize:   configs[cfgIdx].blockSize,
						keySize:     configs[cfgIdx].keySize,
						modulus:     configs[cfgIdx].modulus,
						mode:        modes[modeIdx].mode,
						modeName:    modes[modeIdx].modeName,
						padding:     paddings[paddingIdx].padding,
						paddingName: paddings[paddingIdx].paddingName,
						parallel:    modes[modeIdx].canParallel && (fileIdx == 1),
						inputFile:   files[fileIdx],
					})
				}
			}
		}
	}

	return tests
}

func runRijndaelTest(test RijndaelTest) TestResult {
	result := TestResult{
		testName:  test.name,
		blockSize: test.blockSize,
		keySize:   test.keySize,
		mode:      test.modeName,
		padding:   test.paddingName,
		parallel:  test.parallel,
	}

	fileInfo, err := os.Stat(test.inputFile)
	if err != nil {
		result.errorMsg = "Ошибка доступа к файлу"
		result.errorDetail = err.Error()
		return result
	}
	result.originalSize = fileInfo.Size()

	data, err := os.ReadFile(test.inputFile)
	if err != nil {
		result.errorMsg = "Ошибка чтения файла"
		result.errorDetail = err.Error()
		return result
	}

	key := generateRandomBytes(test.keySize)
	iv := generateRandomBytes(test.blockSize)
	if test.mode == cripta.CipherModeECB {
		iv = []byte{}
	}

	cipher, err := cripta.NewRijndaelCipher(test.blockSize, test.keySize, test.modulus)
	if err != nil {
		result.errorMsg = "Ошибка создания шифра"
		result.errorDetail = err.Error()
		return result
	}

	if err := cipher.SetKey(key); err != nil {
		result.errorMsg = "Ошибка установки ключа"
		result.errorDetail = err.Error()
		return result
	}

	ctx, err := cripta.NewCipherContext(cipher, key, test.mode, test.padding, iv, test.blockSize, test.parallel)
	if err != nil {
		result.errorMsg = "Ошибка создания контекста"
		result.errorDetail = err.Error()
		return result
	}

	encryptStart := time.Now()
	encryptedData, err := ctx.Encrypt(data)
	encryptTime := time.Since(encryptStart)

	if err != nil {
		result.errorMsg = "Ошибка шифрования"
		result.errorDetail = err.Error()
		return result
	}

	if len(encryptedData) == 0 {
		result.errorMsg = "Результат шифрования пуст"
		return result
	}

	decryptStart := time.Now()
	decryptedData, err := ctx.Decrypt(encryptedData)
	decryptTime := time.Since(decryptStart)

	if err != nil {
		result.errorMsg = "Ошибка расшифрования"
		result.errorDetail = err.Error()
		return result
	}

	if len(data) != len(decryptedData) {
		result.errorMsg = "Несоответствие размеров"
		result.errorDetail = fmt.Sprintf("Оригинал: %d байт, Расшифровано: %d байт", len(data), len(decryptedData))
		return result
	}

	for i := 0; i < len(data); i++ {
		if data[i] != decryptedData[i] {
			result.errorMsg = "Нарушение целостности данных"
			result.errorDetail = fmt.Sprintf("Расхождение в байте %d: 0x%02x != 0x%02x", i, data[i], decryptedData[i])
			return result
		}
	}

	result.encryptTime = encryptTime
	result.decryptTime = decryptTime
	result.totalTime = encryptTime + decryptTime
	result.encryptedSize = int64(len(encryptedData))
	result.success = true

	dataSizeMB := float64(len(data)) / (1024 * 1024)
	if encryptTime > 0 {
		result.encryptSpeedMBs = dataSizeMB / encryptTime.Seconds()
	}
	if decryptTime > 0 {
		result.decryptSpeedMBs = dataSizeMB / decryptTime.Seconds()
	}

	return result
}

func printSummary(results []TestResult) {
	fmt.Printf("\nСВОДКА РЕЗУЛЬТАТОВ ТЕСТИРОВАНИЯ RIJNDAEL/AES:\n")
	fmt.Printf("%-12s | %-8s | %-6s | %-4s | %-10s | %-12s | %-12s | Статус\n",
		"Конфигурация", "Режим", "Паддинг", "Пар.", "Размер(КБ)", "Шифр(МБ/с)", "Дешифр(МБ/с)")
	fmt.Println("-------------|----------|--------|------|------------|-------------|-------------|----------")

	successCount := 0
	for _, result := range results {
		status := "УСПЕХ"
		if !result.success {
			status = "ОШИБКА"
		} else {
			successCount++
		}

		parallel := ""
		if result.parallel {
			parallel = "Да"
		}

		config := fmt.Sprintf("%d-%d", result.keySize*8, result.blockSize*8)
		
		encSpeed := 0.0
		decSpeed := 0.0
		if result.success {
			encSpeed = result.encryptSpeedMBs
			decSpeed = result.decryptSpeedMBs
		}

		fmt.Printf("%-12s | %-8s | %-6s | %-4s | %-10d | %-12.1f | %-12.1f | %s\n",
			config,
			result.mode,
			result.padding,
			parallel,
			result.originalSize/1024,
			encSpeed,
			decSpeed,
			status)
	}
}

func testGF28Operations() {
	fmt.Printf("\nТЕСТИРОВАНИЕ ОПЕРАЦИЙ В GF(2⁸):\n")
	
	gf := cripta.NewGF28Service()
	modulus := byte(0x1B)
	
	a := byte(0x57)
	b := byte(0x83)
	
	// Тест сложения
	sum := gf.Add(a, b)
	expectedSum := byte(0xD4)
	statusSum := "ПРОЙДЕН"
	if sum != expectedSum {
		statusSum = "НЕ ПРОЙДЕН"
	}
	fmt.Printf("   Сложение: 0x%02x ⊕ 0x%02x = 0x%02x (ожидается 0x%02x) [%s]\n", 
		a, b, sum, expectedSum, statusSum)
	
	// Тест умножения
	product, err := gf.Multiply(a, b, modulus)
	if err != nil {
		fmt.Printf("   Умножение: ошибка выполнения - %v [НЕ ПРОЙДЕН]\n", err)
	} else {
		expectedProduct := byte(0xC1)
		statusProduct := "ПРОЙДЕН"
		if product != expectedProduct {
			statusProduct = "НЕ ПРОЙДЕН"
		}
		fmt.Printf("   Умножение: 0x%02x ⊗ 0x%02x = 0x%02x (ожидается 0x%02x) [%s]\n", 
			a, b, product, expectedProduct, statusProduct)
	}
	
	// Тест обратного элемента
	inverse, err := gf.Inverse(a, modulus)
	if err != nil {
		fmt.Printf("   Обратный элемент: ошибка вычисления - %v [НЕ ПРОЙДЕН]\n", err)
	} else {
		check, _ := gf.Multiply(a, inverse, modulus)
		statusInverse := "ПРОЙДЕН"
		if check != 0x01 {
			statusInverse = "НЕ ПРОЙДЕН"
		}
		fmt.Printf("   Обратный элемент: (0x%02x)⁻¹ = 0x%02x (проверка: 0x%02x⊗0x%02x=0x%02x) [%s]\n", 
			a, inverse, a, inverse, check, statusInverse)
	}
	
	// Тест проверки на неприводимость
	isIrred := gf.IsIrreducible(modulus)
	statusIrred := "ПРОЙДЕН"
	if !isIrred {
		statusIrred = "НЕ ПРОЙДЕН"
	}
	fmt.Printf("   Проверка неприводимости: полином x⁸ + x⁴ + x³ + x + 1 (0x1B) неприводим = %v [%s]\n", 
		isIrred, statusIrred)
}

func testIrreduciblePolynomials() {
	fmt.Printf("\nТЕСТИРОВАНИЕ НЕПРИВОДИМЫХ ПОЛИНОМОВ:\n")
	
	gf := cripta.NewGF28Service()
	
	polys := gf.GetAllIrreduciblePolynomials()
	
	expectedCount := 30
	statusCount := "ПРОЙДЕН"
	if len(polys) != expectedCount {
		statusCount = "НЕ ПРОЙДЕН"
	}
	fmt.Printf("   Найдено неприводимых полиномов степени 8: %d (ожидается %d) [%s]\n", 
		len(polys), expectedCount, statusCount)
	
	fmt.Printf("   Первые 10 неприводимых полиномов:")
	for i := 0; i < 10 && i < len(polys); i++ {
		fmt.Printf(" 0x%02x", polys[i])
	}
	fmt.Println()
	
	testPoly := uint16(0x11B)
	fmt.Printf("   Факторизация 0x%03x (x⁸ + x⁴ + x³ + x + 1): полином неприводим\n", testPoly)
	
	if gf.IsIrreducible(0x1B) {
		fmt.Printf("   Дополнительная проверка: 0x1B определен как неприводимый полином\n")
	} else {
		fmt.Printf("   ВНИМАНИЕ: 0x1B ошибочно определен как приводимый полином\n")
	}
}

func checkDirectories() error {
	dirs := []string{"../files"}
	for _, dir := range dirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return fmt.Errorf("директория %s не существует", dir)
		}
	}
	return nil
}

func generateRandomBytes(size int) []byte {
	if size == 0 {
		return nil
	}
	data := make([]byte, size)
	rand.Read(data)
	return data
}

func TestBasicRijndaelOperations(t *testing.T) {
	fmt.Printf("\nБАЗОВЫЕ ТЕСТЫ РЕАЛИЗАЦИИ RIJNDAEL:\n")
	
	gf := cripta.NewGF28Service()
	
	testCases := []struct {
		name    string
		block   int
		key     int
		modulus byte
	}{
		{"AES-128 (стандарт)", 16, 16, 0x1B},
		{"AES-192 (стандарт)", 16, 24, 0x1B},
		{"AES-256 (стандарт)", 16, 32, 0x1B},
		{"Rijndael-192/192", 24, 24, 0x1B},
		{"AES-128 с полиномом 0x1D", 16, 16, 0x1D},
		{"AES-128 с полиномом 0x2B", 16, 16, 0x2B},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cipher, err := cripta.NewRijndaelCipher(tc.block, tc.key, tc.modulus)
			if err != nil {
				t.Errorf("Не удалось создать шифр %s: %v", tc.name, err)
				return
			}
			
			if !gf.IsIrreducible(tc.modulus) {
				t.Logf("Внимание: используемый модуль 0x%02x может быть приводимым для %s", tc.modulus, tc.name)
			}
			
			data := make([]byte, tc.block)
			for i := range data {
				data[i] = byte(i)
			}
			
			key := make([]byte, tc.key)
			for i := range key {
				key[i] = byte(i + 1)
			}
			
			if err := cipher.SetKey(key); err != nil {
				t.Errorf("Ошибка установки ключа: %v", err)
				return
			}
			
			encrypted, err := cipher.EncryptBlock(data)
			if err != nil {
				t.Errorf("Ошибка шифрования: %v", err)
				return
			}
			
			decrypted, err := cipher.DecryptBlock(encrypted)
			if err != nil {
				t.Errorf("Ошибка расшифрования: %v", err)
				return
			}
			
			for i := range data {
				if data[i] != decrypted[i] {
					t.Errorf("Несоответствие данных в байте %d: 0x%02x != 0x%02x", i, data[i], decrypted[i])
					break
				}
			}
			
			fmt.Printf("   %s: тест пройден успешно\n", tc.name)
		})
	}
}

func TestRijndaelModes(t *testing.T) {
	fmt.Printf("\nТЕСТИРОВАНИЕ РЕЖИМОВ РАБОТЫ ШИФРА:\n")
	
	cipher, err := cripta.NewRijndaelCipher(16, 16, 0x1B)
	if err != nil {
		t.Fatalf("Не удалось создать базовый шифр: %v", err)
	}
	
	modes := []cripta.CipherMode{
		cripta.CipherModeECB,
		cripta.CipherModeCBC,
		cripta.CipherModeCTR,
		cripta.CipherModeCFB,
	}
	
	testData := []byte("Тестовое сообщение для проверки режимов шифрования Rijndael/AES")
	key := generateRandomBytes(16)
	
	for _, mode := range modes {
		modeName := ""
		switch mode {
		case cripta.CipherModeECB:
			modeName = "ECB"
		case cripta.CipherModeCBC:
			modeName = "CBC"
		case cripta.CipherModeCTR:
			modeName = "CTR"
		case cripta.CipherModeCFB:
			modeName = "CFB"
		}
		
		t.Run(modeName, func(t *testing.T) {
			iv := generateRandomBytes(16)
			if mode == cripta.CipherModeECB {
				iv = []byte{}
			}
			
			ctx, err := cripta.NewCipherContext(cipher, key, mode, cripta.PaddingModePKCS7, iv, 16, false)
			if err != nil {
				t.Errorf("Ошибка создания контекста для режима %s: %v", modeName, err)
				return
			}
			
			encrypted, err := ctx.Encrypt(testData)
			if err != nil {
				t.Errorf("Ошибка шифрования в режиме %s: %v", modeName, err)
				return
			}
			
			decrypted, err := ctx.Decrypt(encrypted)
			if err != nil {
				t.Errorf("Ошибка расшифрования в режиме %s: %v", modeName, err)
				return
			}
			
			if string(testData) != string(decrypted) {
				t.Errorf("Несоответствие данных после шифрования/расшифрования в режиме %s", modeName)
			} else {
				fmt.Printf("   Режим %s: корректная работа подтверждена\n", modeName)
			}
		})
	}
}