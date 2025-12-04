package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"testing"
	"time"

	"OKLabs/cripta"
)

type CryptoTest struct {
	name        string
	algorithm   string
	keySize     int
	mode        cripta.CipherMode
	modeName    string
	padding     cripta.PaddingMode
	paddingName string
	parallel    bool
	inputFile   string
}

type TestResult struct {
	testName        string
	algorithm       string
	mode            string
	padding         string
	parallel        bool
	encryptTime     time.Duration
	decryptTime     time.Duration
	totalTime       time.Duration
	originalSize    int64
	encryptedSize   int64
	encryptSpeedKBs float64
	decryptSpeedKBs float64
	success         bool
	errorMsg        string
	errorDetail     string
}

func Test(t *testing.T) {
	if err := checkDirectories(); err != nil {
		t.Fatalf("❌ Ошибка директорий: %v", err)
	}

	testFiles := []string{
		"../files/text.txt",    // Малый файл
		"../files/photo.jpg",   // Средний файл  
		"../files/video.mp4",   // Большой файл (только параллельные режимы)
	}

	var existingFiles []string
	for _, file := range testFiles {
		if _, err := os.Stat(file); err == nil {
			existingFiles = append(existingFiles, file)
			fmt.Printf("✅ %s\n", file)
		}
	}

	if len(existingFiles) == 0 {
		t.Fatal("❌ Не найдено файлов для тестирования")
	}

	tests := generateCryptoTests(existingFiles)

	fmt.Printf("\nЗапуск %d тестов...\n", len(tests))

	var results []TestResult
	successCount := 0

	for i, test := range tests {
		fmt.Printf("Тест %d/%d: %s %s %s ", i+1, len(tests), test.algorithm, test.modeName, test.paddingName)
		if test.parallel {
			fmt.Printf("(параллельный) ")
		}

		result := runCryptoTest(test)
		results = append(results, result)

		if result.success {
			successCount++
			fmt.Printf("✅ %.1f KB/s\n", result.encryptSpeedKBs)
		} else {
			fmt.Printf("❌ %s\n", result.errorMsg)
			if result.errorDetail != "" {
				fmt.Printf("   Детали: %s\n", result.errorDetail)
			}
		}
	}

	printSummary(results)
	fmt.Printf("\n✅ Успешно: %d/%d тестов\n", successCount, len(tests))
	
	// Детальный анализ ошибок
	analyzeErrors(results)
}

func generateCryptoTests(files []string) []CryptoTest {
	var tests []CryptoTest

	algorithms := []struct {
		name    string
		keySize int
	}{
		{"des", 8},
		{"deal128", 16},
		{"deal192", 24},
		{"deal256", 32},
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
		{cripta.CipherModeOFB, "OFB", false},
		{cripta.CipherModeRandomDelta, "RD", false},
	}

	paddings := []struct {
		padding     cripta.PaddingMode
		paddingName string
	}{
		
		{cripta.PaddingModeZeros, "Zeros"},
		{cripta.PaddingModePKCS7, "PKCS7"},
		{cripta.PaddingModeANSIX923, "ANSI"},
		{cripta.PaddingModeISO10126, "ISO"},
	}

	testCounter := 0

	// 15 оптимизированных тестов
	testConfigs := []struct {
		fileIndex    int
		algoIndex   int
		modeIndex   int
		paddingIndex int
		parallel    bool
	}{
		// Малый файл (text.txt) - базовые тесты
		{0, 0, 1, 1, false}, // DES-CBC-Zeros
		{0, 1, 3, 2, false},  // DEAL128-CFB-PKCS7
		{0, 2, 4, 3, false},  // DEAL192-OFB-ANSI
		{0, 3, 5, 2, false},  // DEAL256-RD-ISO
		
		// Средний файл (photo.jpg) - различные комбинации
		{1, 0, 0, 3, true}, // DES-ECB-PKC57 (параллельный)
		{1, 1, 2, 1, true}, // DEAL128-CTR-ANSI (параллельный)
		{1, 0, 1, 3, false}, // DES-CBC-ISO
		{1, 2, 3, 2, false},  // DEAL192-CFB-ANSI
		
		// Большой файл (video.mp4) - только параллельные режимы
		{2, 0, 0, 1, true},  // DES-ECB-ANSI (параллельный)
		{2, 0, 2, 2, true},  // DES-CTR-ISO (параллельный)
		{2, 1, 0, 1, true},  // DEAL128-ECB-ANSI (параллельный)
		{2, 3, 2, 3, true},  // DEAL256-CTR-PKCS7 (параллельный)

	}

	for _, config := range testConfigs {
		if config.fileIndex >= len(files) {
			continue
		}

		file := files[config.fileIndex]
		algo := algorithms[config.algoIndex % len(algorithms)]
		mode := modes[config.modeIndex % len(modes)]
		padding := paddings[config.paddingIndex % len(paddings)]

		testCounter++

		tests = append(tests, CryptoTest{
			name:        fmt.Sprintf("T%d", testCounter),
			algorithm:   algo.name,
			keySize:     algo.keySize,
			mode:        mode.mode,
			modeName:    mode.modeName,
			padding:     padding.padding,
			paddingName: padding.paddingName,
			parallel:    config.parallel && mode.canParallel,
			inputFile:   file,
		})
	}

	return tests
}

func runCryptoTest(test CryptoTest) TestResult {
	result := TestResult{
		testName:  test.name,
		algorithm: test.algorithm,
		mode:      test.modeName,
		padding:   test.paddingName,
		parallel:  test.parallel,
	}

	fileInfo, err := os.Stat(test.inputFile)
	if err != nil {
		result.errorMsg = "File error"
		result.errorDetail = err.Error()
		return result
	}
	result.originalSize = fileInfo.Size()

	data, err := os.ReadFile(test.inputFile)
	if err != nil {
		result.errorMsg = "Read error"
		result.errorDetail = err.Error()
		return result
	}

	key := generateRandomBytes(test.keySize)
	blockSize := 8
	if test.algorithm != "des" {
		blockSize = 16
	}
	
	ivSize := blockSize
	if test.mode == cripta.CipherModeECB {
		ivSize = 0
	}
	iv := generateRandomBytes(ivSize)

	cipher, ks, err := CreateCipher(test.algorithm)
	if ks != test.keySize {
		result.errorMsg = "key length mismatch"
		result.errorDetail = err.Error()
		return result
	}
	if err != nil {
		result.errorMsg = "Cipher creation error"
		result.errorDetail = err.Error()
		return result
	}

	ctx, err := cripta.NewCipherContext(cipher, key, test.mode, test.padding, iv, blockSize, test.parallel)
	if err != nil {
		result.errorMsg = "Context creation error"
		result.errorDetail = err.Error()
		return result
	}

	encryptStart := time.Now()
	encryptedData, err := ctx.Encrypt(data)
	encryptTime := time.Since(encryptStart)

	if err != nil {
		result.errorMsg = "Encrypt error"
		result.errorDetail = err.Error()
		return result
	}

	if len(encryptedData) == 0 {
		result.errorMsg = "Empty encrypted data"
		return result
	}

	decryptStart := time.Now()
	decryptedData, err := ctx.Decrypt(encryptedData)
	decryptTime := time.Since(decryptStart)

	if err != nil {
		result.errorMsg = "Decrypt error"
		result.errorDetail = err.Error()
		return result
	}

	if len(data) != len(decryptedData) {
		result.errorMsg = "Size mismatch"
		result.errorDetail = fmt.Sprintf("Original: %d, Decrypted: %d", len(data), len(decryptedData))
		return result
	}

	if string(data) != string(decryptedData) {
		result.errorMsg = "Integrity error"
		for i := 0; i < len(data) && i < len(decryptedData); i++ {
			if data[i] != decryptedData[i] {
				result.errorDetail = fmt.Sprintf("First mismatch at byte %d: 0x%02x != 0x%02x", i, data[i], decryptedData[i])
				break
			}
		}
		return result
	}

	result.encryptTime = encryptTime
	result.decryptTime = decryptTime
	result.totalTime = encryptTime + decryptTime
	result.encryptedSize = int64(len(encryptedData))
	result.success = true

	dataSizeMB := float64(len(data)) / (1024 * 1024)
	result.encryptSpeedKBs = dataSizeMB / encryptTime.Seconds()
	result.decryptSpeedKBs = dataSizeMB / decryptTime.Seconds()

	return result
}

func printSummary(results []TestResult) {
	fmt.Printf("\n📊 СВОДКА РЕЗУЛЬТАТОВ:\n")
	fmt.Printf("%-8s | %-6s | %-6s | %-4s | %-8s | %-8s | %-8s | %s\n",
		"Algo", "Mode", "Pad", "Par", "Size(KB)", "Enc(MB/s)", "Dec(MB/s)", "Status")
	fmt.Println("---------|--------|--------|------|----------|-----------|-----------|--------")

	successCount := 0
	for _, result := range results {
		status := "✅"
		if !result.success {
			status = "❌"
		} else {
			successCount++
		}

		parallel := ""
		if result.parallel {
			parallel = "✓"
		}

		encSpeed := 0.0
		decSpeed := 0.0
		if result.success {
			encSpeed = result.encryptSpeedKBs
			decSpeed = result.decryptSpeedKBs
		}

		fmt.Printf("%-8s | %-6s | %-6s | %-4s | %-8d | %-9.1f | %-9.1f | %s\n",
			result.algorithm,
			result.mode,
			result.padding,
			parallel,
			result.originalSize / 1024,
			encSpeed,
			decSpeed,
			status)
	}
}

func analyzeErrors(results []TestResult) {
	fmt.Printf("\n🔍 АНАЛИЗ ОШИБОК:\n")
	
	errorCount := 0
	algoErrors := make(map[string]int)
	modeErrors := make(map[string]int)
	
	for _, result := range results {
		if !result.success {
			errorCount++
			algoErrors[result.algorithm]++
			modeErrors[result.mode]++
			
			fmt.Printf("\n❌ %s %s %s: %s\n", 
				result.algorithm, result.mode, result.padding, result.errorMsg)
			if result.errorDetail != "" {
				fmt.Printf("   %s\n", result.errorDetail)
			}
		}
	}
	
	if errorCount > 0 {
		fmt.Printf("\n📋 РАСПРЕДЕЛЕНИЕ ОШИБОК:\n")
		fmt.Printf("Всего ошибок: %d\n", errorCount)
		fmt.Printf("По алгоритмам: ")
		for algo, count := range algoErrors {
			fmt.Printf("%s(%d) ", algo, count)
		}
		fmt.Printf("\nПо режимам: ")
		for mode, count := range modeErrors {
			fmt.Printf("%s(%d) ", mode, count)
		}
		fmt.Println()
	}
}

func checkDirectories() error {
	dirs := []string{"../files", "../encrypted_files", "../decrypted_files"}
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