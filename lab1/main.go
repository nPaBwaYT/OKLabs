package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"OKLabs/cripta"
)

/*
Шифрование файла DES в режиме CBC
go run main.go -e -a=des -m=cbc input.txt output.enc

Дешифрование файла DES
go run main.go -d -a=des -m=cbc input.enc output.txt

Шифрование DEAL-256 с параллельной обработкой
go run main.go -e -a=deal256 -m=ctr -parallel input.txt output.enc

Шифрование с указанием ключа и IV
go run main.go -e -a=des -k="0123456789ABCDEF" -iv="FEDCBA9876543210" input.txt output.enc

Шифрование с разными режимами набивки
go run main.go -e -a=des -m=cbc -p=ansi input.txt output.enc

Поддержка алгоритмов: DES, DEAL-128, DEAL-192, DEAL-256
Режимы шифрования: ECB, CBC, PCBC, CFB, OFB, CTR, RANDOM_DELTA
Режимы набивки: Zeros, PKCS7, ANSI X.923, ISO 10126
Параллельная обработка: для ECB и CTR режимов
*/

func main() {
	encryptFlag := flag.Bool("e", false, "Режим шифрования")
	decryptFlag := flag.Bool("d", false, "Режим дешифрования")
	algorithmFlag := flag.String("a", "des", "Алгоритм шифрования: des, deal128, deal192, deal256")
	modeFlag := flag.String("m", "cbc", "Режим шифрования: ecb, cbc, pcbc, cfb, ofb, ctr, random")
	paddingFlag := flag.String("p", "pkcs7", "Режим набивки: zeros, pkcs7, ansi, iso")
	parallelFlag := flag.Bool("parallel", false, "Использовать параллельную обработку (только для ECB/CTR)")
	keyFlag := flag.String("k", "", "Ключ шифрования в hex")
	ivFlag := flag.String("iv", "", "Вектор инициализации в hex")

	flag.Parse()

	if (*encryptFlag && *decryptFlag) || (!*encryptFlag && !*decryptFlag) {
		fmt.Println("Использование:")
		fmt.Println("  Шифрование: go run main.go -e -a=des -m=cbc input.txt output.enc")
		fmt.Println("  Дешифрование: go run main.go -d -a=des -m=cbc input.enc output.txt")
		fmt.Println("\nФлаги:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	args := flag.Args()
	if len(args) != 2 {
		fmt.Println("Ошибка: необходимо указать входной и выходной файлы")
		os.Exit(1)
	}

	inputFile := args[0]
	outputFile := args[1]

	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		log.Fatalf("Ошибка: входной файл '%s' не существует", inputFile)
	}

	cipher, keyLength, err := CreateCipher(*algorithmFlag)
	if err != nil {
		log.Fatalf("Ошибка создания шифра: %v", err)
	}

	blockSize := 8
	if *algorithmFlag != "des" {
		blockSize = 16
	}

	key, err := getOrGenerateKey(*keyFlag, keyLength)
	if err != nil {
		log.Fatalf("Ошибка работы с ключом: %v", err)
	}

	cipherMode := parseCipherMode(*modeFlag)
	paddingMode := parsePaddingMode(*paddingFlag)

	iv, err := getOrGenerateIV(*ivFlag, blockSize, cipherMode)
	if err != nil {
		log.Fatalf("Ошибка работы с IV: %v", err)
	}

	ctx, err := cripta.NewCipherContext(cipher, key, cipherMode, paddingMode, iv, blockSize, *parallelFlag)
	if err != nil {
		log.Fatalf("Ошибка создания контекста шифрования: %v", err)
	}

	startTime := time.Now()

	if *encryptFlag {
		err = encryptFile(ctx, inputFile, outputFile)
		if err != nil {
			log.Fatalf("Ошибка шифрования: %v", err)
		}
		fmt.Printf("Файл успешно зашифрован: %s -> %s\n", inputFile, outputFile)
	} else {
		err = decryptFile(ctx, inputFile, outputFile)
		if err != nil {
			log.Fatalf("Ошибка дешифрования: %v", err)
		}
		fmt.Printf("Файл успешно дешифрован: %s -> %s\n", inputFile, outputFile)
	}

	duration := time.Since(startTime)
	fileInfo, _ := os.Stat(inputFile)
	fileSize := fileInfo.Size()

	fmt.Printf("\nИнформация:\n")
	fmt.Printf("  Алгоритм: %s\n", *algorithmFlag)
	fmt.Printf("  Режим: %s\n", *modeFlag)
	fmt.Printf("  Набивка: %s\n", *paddingFlag)
	fmt.Printf("  Параллельная обработка: %v\n", *parallelFlag)
	fmt.Printf("  Размер файла: %d байт\n", fileSize)
	fmt.Printf("  Время выполнения: %v\n", duration)
	fmt.Printf("  Ключ: %x\n", key)
	if cipherMode != cripta.CipherModeECB {
		fmt.Printf("  IV: %x\n", iv)
	}
}

func CreateCipher(algorithm string) (cripta.ISymmetricCipher, int, error) {
	switch algorithm {
	case "des":
		cipher, err := cripta.NewDESCipher()
		return cipher, 8, err
	case "deal128":
		cipher, err := cripta.NewDEALCipher(16)
		return cipher, 16, err
	case "deal192":
		cipher, err := cripta.NewDEALCipher(24)
		return cipher, 24, err
	case "deal256":
		cipher, err := cripta.NewDEALCipher(32)
		return cipher, 32, err
	default:
		return nil, 0, fmt.Errorf("неизвестный алгоритм: %s", algorithm)
	}
}

func getOrGenerateKey(keyFlag string, keyLength int) ([]byte, error) {
	if keyFlag != "" {
		return parseHexString(keyFlag, keyLength)
	}
	
	key := make([]byte, keyLength)
	_, err := cripta.GenerateRandomBytes(key)
	if err != nil {
		return nil, fmt.Errorf("ошибка генерации ключа: %w", err)
	}
	return key, nil
}

func getOrGenerateIV(ivFlag string, ivLength int, mode cripta.CipherMode) ([]byte, error) {
	if ivFlag != "" {
		return parseHexString(ivFlag, ivLength)
	}
	
	if mode == cripta.CipherModeECB {
		return nil, nil
	}
	
	iv := make([]byte, ivLength)
	_, err := cripta.GenerateRandomBytes(iv)
	if err != nil {
		return nil, fmt.Errorf("ошибка генерации IV: %w", err)
	}
	return iv, nil
}

func parseHexString(hexStr string, expectedLength int) ([]byte, error) {
	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("неверный hex формат: %w", err)
	}

	if len(data) != expectedLength {
		return nil, fmt.Errorf("неверная длина: ожидается %d байт, получено %d", expectedLength, len(data))
	}

	return data, nil
}

func parseCipherMode(mode string) cripta.CipherMode {
	switch mode {
	case "ecb":
		return cripta.CipherModeECB
	case "cbc":
		return cripta.CipherModeCBC
	case "pcbc":
		return cripta.CipherModePCBC
	case "cfb":
		return cripta.CipherModeCFB
	case "ofb":
		return cripta.CipherModeOFB
	case "ctr":
		return cripta.CipherModeCTR
	case "random":
		return cripta.CipherModeRandomDelta
	default:
		return cripta.CipherModeCBC
	}
}

func parsePaddingMode(padding string) cripta.PaddingMode {
	switch padding {
	case "zeros":
		return cripta.PaddingModeZeros
	case "pkcs7":
		return cripta.PaddingModePKCS7
	case "ansi":
		return cripta.PaddingModeANSIX923
	case "iso":
		return cripta.PaddingModeISO10126
	default:
		return cripta.PaddingModePKCS7
	}
}

func encryptFile(ctx *cripta.CipherContext, inputPath, outputPath string) error {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("ошибка чтения файла: %w", err)
	}
	
	encrypted, err := ctx.Encrypt(data)
	if err != nil {
		return fmt.Errorf("ошибка шифрования: %w", err)
	}
	
	err = os.WriteFile(outputPath, encrypted, 0644)
	if err != nil {
		return fmt.Errorf("ошибка записи файла: %w", err)
	}
	
	return nil
}

func decryptFile(ctx *cripta.CipherContext, inputPath, outputPath string) error {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("ошибка чтения файла: %w", err)
	}
	
	decrypted, err := ctx.Decrypt(data)
	if err != nil {
		return fmt.Errorf("ошибка дешифрования: %w", err)
	}
	
	err = os.WriteFile(outputPath, decrypted, 0644)
	if err != nil {
		return fmt.Errorf("ошибка записи файла: %w", err)
	}
	
	return nil
}