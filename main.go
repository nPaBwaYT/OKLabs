package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/nPaBwaYT/crypta"
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
	// Определяем флаги
	encryptFlag := flag.Bool("e", false, "Режим шифрования")
	decryptFlag := flag.Bool("d", false, "Режим дешифрования")
	algorithmFlag := flag.String("a", "des", "Алгоритм шифрования: des, deal128, deal192, deal256")
	modeFlag := flag.String("m", "cbc", "Режим шифрования: ecb, cbc, pcbc, cfb, ofb, ctr, random")
	paddingFlag := flag.String("p", "pkcs7", "Режим набивки: zeros, pkcs7, ansi, iso")
	parallelFlag := flag.Bool("parallel", false, "Использовать параллельную обработку (только для ECB/CTR)")
	keyFlag := flag.String("k", "", "Ключ шифрования в hex (если не указан, будет сгенерирован)")
	ivFlag := flag.String("iv", "", "Вектор инициализации в hex (если не указан, будет сгенерирован)")

	flag.Parse()

	// Проверяем аргументы
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

	// Проверяем существование входного файла
	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		log.Fatalf("Ошибка: входной файл '%s' не существует", inputFile)
	}

	// Выбираем алгоритм
	cipher, keyLength, err := createCipher(*algorithmFlag)
	if err != nil {
		log.Fatalf("Ошибка создания шифра: %v", err)
	}

	// Генерируем или парсим ключ
	key, err := getOrGenerateKey(*keyFlag, keyLength)
	if err != nil {
		log.Fatalf("Ошибка работы с ключом: %v", err)
	}

	// Преобразуем режимы
	cipherMode := parseCipherMode(*modeFlag)
	paddingMode := parsePaddingMode(*paddingFlag)

	// Генерируем или парсим IV
	iv, err := getOrGenerateIV(*ivFlag, 8) // 8 байт для DES/DEAL
	if err != nil {
		log.Fatalf("Ошибка работы с IV: %v", err)
	}

	// Создаем контекст шифрования
	ctx, err := cripta.NewCipherContext(cipher, key, cipherMode, paddingMode, iv, 8)
	if err != nil {
		log.Fatalf("Ошибка создания контекста шифрования: %v", err)
	}

	// Выполняем операцию
	startTime := time.Now()

	if *encryptFlag {
		err = encryptFile(ctx, inputFile, outputFile, *parallelFlag)
		if err != nil {
			log.Fatalf("Ошибка шифрования: %v", err)
		}
		fmt.Printf("Файл успешно зашифрован: %s -> %s\n", inputFile, outputFile)
	} else {
		err = decryptFile(ctx, inputFile, outputFile, *parallelFlag)
		if err != nil {
			log.Fatalf("Ошибка дешифрования: %v", err)
		}
		fmt.Printf("Файл успешно дешифрован: %s -> %s\n", inputFile, outputFile)
	}

	// Выводим информацию
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

// createCipher создает экземпляр шифра в зависимости от алгоритма
func createCipher(algorithm string) (cripta.ISymmetricCipher, int, error) {
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

// getOrGenerateKey возвращает ключ из флага или генерирует новый
func getOrGenerateKey(keyFlag string, keyLength int) ([]byte, error) {
	if keyFlag != "" {
		// Парсим ключ из hex
		return parseHexString(keyFlag, keyLength)
	}
	
	// Генерируем случайный ключ
	key := make([]byte, keyLength)
	_, err := cripta.GenerateRandomBytes(key)
	if err != nil {
		return nil, fmt.Errorf("ошибка генерации ключа: %w", err)
	}
	return key, nil
}

// getOrGenerateIV возвращает IV из флага или генерирует новый
func getOrGenerateIV(ivFlag string, ivLength int) ([]byte, error) {
	if ivFlag != "" {
		// Парсим IV из hex
		return parseHexString(ivFlag, ivLength)
	}
	
	// Генерируем случайный IV
	iv := make([]byte, ivLength)
	_, err := cripta.GenerateRandomBytes(iv)
	if err != nil {
		return nil, fmt.Errorf("ошибка генерации IV: %w", err)
	}
	return iv, nil
}

// parseHexString парсит hex строку в байты
func parseHexString(hexStr string, expectedLength int) ([]byte, error) {
	// Простая реализация - в реальном приложении нужно использовать hex.DecodeString
	// Здесь для простоты генерируем байты из строки
	// Декодируем hex строку
	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("неверный hex формат: %w", err)
	}

	// Проверяем длину
	if len(data) != expectedLength {
		return nil, fmt.Errorf("неверная длина: ожидается %d байт, получено %d", expectedLength, len(data))
	}

	return data, nil
}

// parseCipherMode преобразует строку в CipherMode
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

// parsePaddingMode преобразует строку в PaddingMode
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

// encryptFile шифрует файл
func encryptFile(ctx *cripta.CipherContext, inputPath, outputPath string, parallel bool) error {
	if parallel && (ctx.GetMode() == cripta.CipherModeECB || ctx.GetMode() == cripta.CipherModeCTR) {
		// Для параллельных режимов читаем файл и используем EncryptSync
		data, err := os.ReadFile(inputPath)
		if err != nil {
			return fmt.Errorf("ошибка чтения файла: %w", err)
		}
		
		encrypted, err := ctx.EncryptSync(data)
		if err != nil {
			return fmt.Errorf("ошибка шифрования: %w", err)
		}
		
		err = os.WriteFile(outputPath, encrypted, 0644)
		if err != nil {
			return fmt.Errorf("ошибка записи файла: %w", err)
		}
	} else {
		// Для последовательных режимов используем EncryptFile
		err := ctx.EncryptFile(inputPath, outputPath)
		if err != nil {
			return fmt.Errorf("ошибка шифрования файла: %w", err)
		}
	}
	return nil
}

// decryptFile дешифрует файл
func decryptFile(ctx *cripta.CipherContext, inputPath, outputPath string, parallel bool) error {
	if parallel && (ctx.GetMode() == cripta.CipherModeECB || ctx.GetMode() == cripta.CipherModeCTR) {
		// Для параллельных режимов читаем файл и используем DecryptSync
		data, err := os.ReadFile(inputPath)
		if err != nil {
			return fmt.Errorf("ошибка чтения файла: %w", err)
		}
		
		decrypted, err := ctx.DecryptSync(data)
		if err != nil {
			return fmt.Errorf("ошибка дешифрования: %w", err)
		}
		
		err = os.WriteFile(outputPath, decrypted, 0644)
		if err != nil {
			return fmt.Errorf("ошибка записи файла: %w", err)
		}
	} else {
		// Для последовательных режимов используем DecryptFile
		err := ctx.DecryptFile(inputPath, outputPath)
		if err != nil {
			return fmt.Errorf("ошибка дешифрования файла: %w", err)
		}
	}
	return nil
}

// Дополнительные методы для CipherContext (нужно добавить в cripta package)
// В файле cipher_context.go добавьте:

// GetMode возвращает текущий режим шифрования