package cripta

import (
	"fmt"
	"log"
	"time"
	"math/big"
)

// Demo демонстрирует работу всех компонентов
func Demo() {
	fmt.Println("=== Демонстрация работы криптографического пакета ===")
	
	// 1. Демонстрация математического сервиса
	fmt.Println("\n1. Математический сервис:")
	
	// Символ Лежандра
	a, p := int64(5), int64(11)
	fmt.Printf("   Символ Лежандра (%d/%d) = %d\n", a, p, LegendreSymbol(a, p))
	
	// Символ Якоби
	a2, n2 := int64(15), int64(11)
	fmt.Printf("   Символ Якоби (%d/%d) = %d\n", a2, n2, JacobiSymbol(a2, n2))
	
	// НОД
	num1, num2 := int64(48), int64(18)
	gcd := GCD(num1, num2)
	fmt.Printf("   НОД(%d, %d) = %d\n", num1, num2, gcd)
	
	// Расширенный алгоритм Евклида
	g, x, y := ExtendedGCD(num1, num2)
	fmt.Printf("   Расширенный НОД(%d, %d) = %d, коэффициенты: x=%d, y=%d\n", 
		num1, num2, g, x, y)
	
	// Возведение в степень по модулю
	base, exp, mod := int64(7), int64(13), int64(11)
	result := ModExp(base, exp, mod)
	fmt.Printf("   %d^%d mod %d = %d\n", base, exp, mod, result)
	
	// 2. Демонстрация тестов простоты
	fmt.Println("\n2. Тесты простоты:")
	
	testNumber := big.NewInt(97)
	probability := 0.999
	
	tests := []PrimalityTest{
		NewFermatTest(),
		NewSolovayStrassenTest(),
		NewMillerRabinTest(),
	}
	
	for _, test := range tests {
		isPrime := test.IsPrime(testNumber, probability)
		fmt.Printf("   %s: %d является простым? %v\n", 
			test.TestName(), testNumber, isPrime)
	}
	
	// 3. Демонстрация RSA
	fmt.Println("\n3. RSA Шифрование/Дешифрование:")
	
	// Создаем сервис RSA
	rsaService := NewRSAService(RSAMillerRabin, 0.999, 512)
	
	// Генерируем ключи
	err := rsaService.GenerateNewKey()
	if err != nil {
		log.Printf("Ошибка генерации ключей RSA: %v", err)
	} else {
		fmt.Println("   Ключи RSA успешно сгенерированы")
		
		// Получаем открытый ключ
		publicKey, err := rsaService.GetPublicKey()
		if err != nil {
			log.Printf("Ошибка получения открытого ключа: %v", err)
		} else {
			fmt.Printf("   Открытый ключ:\n")
			fmt.Printf("     N: %s\n", publicKey.N.String())
			fmt.Printf("     E: %s\n", publicKey.E.String())
		}
		
		// Тестовое сообщение
		message := "Hello, RSA!"
		fmt.Printf("   Исходное сообщение: %s\n", message)
		
		// Шифруем
		ciphertext, err := rsaService.EncryptString(message)
		if err != nil {
			log.Printf("Ошибка шифрования: %v", err)
		} else {
			fmt.Printf("   Зашифрованное сообщение (hex): %x\n", ciphertext)
			
			// Дешифруем
			decrypted, err := rsaService.DecryptString(ciphertext)
			if err != nil {
				log.Printf("Ошибка дешифрования: %v", err)
			} else {
				fmt.Printf("   Дешифрованное сообщение: %s\n", decrypted)
			}
		}
	}
	
	// 4. Демонстрация атаки Винера (на тестовых данных)
	fmt.Println("\n4. Атака Винера (демонстрация):")
	
	// Создаем сервис для атаки Винера
	wienerService := NewWienerAttackService()
	
	// Тестовый открытый ключ (маленький для демонстрации)
	testPublicKey := &RSAPublicKey{
		N: big.NewInt(3233), // n = 61 * 53
		E: big.NewInt(17),
	}
	
	fmt.Printf("   Тестовый открытый ключ:\n")
	fmt.Printf("     N: %s\n", testPublicKey.N.String())
	fmt.Printf("     E: %s\n", testPublicKey.E.String())
	
	// Выполняем атаку
	weinerResult := wienerService.Attack(testPublicKey)
	
	if weinerResult.Success {
		fmt.Println("   Атака успешна!")
		fmt.Printf("   Найденная закрытая экспонента d: %s\n", weinerResult.FoundD.String())
		fmt.Printf("   Значение φ(N): %s\n", weinerResult.PhiN.String())
		fmt.Printf("   Количество проверенных подходящих дробей: %d\n", len(weinerResult.Convergents))
	} else {
		fmt.Println("   Атака не удалась для данного ключа")
		fmt.Printf("   Проверено подходящих дробей: %d\n", len(weinerResult.Convergents))
	}
	
	fmt.Println("\n=== Демонстрация завершена ===")
}

// DemoLargeKeys демонстрация работы с большими ключами
func DemoLargeKeys() {
	fmt.Println("\n=== Демонстрация работы с большими ключами (2048 бит) ===")
	
	// Генерация 2048-битного ключа
	rsaService := NewRSAService(RSAMillerRabin, 0.999999, 2048)
	
	fmt.Println("Генерация 2048-битного RSA ключа...")
	start := time.Now()
	
	err := rsaService.GenerateNewKey()
	if err != nil {
		log.Fatalf("Ошибка генерации ключа: %v", err)
	}
	
	elapsed := time.Since(start)
	fmt.Printf("Ключ сгенерирован за %v\n", elapsed)
	
	// Получаем ключи
	publicKey, _ := rsaService.GetPublicKey()
	fmt.Printf("Длина ключа: %d бит\n", publicKey.N.BitLen())
	
	// Тестовое шифрование
	message := "This is a test message for 2048-bit RSA encryption"
	fmt.Printf("\nСообщение: %s\n", message)
	
	// Шифруем
	ciphertext, err := rsaService.EncryptString(message)
	if err != nil {
		log.Printf("Ошибка шифрования: %v", err)
	} else {
		fmt.Printf("Размер шифртекста: %d байт\n", len(ciphertext))
		
		// Дешифруем
		decrypted, err := rsaService.DecryptString(ciphertext)
		if err != nil {
			log.Printf("Ошибка дешифрования: %v", err)
		} else {
			fmt.Printf("Дешифровано успешно: %s\n", decrypted)
		}
	}
	
	fmt.Println("\n=== Демонстрация больших ключей завершена ===")
}

// RunAllTests запускает все тесты
func RunAllTests() {
	fmt.Println("Запуск всех тестов...")
	Demo()
	DemoLargeKeys()
}