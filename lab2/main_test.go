package main

import (
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"OKLabs/cripta"
)

// TestRSAIntegration запускает основные интеграционные тесты
func TestRSAIntegration(t *testing.T) {
	fmt.Println("\nИНТЕГРАЦИОННЫЕ ТЕСТЫ RSA СИСТЕМЫ")
	fmt.Println(strings.Repeat("-", 40))

	tests := []struct {
		name string
		test func(*testing.T)
	}{
		{"Генерация ключей", testKeyGeneration},
		{"Шифрование/дешифрование", testEncryptionDecryption},
		{"Атака Винера", testWienerAttack},
		{"Производительность", testPerformance},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.test)
	}

	fmt.Println("\n" + strings.Repeat("-", 40))
	fmt.Println("ВСЕ ТЕСТЫ ЗАВЕРШЕНЫ")
}

// testKeyGeneration тестирует генерацию ключей разных размеров
func testKeyGeneration(t *testing.T) {
	fmt.Println("\nТЕСТ ГЕНЕРАЦИИ КЛЮЧЕЙ RSA")
	fmt.Printf("%-8s %-10s %-12s\n", "Размер", "Статус", "Время")

	sizes := []int{512, 1024, 2048}
	allPassed := true

	for _, size := range sizes {
		start := time.Now()
		
		rsa := cripta.NewRSAService(cripta.RSAMillerRabin, 0.9999, size)
		err := rsa.GenerateNewKey()
		
		duration := time.Since(start)
		status := "OK"
		
		if err != nil {
			status = "FAIL"
			allPassed = false
			t.Errorf("Ошибка генерации %d-битного ключа: %v", size, err)
		}

		fmt.Printf("%-8d %-10s %-12v\n", size, status, duration.Round(time.Millisecond))
	}

	if allPassed {
		fmt.Println("РЕЗУЛЬТАТ: Все ключи сгенерированы успешно")
	}
}

// testEncryptionDecryption тестирует шифрование и дешифрование
func testEncryptionDecryption(t *testing.T) {
	fmt.Println("\nТЕСТ ШИФРОВАНИЯ/ДЕШИФРОВАНИЯ")
	
	rsa := cripta.NewRSAService(cripta.RSAMillerRabin, 0.9999, 1024)
	if err := rsa.GenerateNewKey(); err != nil {
		t.Fatalf("Не удалось сгенерировать ключ: %v", err)
	}

	testMessages := []string{
		"Hello, World!",
		"Тестовое сообщение на русском",
		strings.Repeat("A", 100),
		"1234567890!@#$%^&*()",
	}

	fmt.Printf("%-35s %-8s\n", "Сообщение", "Статус")
	fmt.Println(strings.Repeat("-", 44))

	failed := 0
	total := 0

	for _, msg := range testMessages {
		total++
		ciphertext, err := rsa.EncryptString(msg)
		if err != nil {
			failed++
			t.Errorf("Ошибка шифрования: %v", err)
			continue
		}

		decrypted, err := rsa.DecryptString(ciphertext)
		if err != nil {
			failed++
			t.Errorf("Ошибка дешифрования: %v", err)
			continue
		}

		status := "OK"
		if decrypted != msg {
			status = "FAIL"
			failed++
			t.Errorf("Сообщение не совпадает: '%s' != '%s'", decrypted, msg)
		}

		displayMsg := msg
		if len(displayMsg) > 30 {
			displayMsg = displayMsg[:27] + "..."
		}
		fmt.Printf("%-35s %-8s\n", displayMsg, status)
	}

	fmt.Printf("РЕЗУЛЬТАТ: %d/%d тестов пройдено\n", total-failed, total)
}

// testWienerAttack тестирует атаку Винера на уязвимые ключи
func testWienerAttack(t *testing.T) {
	fmt.Println("\nТЕСТ АТАКИ ВИНЕРА НА RSA")
	
	attackService := cripta.NewWienerAttackService()

	// Известные уязвимые ключи для демонстрации
	vulnerableKeys := []struct {
		name string
		n    *big.Int
		e    *big.Int
		d    *big.Int // Ожидаемое значение для проверки
	}{
		{
			name: "Wiener Example 1",
			n:    big.NewInt(11023),   // 73 * 151
			e:    big.NewInt(1543),
			d:    big.NewInt(7),       // d = 7 для этого ключа
		},
		{
			name: "Wiener Example 2",
			n:    big.NewInt(1022117), // 1009 * 1013
			e:    big.NewInt(816077),
			d:    big.NewInt(5),       // d = 5
		},
		{
			name: "Wiener Example 3",
			n:    big.NewInt(784319),  // 823 * 953
			e:    big.NewInt(156509),
			d:    big.NewInt(5),       // d = 5
		},
	}

	fmt.Printf("%-20s %-12s %-15s %-10s\n", "Ключ", "Статус", "Найден d", "Ожидаемый d")
	fmt.Println(strings.Repeat("-", 60))

	successful := 0
	total := len(vulnerableKeys)

	for _, key := range vulnerableKeys {
		publicKey := &cripta.RSAPublicKey{N: key.n, E: key.e}
		result := attackService.Attack(publicKey)

		status := "FAIL"
		foundD := "не найден"
		expectedD := key.d.String()
		
		if result.Success {
			status = "SUCCESS"
			foundD = result.FoundD.String()
			
			// Проверяем, что найденный d действительно работает
			if testDCorrectness(key.e, result.FoundD, key.n) {
				successful++
			} else {
				status = "INVALID"
				t.Errorf("Найден некорректный d для ключа %s", key.name)
			}
		} else {
			t.Logf("Атака не удалась для ключа %s", key.name)
		}

		fmt.Printf("%-20s %-12s %-15s %-10s\n", key.name, status, foundD, expectedD)
	}

	fmt.Printf("РЕЗУЛЬТАТ: %d/%d ключей взломано успешно\n", successful, total)
}


// testDCorrectness проверяет корректность закрытой экспоненты
func testDCorrectness(e, d, n *big.Int) bool {
	if d == nil {
		return false
	}
	
	// Тестируем на нескольких случайных значениях
	testVals := []int64{2, 3, 5, 7, 11}
	for _, val := range testVals {
		m := big.NewInt(val)
		c := new(big.Int).Exp(m, e, n)
		decrypted := new(big.Int).Exp(c, d, n)
		
		if decrypted.Cmp(m) != 0 {
			return false
		}
	}
	return true
}

// testPerformance тестирует производительность
func testPerformance(t *testing.T) {
	fmt.Println("\nТЕСТ ПРОИЗВОДИТЕЛЬНОСТИ RSA")
	
	rsa := cripta.NewRSAService(cripta.RSAMillerRabin, 0.9999, 1024)
	
	fmt.Printf("%-20s %-15s\n", "Операция", "Время")
	fmt.Println(strings.Repeat("-", 36))
	
	// Тест генерации ключа
	start := time.Now()
	err := rsa.GenerateNewKey()
	keyGenTime := time.Since(start)
	
	if err != nil {
		t.Fatalf("Ошибка генерации ключа: %v", err)
	}
	fmt.Printf("%-20s %-15v\n", "Генерация ключа", keyGenTime.Round(time.Millisecond))
	
	// Тест шифрования
	msg := "Тестовое сообщение для проверки производительности RSA"
	start = time.Now()
	ciphertext, err := rsa.EncryptString(msg)
	encryptTime := time.Since(start)
	
	if err != nil {
		t.Fatalf("Ошибка шифрования: %v", err)
	}
	fmt.Printf("%-20s %-15v\n", "Шифрование", encryptTime.Round(time.Microsecond))
	
	// Тест дешифрования
	start = time.Now()
	_, err = rsa.DecryptString(ciphertext)
	decryptTime := time.Since(start)
	
	if err != nil {
		t.Fatalf("Ошибка дешифрования: %v", err)
	}
	fmt.Printf("%-20s %-15v\n", "Дешифрование", decryptTime.Round(time.Microsecond))
}

// TestMathFunctions тестирует математические функции
func TestMathFunctions(t *testing.T) {
	fmt.Println("\nТЕСТ МАТЕМАТИЧЕСКИХ ФУНКЦИЙ")
	
	passed := 0
	total := 0
	
	t.Run("Алгоритм Евклида", func(t *testing.T) {
		total++
		gcd := cripta.GCD(48, 18)
		if gcd != 6 {
			t.Errorf("НОД(48, 18) = %d, ожидалось 6", gcd)
		} else {
			passed++
		}
		
		total++
		g, x, y := cripta.ExtendedGCD(17, 5)
		if g != 1 || 17*x+5*y != 1 {
			t.Errorf("Расширенный НОД(17, 5) некорректен")
		} else {
			passed++
		}
	})
	
	t.Run("Модульная арифметика", func(t *testing.T) {
		total++
		// Тест быстрого возведения в степень
		result := cripta.ModExp(2, 10, 100)
		if result != 24 {
			t.Errorf("2^10 mod 100 = %d, ожидалось 24", result)
		} else {
			passed++
		}
		
		total++
		// Тест обратного элемента
		inv, exists := cripta.ModularInverse(3, 11)
		if !exists || (3*inv)%11 != 1 {
			t.Errorf("Обратный элемент 3 mod 11 некорректен")
		} else {
			passed++
		}
	})
	
	fmt.Printf("РЕЗУЛЬТАТ: %d/%d тестов пройдено\n", passed, total)
}

// BenchmarkRSA бенчмарки производительности
func BenchmarkRSA(b *testing.B) {
	fmt.Println("\nБЕНЧМАРК ПРОИЗВОДИТЕЛЬНОСТИ RSA")
	rsa := cripta.NewRSAService(cripta.RSAMillerRabin, 0.9999, 1024)
	_ = rsa.GenerateNewKey()
	msg := "Тестовое сообщение"
	
	b.Run("Шифрование", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = rsa.EncryptString(msg)
		}
	})
	
	b.Run("Дешифрование", func(b *testing.B) {
		ciphertext, _ := rsa.EncryptString(msg)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = rsa.DecryptString(ciphertext)
		}
	})
	
	fmt.Println("Бенчмарки завершены")
}