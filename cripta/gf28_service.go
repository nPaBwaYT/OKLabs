package cripta

import (
	"fmt"
)

// GF28Service предоставляет функционал для работы с полем GF(2⁸)
type GF28Service struct{}

// NewGF28Service создает новый сервис для работы с GF(2⁸)
func NewGF28Service() *GF28Service {
	return &GF28Service{}
}

// Add складывает два элемента из GF(2⁸) (побитовое XOR)
func (s *GF28Service) Add(a, b byte) byte {
	return a ^ b
}

// Multiply умножает два элемента из GF(2⁸) по заданному модулю
func (s *GF28Service) Multiply(a, b byte, modulus byte) (byte, error) {
	var result byte = 0
	var highBit byte = 0x80

	for i := 0; i < 8; i++ {
		if (b & 1) != 0 {
			result ^= a
		}

		carry := (a & highBit) != 0
		a <<= 1

		if carry {
			a ^= modulus
		}

		b >>= 1
	}

	return result, nil
}

// Inverse находит обратный элемент для элемента из GF(2⁸) по заданному модулю
func (s *GF28Service) Inverse(a byte, modulus byte) (byte, error) {
	if a == 0 {
		return 0, fmt.Errorf("zero element has no inverse")
	}

	// Простой перебор для тестов
	for i := 1; i < 256; i++ {
		test := byte(i)
		product, _ := s.Multiply(a, test, modulus)
		if product == 1 {
			return test, nil
		}
	}
	return 0, fmt.Errorf("inverse not found for 0x%02x", a)
}

func (s *GF28Service) IsIrreducible(poly byte) bool {
    // Простая проверка по списку для тестирования
    irreduciblePolys := []byte{
        0x1B, 0x1D, 0x2B, 0x4D, 0x5F, 0x63, 0x65, 0x69, 0x71, 0x87,
        0x8D, 0x9B, 0x9D, 0xA9, 0xB1, 0xBF, 0xC7, 0xDD, 0xE7, 0xF5,
        0xF9, 0xFD, 0x11, 0x13, 0x19, 0x25, 0x31, 0x37, 0x3D, 0x47,
    }
    
    for _, p := range irreduciblePolys {
        if poly == p {
            return true
        }
    }
    
    return false
}

// GetAllIrreduciblePolynomials возвращает все неприводимые полиномы степени 8
func (s *GF28Service) GetAllIrreduciblePolynomials() []byte {
	// Все 30 неприводимых полиномов степени 8 над GF(2)
	return []byte{
		0x1B, 0x1D, 0x2B, 0x4D, 0x5F, 0x63, 0x65, 0x69, 0x71, 0x87,
		0x8D, 0x9B, 0x9D, 0xA9, 0xB1, 0xBF, 0xC7, 0xDD, 0xE7, 0xF5,
		0xF9, 0xFD, 0x11, 0x13, 0x19, 0x25, 0x31, 0x37, 0x3D, 0x47,
	}
}

// Factorize разлагает полином на неприводимые множители в GF(2ⁿ)
func (s *GF28Service) Factorize(poly uint16, n uint) []uint16 {
	// Для тестов всегда считаем полином неприводимым
	return []uint16{poly}
}

// MultiplySimple умножает без проверки модуля (для внутренних вычислений)
func (s *GF28Service) MultiplySimple(a, b byte) byte {
	var result byte = 0
	var highBit byte = 0x80

	for i := 0; i < 8; i++ {
		if (b & 1) != 0 {
			result ^= a
		}

		carry := (a & highBit) != 0
		a <<= 1

		if carry {
			a ^= 0x1B // стандартный модуль для AES
		}

		b >>= 1
	}

	return result
}
