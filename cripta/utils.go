package cripta

import (
	"crypto/rand"
	"errors"
	"math/big"
)

// BigNumberUtils предоставляет утилиты для работы с большими числами
type BigNumberUtils struct{}

// Вспомогательная функция для сокращения больших чисел
func ShortenBigInt(n *big.Int) string {
	s := n.String()
	if len(s) > 10 {
		return s[:4] + "..." + s[len(s)-4:]
	}
	return s
}

// GenerateRandomBits генерирует случайное число заданной битовой длины
func (bnu *BigNumberUtils) GenerateRandomBits(bits int) (*big.Int, error) {
	if bits <= 0 {
		return nil, errors.New("bit length must be positive")
	}
	
	max := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	
	// Устанавливаем старший бит
	n.Or(n, new(big.Int).Lsh(big.NewInt(1), uint(bits-1)))
	
	return n, nil
}

// IsProbablyPrime вероятностная проверка на простоту
func (bnu *BigNumberUtils) IsProbablyPrime(n *big.Int, k int) bool {
	if n.Cmp(big.NewInt(2)) < 0 {
		return false
	}
	
	// Проверяем делимость на маленькие простые числа
	smallPrimes := []int64{2, 3, 5, 7, 11, 13, 17, 19, 23, 29}
	for _, p := range smallPrimes {
		prime := big.NewInt(p)
		if n.Cmp(prime) == 0 {
			return true
		}
		if new(big.Int).Mod(n, prime).Cmp(big.NewInt(0)) == 0 {
			return false
		}
	}
	
	return n.ProbablyPrime(k)
}

// ModularExponentiation быстрое возведение в степень по модулю
func (bnu *BigNumberUtils) ModularExponentiation(base, exponent, modulus *big.Int) *big.Int {
	return new(big.Int).Exp(base, exponent, modulus)
}

// ChineseRemainderTheorem реализация КТО для RSA
func (bnu *BigNumberUtils) ChineseRemainderTheorem(mp, mq, p, q, pinv, qinv *big.Int) *big.Int {
	// Вычисляем m = mq + q * (qinv * (mp - mq) mod p)
	diff := new(big.Int).Sub(mp, mq)
	diff.Mul(diff, qinv)
	diff.Mod(diff, p)
	diff.Mul(diff, q)
	diff.Add(diff, mq)
	
	return diff.Mod(diff, new(big.Int).Mul(p, q))
}

