package cripta

import (
	"math/big"
)

// LegendreSymbol вычисляет символ Лежандра (a/p)
func LegendreSymbol(a, p int64) int64 {
	if p <= 0 || p%2 == 0 {
		return 0 // p должно быть простым нечетным числом
	}
	
	if a%p == 0 {
		return 0
	}
	
	// Используем критерий Эйлера
	result := ModExp(a, (p-1)/2, p)
	if result == p-1 {
		return -1
	}
	return result
}

// BigJacobiSymbol - оптимизированная версия для больших чисел
func BigJacobiSymbol(a, n *big.Int) *big.Int {
	if n.Sign() <= 0 || n.Bit(0) == 0 { // n четное
		return big.NewInt(0)
	}
	
	a = new(big.Int).Set(a)
	a.Mod(a, n)
	
	if a.Cmp(big.NewInt(0)) == 0 {
		return big.NewInt(0)
	}
	
	result := big.NewInt(1)
	
	// Обрабатываем отрицательный a
	if a.Sign() < 0 {
		a.Neg(a)
		if new(big.Int).And(n, big.NewInt(3)).Cmp(big.NewInt(3)) == 0 {
			result.Neg(result)
		}
	}
	
	for a.Sign() > 0 {
		// Извлекаем степени двойки
		trailingZeros := 0
		temp := new(big.Int).Set(a)
		for temp.Bit(0) == 0 { // пока четное
			temp.Rsh(temp, 1)
			trailingZeros++
		}
		
		if trailingZeros%2 == 1 {
			nMod8 := new(big.Int).And(n, big.NewInt(7))
			if nMod8.Cmp(big.NewInt(3)) == 0 || nMod8.Cmp(big.NewInt(5)) == 0 {
				result.Neg(result)
			}
		}
		
		// Квадратичный закон взаимности
		aMod4 := new(big.Int).And(a, big.NewInt(3))
		nMod4 := new(big.Int).And(n, big.NewInt(3))
		
		if aMod4.Cmp(big.NewInt(3)) == 0 && nMod4.Cmp(big.NewInt(3)) == 0 {
			result.Neg(result)
		}
		
		// Меняем местами
		a, n = new(big.Int).Mod(n, a), a
	}
	
	if n.Cmp(big.NewInt(1)) == 0 {
		return result
	}
	
	return big.NewInt(0)
}

// JacobiSymbol вычисляет символ Якоби (a/n)
func JacobiSymbol(a, n int64) int64 {
	if n <= 0 || n%2 == 0 {
		return 0 // n должно быть положительным нечетным
	}
	
	// Приводим a по модулю n
	a = a % n
	if a < 0 {
		a += n
	}
	
	if a == 0 {
		return 0
	}
	if a == 1 {
		return 1
	}
	
	// Разложение на множители 2
	s := int64(1)
	for a%2 == 0 {
		a /= 2
		nMod8 := n % 8
		if nMod8 == 3 || nMod8 == 5 {
			s = -s
		}
	}
	
	if a == 1 {
		return s
	}
	
	// Квадратичный закон взаимности
	if a%4 == 3 && n%4 == 3 {
		s = -s
	}
	
	return s * JacobiSymbol(n%a, a)
}

// GCD вычисляет НОД двух чисел (алгоритм Евклида)
func GCD(a, b int64) int64 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// ExtendedGCD вычисляет НОД и коэффициенты Безу
func ExtendedGCD(a, b int64) (int64, int64, int64) {
	if b == 0 {
		return a, 1, 0
	}
	
	g, x1, y1 := ExtendedGCD(b, a%b)
	x := y1
	y := x1 - (a/b)*y1
	
	return g, x, y
}

// ModExp вычисляет a^b mod m (быстрое возведение в степень)
func ModExp(a, b, m int64) int64 {
	if m == 1 {
		return 0
	}
	
	result := int64(1)
	a = a % m
	
	for b > 0 {
		if b&1 == 1 {
			result = (result * a) % m
		}
		a = (a * a) % m
		b >>= 1
	}
	
	return result
}

// ModularInverse вычисляет обратный элемент по модулю
func ModularInverse(a, m int64) (int64, bool) {
	g, x, _ := ExtendedGCD(a, m)
	if g != 1 {
		return 0, false // обратного не существует
	}
	
	// Приводим x к положительному значению
	result := x % m
	if result < 0 {
		result += m
	}
	
	return result, true
}

// BigModExp вычисляет a^b mod m для big.Int
func BigModExp(a, b, m *big.Int) *big.Int {
	result := new(big.Int).Exp(a, b, m)
	return result
}

// BigGCD вычисляет НОД для big.Int
func BigGCD(a, b *big.Int) *big.Int {
	result := new(big.Int).GCD(nil, nil, a, b)
	return result
}

// BigExtendedGCD вычисляет НОД и коэффициенты Безу для big.Int
func BigExtendedGCD(a, b *big.Int) (*big.Int, *big.Int, *big.Int) {
	x := new(big.Int)
	y := new(big.Int)
	g := new(big.Int).GCD(x, y, a, b)
	return g, x, y
}

// BigModularInverse вычисляет обратный элемент по модулю для big.Int
func BigModularInverse(a, m *big.Int) (*big.Int, bool) {
	result := new(big.Int).ModInverse(a, m)
	if result == nil {
		return nil, false
	}
	return result, true
}