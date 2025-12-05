package cripta

import (
	"math/big"
	"math/rand"
	"time"
)

// PrimalityTestType перечисление типов тестов простоты
type PrimalityTestType int

const (
	FermatTest PrimalityTestType = iota
	SolovayStrassenTest
	MillerRabinTest
)

// PrimalityTest интерфейс для вероятностных тестов простоты
type PrimalityTest interface {
	IsPrime(n *big.Int, probability float64) bool
	TestName() string
}

// BasePrimalityTest базовый класс для тестов простоты
type BasePrimalityTest struct {
	testIteration func(n, a, nMinusOne *big.Int) bool
	name          string
}

// IsPrime реализация шаблонного метода
func (bpt *BasePrimalityTest) IsPrime(n *big.Int, probability float64) bool {
	// Проверяем тривиальные случаи
	if n.Sign() <= 0 {
		return false
	}
	if n.Cmp(big.NewInt(2)) == 0 || n.Cmp(big.NewInt(3)) == 0 {
		return true
	}
	if new(big.Int).Mod(n, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
		return false
	}
	
	// Для маленьких чисел используем детерминированную проверку
	if n.Cmp(big.NewInt(100)) < 0 {
		return isSmallPrime(n)
	}
	
	// Вычисляем количество итераций
	iterations := calculateIterationsCount(probability)
	if iterations < 5 {
		iterations = 5
	}
	
	// Готовим n-1
	nMinusOne := new(big.Int).Sub(n, big.NewInt(1))
	nMinusTwo := new(big.Int).Sub(n, big.NewInt(2))
	
	// Инициализируем источник случайных чисел
	src := rand.New(rand.NewSource(time.Now().UnixNano()))
	
	for i := 0; i < iterations; i++ {
		// Генерируем случайное a в [2, n-2]
		a := new(big.Int).Rand(src, nMinusTwo)
		a.Add(a, big.NewInt(2))
		
		if !bpt.testIteration(n, a, nMinusOne) {
			return false
		}
	}
	
	return true
}

// Детерминированная проверка для маленьких чисел
func isSmallPrime(n *big.Int) bool {
	// Проверяем числа до 100
	smallPrimes := []int64{2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97}

	if n.Cmp(big.NewInt(1)) == 0 {
		return false
	} 
	
	// Проверяем делимость на маленькие простые числа
	for _, p := range smallPrimes {
		prime := big.NewInt(p)
		if n.Cmp(prime) == 0 {
			return true
		}
		if new(big.Int).Mod(n, prime).Cmp(big.NewInt(0)) == 0 {
			return false
		}
	}
	
	// Для чисел меньше 10000 проверяем все делители до sqrt(n)
	max := sqrt(n)
	for i := int64(101); i <= max.Int64(); i += 2 {
		if new(big.Int).Mod(n, big.NewInt(i)).Cmp(big.NewInt(0)) == 0 {
			return false
		}
	}
	
	return true
}

// Вычисление квадратного корня
func sqrt(n *big.Int) *big.Int {
	if n.Sign() < 0 {
		return big.NewInt(0)
	}
	
	if n.Cmp(big.NewInt(0)) == 0 {
		return big.NewInt(0)
	}
	
	// Метод Ньютона
	x := new(big.Int).Set(n)
	y := new(big.Int).Add(x, big.NewInt(1))
	y.Div(y, big.NewInt(2))
	
	for y.Cmp(x) < 0 {
		x.Set(y)
		y.Add(x, new(big.Int).Div(n, x))
		y.Div(y, big.NewInt(2))
	}
	
	return x
}

// Вычисление количества итераций
func calculateIterationsCount(probability float64) int {
	if probability >= 0.999999 {
		return 50
	}
	if probability >= 0.99999 {
		return 40
	}
	if probability >= 0.9999 {
		return 30
	}
	if probability >= 0.999 {
		return 20
	}
	if probability >= 0.99 {
		return 10
	}
	if probability >= 0.9 {
		return 5
	}
	return 3
}

// TestName возвращает название теста
func (bpt *BasePrimalityTest) TestName() string {
	return bpt.name
}

// FermatTestImpl реализация теста Ферма
type FermatTestImpl struct {
	BasePrimalityTest
}

// NewFermatTest создает новый тест Ферма
func NewFermatTest() *FermatTestImpl {
	ft := &FermatTestImpl{}
	ft.name = "Fermat Primality Test"
	ft.testIteration = func(n, a, nMinusOne *big.Int) bool {
		// Проверяем a^(n-1) ≡ 1 mod n
		result := BigModExp(a, nMinusOne, n)
		return result.Cmp(big.NewInt(1)) == 0
	}
	return ft
}

// SolovayStrassenTestImpl реализация теста Соловея-Штрассена
type SolovayStrassenTestImpl struct {
	BasePrimalityTest
}

// NewSolovayStrassenTest создает новый тест Соловея-Штрассена
func NewSolovayStrassenTest() *SolovayStrassenTestImpl {
	sst := &SolovayStrassenTestImpl{}
	sst.name = "Solovay-Strassen Primality Test"
	sst.testIteration = func(n, a, nMinusOne *big.Int) bool {
		// Проверяем НОД(a, n) = 1
		if gcd := BigGCD(a, n); gcd.Cmp(big.NewInt(1)) != 0 {
			return false
		}
		
		// Вычисляем символ Якоби
		jacobi := BigJacobiSymbol(a, n)
		if jacobi.Sign() == 0 {
			return false
		}
		
		// Вычисляем a^((n-1)/2) mod n
		exp := new(big.Int).Rsh(nMinusOne, 1)
		modExp := BigModExp(a, exp, n)
		
		// Приводим символ Якоби к значению по модулю n
		jacobiModN := new(big.Int).Mod(jacobi, n)
		
		return modExp.Cmp(jacobiModN) == 0
	}
	return sst
}

// MillerRabinTestImpl реализация теста Миллера-Рабина
type MillerRabinTestImpl struct {
	BasePrimalityTest
}

// NewMillerRabinTest создает новый тест Миллера-Рабина
func NewMillerRabinTest() *MillerRabinTestImpl {
	mrt := &MillerRabinTestImpl{}
	mrt.name = "Miller-Rabin Primality Test"
	mrt.testIteration = func(n, a, nMinusOne *big.Int) bool {
		// Представляем n-1 = d * 2^s
		d := new(big.Int).Set(nMinusOne)
		s := 0
		for new(big.Int).Mod(d, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
			d.Rsh(d, 1)
			s++
		}
		
		// Вычисляем x = a^d mod n
		x := BigModExp(a, d, n)
		
		if x.Cmp(big.NewInt(1)) == 0 || x.Cmp(nMinusOne) == 0 {
			return true
		}
		
		// Проводим s-1 итераций
		for i := 0; i < s-1; i++ {
			x.Mul(x, x)
			x.Mod(x, n)
			if x.Cmp(nMinusOne) == 0 {
				return true
			}
			if x.Cmp(big.NewInt(1)) == 0 {
				return false
			}
		}
		
		return false
	}
	return mrt
}


// CreatePrimalityTest фабричный метод для создания тестов
func CreatePrimalityTest(testType PrimalityTestType) PrimalityTest {
	switch testType {
	case FermatTest:
		return NewFermatTest()
	case SolovayStrassenTest:
		return NewSolovayStrassenTest()
	case MillerRabinTest:
		return NewMillerRabinTest()
	default:
		return NewMillerRabinTest()
	}
}