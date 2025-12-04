package cripta

import (
	"fmt"
	"math/big"
)

// ContinuedFraction представляет подходящую дробь
type ContinuedFraction struct {
	A *big.Int // числитель (k)
	B *big.Int // знаменатель (d)
}

// WienerAttackResult результат атаки Винера
type WienerAttackResult struct {
	FoundD          *big.Int            // найденная закрытая экспонента
	PhiN            *big.Int            // значение φ(n)
	Convergents     []ContinuedFraction // подходящие дроби
	Success         bool                // успешность атаки
	Iterations      int                 // количество итераций
	Message         string              // сообщение об ошибке/результате
}

// WienerAttackService сервис для выполнения атаки Винера
type WienerAttackService struct{}

// NewWienerAttackService создает новый сервис для атаки Винера
func NewWienerAttackService() *WienerAttackService {
	return &WienerAttackService{}
}

// Attack выполняет атаку Винера
func (was *WienerAttackService) Attack(publicKey *RSAPublicKey) *WienerAttackResult {
	result := &WienerAttackResult{
		Convergents: make([]ContinuedFraction, 0),
		Success:     false,
		Iterations:  0,
		Message:     "Атака начата",
	}
	
	n := publicKey.N
	e := publicKey.E
	
	fmt.Printf("[DEBUG] Атака Винера для N=%s, e=%s\n", 
		shortenDebug(n), e.String())
	
	// Вычисляем непрерывную дробь для e/n
	convergents := was.computeConvergents(e, n)
	result.Convergents = convergents
	
	fmt.Printf("[DEBUG] Вычислено %d подходящих дробей\n", len(convergents))
	
	// Проверяем каждую подходящую дробь
	for i, conv := range convergents {
		result.Iterations++
		
		k := conv.A
		d := conv.B
		
		// Пропускаем если k или d равны 0
		if k.Cmp(big.NewInt(0)) == 0 || d.Cmp(big.NewInt(0)) == 0 {
			continue
		}
		
		// Проверяем условие Винера: d < n^(1/4)/3
		if !was.checkWienerCondition(d, n) {
			continue
		}
		
		// Вычисляем φ(n) = (e*d - 1) / k
		ed := new(big.Int).Mul(e, d)
		edMinus1 := new(big.Int).Sub(ed, big.NewInt(1))
		
		// Проверяем делимость
		if new(big.Int).Mod(edMinus1, k).Cmp(big.NewInt(0)) != 0 {
			continue
		}
		
		phiCandidate := new(big.Int)
		phiCandidate.Div(edMinus1, k)
		
		// Проверяем φ(n)
		if was.validatePhi(phiCandidate, n) {
			result.PhiN = phiCandidate
			result.FoundD = d
			
			// Проверяем, что d действительно работает
			if was.verifyKey(e, d, n, phiCandidate) {
				result.Success = true
				result.Message = fmt.Sprintf("Атака успешна на итерации %d: d = %s", i+1, d.String())
				fmt.Printf("[DEBUG] Успех! Найден d=%s, k=%s\n", d.String(), k.String())
				return result
			}
		}
	}
	
	result.Message = fmt.Sprintf("Атака не удалась. Проверено %d подходящих дробей", result.Iterations)
	return result
}


// computeConvergents вычисляет подходящие дроби для e/n
func (was *WienerAttackService) computeConvergents(e, n *big.Int) []ContinuedFraction {
	convergents := make([]ContinuedFraction, 0)
	
	// Вычисляем непрерывную дробь для e/n
	cf := was.computeCF(e, n)
	
	// Вычисляем подходящие дроби
	hPrev2 := big.NewInt(0)
	kPrev2 := big.NewInt(1)
	hPrev1 := big.NewInt(1)
	kPrev1 := big.NewInt(0)
	
	for i, a := range cf {
		// Вычисляем текущую подходящую дробь
		h := new(big.Int).Mul(a, hPrev1)
		h.Add(h, hPrev2)
		
		k := new(big.Int).Mul(a, kPrev1)
		k.Add(k, kPrev2)
		
		convergents = append(convergents, ContinuedFraction{
			A: new(big.Int).Set(h),
			B: new(big.Int).Set(k),
		})
		
		// Обновляем значения
		hPrev2, hPrev1 = hPrev1, h
		kPrev2, kPrev1 = kPrev1, k
		
		// Ограничиваем количество итераций
		if i > 100 {
			break
		}
	}
	
	return convergents
}

// computeCF вычисляет коэффициенты непрерывной дроби для a/b
func (was *WienerAttackService) computeCF(a, b *big.Int) []*big.Int {
	coefficients := make([]*big.Int, 0)
	
	x := new(big.Int).Set(a)
	y := new(big.Int).Set(b)
	
	for y.Cmp(big.NewInt(0)) != 0 {
		q := new(big.Int)
		r := new(big.Int)
		q.DivMod(x, y, r)
		
		coefficients = append(coefficients, new(big.Int).Set(q))
		
		x, y = y, r
	}
	
	return coefficients
}

// checkWienerCondition проверяет условие Винера
func (was *WienerAttackService) checkWienerCondition(d, n *big.Int) bool {
	// d < (1/3) * n^(1/4)
	nSqrt := was.sqrt(n)
	nFourth := was.sqrt(nSqrt)
	
	// Вычисляем 3*d
	//dTimes3 := new(big.Int).Mul(d, big.NewInt(3))
	
	return d.Cmp(nFourth) < 0 // ослабленное условие
}

// validatePhi проверяет кандидата на φ(n)
func (was *WienerAttackService) validatePhi(phi, n *big.Int) bool {
	if phi.Cmp(big.NewInt(0)) <= 0 {
		return false
	}
	
	if phi.Cmp(n) >= 0 {
		return false
	}
	
	// Вычисляем s = n - φ + 1 (сумма p+q)
	s := new(big.Int)
	s.Sub(n, phi)
	s.Add(s, big.NewInt(1))
	
	// s должно быть положительным и четным
	if s.Cmp(big.NewInt(0)) <= 0 {
		return false
	}
	
	// Проверяем дискриминант: s^2 - 4n
	discriminant := new(big.Int)
	sSquared := new(big.Int).Mul(s, s)
	nTimes4 := new(big.Int).Lsh(n, 2)
	discriminant.Sub(sSquared, nTimes4)
	
	if discriminant.Cmp(big.NewInt(0)) <= 0 {
		return false
	}
	
	// Проверяем, что дискриминант - полный квадрат
	return was.isPerfectSquare(discriminant)
}

// verifyKey проверяет, что d действительно является закрытым ключом
func (was *WienerAttackService) verifyKey(e, d, n, phi *big.Int) bool {
	// 1. Проверяем e*d ≡ 1 mod φ(n)
	ed := new(big.Int).Mul(e, d)
	edModPhi := new(big.Int).Mod(ed, phi)
	if edModPhi.Cmp(big.NewInt(1)) != 0 {
		return false
	}
	
	// 2. Проверяем шифрование/дешифрование
	testValues := []int64{2, 3, 5}
	for _, val := range testValues {
		m := big.NewInt(val)
		c := new(big.Int).Exp(m, e, n)
		m2 := new(big.Int).Exp(c, d, n)
		if m2.Cmp(m) != 0 {
			return false
		}
	}
	
	return true
}

// sqrt вычисляет квадратный корень
func (was *WienerAttackService) sqrt(n *big.Int) *big.Int {
	if n.Cmp(big.NewInt(0)) == 0 {
		return big.NewInt(0)
	}
	
	// Метод Ньютона
	x := new(big.Int).Set(n)
	y := new(big.Int)
	y.Add(x, big.NewInt(1))
	y.Rsh(y, 1)
	
	for y.Cmp(x) < 0 {
		x.Set(y)
		temp := new(big.Int).Div(n, x)
		y.Add(x, temp)
		y.Rsh(y, 1)
	}
	
	return x
}

// isPerfectSquare проверяет, является ли число полным квадратом
func (was *WienerAttackService) isPerfectSquare(n *big.Int) bool {
	if n.Cmp(big.NewInt(0)) < 0 {
		return false
	}
	
	sqrt := was.sqrt(n)
	square := new(big.Int).Mul(sqrt, sqrt)
	return square.Cmp(n) == 0
}

// shortenDebug вспомогательная функция для отладки
func shortenDebug(n *big.Int) string {
	s := n.String()
	if len(s) > 10 {
		return s[:4] + "..." + s[len(s)-4:]
	}
	return s
}