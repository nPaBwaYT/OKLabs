package cripta

import (
	"crypto/rand"
	"errors"
	"math/big"
)

// RSATestType перечисление для типа теста простоты
type RSATestType int

const (
	RSAFermat RSATestType = iota
	RSASolovayStrassen
	RSAMillerRabin
)

// RSAKey пара ключей RSA
type RSAKey struct {
	PublicKey  RSAPublicKey
	PrivateKey RSAPrivateKey
}

// RSAPublicKey открытый ключ RSA
type RSAPublicKey struct {
	N *big.Int // модуль
	E *big.Int // открытая экспонента
}

// RSAPrivateKey закрытый ключ RSA
type RSAPrivateKey struct {
	N *big.Int // модуль
	D *big.Int // закрытая экспонента
	P *big.Int // простое число p
	Q *big.Int // простое число q
}

// RSAKeyGenerator генератор ключей RSA
type RSAKeyGenerator struct {
	testType       RSATestType
	minProbability float64
	bitLength      int
}

// NewRSAKeyGenerator создает новый генератор ключей
func NewRSAKeyGenerator(testType RSATestType, minProbability float64, bitLength int) *RSAKeyGenerator {
	if minProbability < 0.5 || minProbability >= 1 {
		minProbability = 0.999
	}
	if bitLength < 512 {
		bitLength = 512
	}
	
	return &RSAKeyGenerator{
		testType:       testType,
		minProbability: minProbability,
		bitLength:      bitLength,
	}
}

// GenerateKeyPair генерирует новую пару ключей RSA
func (gen *RSAKeyGenerator) GenerateKeyPair() (*RSAKey, error) {
	// Выбираем тест простоты
	var primalityTest PrimalityTest
	switch gen.testType {
	case RSAFermat:
		primalityTest = NewFermatTest()
	case RSASolovayStrassen:
		primalityTest = NewSolovayStrassenTest()
	case RSAMillerRabin:
		primalityTest = NewMillerRabinTest()
	default:
		primalityTest = NewMillerRabinTest()
	}
	
	// Генерируем простые числа p и q
	p, err := gen.generatePrime(primalityTest)
	if err != nil {
		return nil, err
	}
	
	q, err := gen.generatePrime(primalityTest)
	if err != nil {
		return nil, err
	}
	
	// Проверяем условия для предотвращения атак
	if err := gen.validatePrimes(p, q); err != nil {
		return nil, err
	}
	
	// Вычисляем модуль n = p * q
	n := new(big.Int).Mul(p, q)
	
	// Вычисляем φ(n) = (p-1)*(q-1)
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	qMinus1 := new(big.Int).Sub(q, big.NewInt(1))
	phi := new(big.Int).Mul(pMinus1, qMinus1)
	
	// Выбираем открытую экспоненту e (обычно 65537)
	e := big.NewInt(65537)
	
	// Проверяем, что e и φ(n) взаимно просты
	gcd := new(big.Int).GCD(nil, nil, e, phi)
	if gcd.Cmp(big.NewInt(1)) != 0 {
		// Если 65537 не подходит, ищем другую
		e = gen.findPublicExponent(phi)
	}
	
	// Вычисляем закрытую экспоненту d = e^(-1) mod φ(n)
	d := new(big.Int).ModInverse(e, phi)
	if d == nil {
		return nil, errors.New("не удалось вычислить обратный элемент для e")
	}
	
	// Проверяем на атаку Винера (d не должно быть слишком маленьким)
	if gen.isVulnerableToWiener(d, n) {
		return nil, errors.New("сгенерированный ключ уязвим к атаке Винера")
	}
	
	return &RSAKey{
		PublicKey: RSAPublicKey{
			N: n,
			E: e,
		},
		PrivateKey: RSAPrivateKey{
			N: n,
			D: d,
			P: p,
			Q: q,
		},
	}, nil
}

// generatePrime генерирует простое число заданной длины
func (gen *RSAKeyGenerator) generatePrime(test PrimalityTest) (*big.Int, error) {
	maxAttempts := 100
	
	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Генерируем случайное число нужной длины
		num, err := rand.Prime(rand.Reader, gen.bitLength/2)
		if err != nil {
			return nil, err
		}
		
		// Проверяем на простоту
		if test.IsPrime(num, gen.minProbability) {
			return num, nil
		}
	}
	
	return nil, errors.New("не удалось сгенерировать простое число")
}

// validatePrimes проверяет p и q на соответствие требованиям безопасности
func (gen *RSAKeyGenerator) validatePrimes(p, q *big.Int) error {
	// Проверяем, что p ≠ q
	if p.Cmp(q) == 0 {
		return errors.New("p и q не должны быть равны")
	}
	
	// Проверяем разницу между p и q
	diff := new(big.Int).Abs(new(big.Int).Sub(p, q))
	minDiffBits := gen.bitLength/2 - 100
	if minDiffBits < 10 {
		minDiffBits = 10
	}
	minDiff := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(minDiffBits)), nil)
	
	if diff.Cmp(minDiff) < 0 {
		return errors.New("p и q слишком близки")
	}
	
	return nil
}

// findPublicExponent ищет подходящую открытую экспоненту
func (gen *RSAKeyGenerator) findPublicExponent(phi *big.Int) *big.Int {
	// Попробуем несколько популярных значений
	candidates := []int64{65537, 17, 5, 3}
	
	for _, candidate := range candidates {
		e := big.NewInt(candidate)
		gcd := new(big.Int).GCD(nil, nil, e, phi)
		if gcd.Cmp(big.NewInt(1)) == 0 {
			return e
		}
	}
	
	// Если популярные не подошли, ищем случайную
	maxAttempts := 100
	for i := 0; i < maxAttempts; i++ {
		e, err := rand.Int(rand.Reader, phi)
		if err != nil {
			continue
		}
		
		if e.Cmp(big.NewInt(1)) <= 0 {
			continue
		}
		
		gcd := new(big.Int).GCD(nil, nil, e, phi)
		if gcd.Cmp(big.NewInt(1)) == 0 {
			return e
		}
	}
	
	return big.NewInt(65537)
}

// isVulnerableToWiener проверяет уязвимость к атаке Винера
func (gen *RSAKeyGenerator) isVulnerableToWiener(d, n *big.Int) bool {
	// Атака Винера работает, если d < n^(1/4)/3
	// Вычисляем n^(1/4)
	nFloat := new(big.Float).SetInt(n)
	
	// Вычисляем n^(1/4)
	var quarterPower big.Float
	quarterPower.Sqrt(nFloat)
	quarterPower.Sqrt(&quarterPower)
	
	// Делим на 3
	var threshold big.Float
	threshold.Quo(&quarterPower, big.NewFloat(3))
	
	// Преобразуем d в float для сравнения
	dFloat := new(big.Float).SetInt(d)
	
	// Сравниваем
	cmpResult := dFloat.Cmp(&threshold)
	return cmpResult <= 0
}

// RSAService сервис для шифрования/дешифрования RSA
type RSAService struct {
	keyGenerator *RSAKeyGenerator
	currentKey   *RSAKey
}

// NewRSAService создает новый сервис RSA
func NewRSAService(testType RSATestType, minProbability float64, bitLength int) *RSAService {
	return &RSAService{
		keyGenerator: NewRSAKeyGenerator(testType, minProbability, bitLength),
	}
}

// GenerateNewKey генерирует новую пару ключей
func (rs *RSAService) GenerateNewKey() error {
	key, err := rs.keyGenerator.GenerateKeyPair()
	if err != nil {
		return err
	}
	
	rs.currentKey = key
	return nil
}

// GetPublicKey возвращает текущий открытый ключ
func (rs *RSAService) GetPublicKey() (*RSAPublicKey, error) {
	if rs.currentKey == nil {
		return nil, errors.New("ключи не сгенерированы")
	}
	
	return &rs.currentKey.PublicKey, nil
}

// Encrypt шифрует сообщение
func (rs *RSAService) Encrypt(message []byte) ([]byte, error) {
	if rs.currentKey == nil {
		return nil, errors.New("ключи не сгенерированы")
	}
	
	n := rs.currentKey.PublicKey.N
	msgInt := new(big.Int).SetBytes(message)
	
	if msgInt.Cmp(n) >= 0 {
		// Если сообщение слишком большое, разбиваем на блоки
		return rs.encryptBlockByBlock(message)
	}
	
	// Шифрование: c = m^e mod n
	cipherInt := new(big.Int).Exp(msgInt, rs.currentKey.PublicKey.E, n)
	
	return cipherInt.Bytes(), nil
}

// EncryptString шифрует строку
func (rs *RSAService) EncryptString(message string) ([]byte, error) {
	return rs.Encrypt([]byte(message))
}

// encryptBlockByBlock шифрует большие сообщения по блокам
func (rs *RSAService) encryptBlockByBlock(message []byte) ([]byte, error) {
	n := rs.currentKey.PublicKey.N
	e := rs.currentKey.PublicKey.E
	
	// Определяем максимальный размер блока
	nBytes := len(n.Bytes())
	maxBlockSize := nBytes - 11 // оставляем место для padding
	
	if maxBlockSize <= 0 {
		return nil, errors.New("ключ слишком мал для шифрования")
	}
	
	var encrypted []byte
	
	// Шифруем по блокам
	for i := 0; i < len(message); i += maxBlockSize {
		end := i + maxBlockSize
		if end > len(message) {
			end = len(message)
		}
		
		block := message[i:end]
		blockInt := new(big.Int).SetBytes(block)
		
		// Шифруем блок
		cipherInt := new(big.Int).Exp(blockInt, e, n)
		
		// Добавляем к результату
		encrypted = append(encrypted, cipherInt.Bytes()...)
	}
	
	return encrypted, nil
}

// Decrypt дешифрует сообщение
func (rs *RSAService) Decrypt(ciphertext []byte) ([]byte, error) {
	if rs.currentKey == nil {
		return nil, errors.New("ключи не сгенерированы")
	}
	
	cipherInt := new(big.Int).SetBytes(ciphertext)
	
	// Проверяем размер
	if cipherInt.Cmp(rs.currentKey.PrivateKey.N) >= 0 {
		// Если шифртекст слишком большой, дешифруем по блокам
		return rs.decryptBlockByBlock(ciphertext)
	}
	
	msgInt := new(big.Int).Exp(cipherInt, rs.currentKey.PrivateKey.D, rs.currentKey.PrivateKey.N)
	
	return msgInt.Bytes(), nil
}

// decryptBlockByBlock дешифрует по блокам
func (rs *RSAService) decryptBlockByBlock(ciphertext []byte) ([]byte, error) {
	n := rs.currentKey.PrivateKey.N
	d := rs.currentKey.PrivateKey.D
	
	nBytes := len(n.Bytes())
	
	var decrypted []byte
	
	// Дешифруем по блокам
	for i := 0; i < len(ciphertext); i += nBytes {
		end := i + nBytes
		if end > len(ciphertext) {
			end = len(ciphertext)
		}
		
		block := ciphertext[i:end]
		blockInt := new(big.Int).SetBytes(block)
		
		// Дешифруем блок
		msgInt := new(big.Int).Exp(blockInt, d, n)
		
		// Добавляем к результату
		decrypted = append(decrypted, msgInt.Bytes()...)
	}
	
	return decrypted, nil
}

// DecryptString дешифрует в строку
func (rs *RSAService) DecryptString(ciphertext []byte) (string, error) {
	decrypted, err := rs.Decrypt(ciphertext)
	if err != nil {
		return "", err
	}
	
	return string(decrypted), nil
}