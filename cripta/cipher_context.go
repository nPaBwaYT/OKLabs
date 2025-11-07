package cripta

import (
	"crypto/rand"
	"fmt"
	"os"
	"runtime"
	"sync"
)

type CipherMode int

const (
	CipherModeECB CipherMode = iota
	CipherModeCBC
	CipherModePCBC
	CipherModeCFB
	CipherModeOFB
	CipherModeCTR
	CipherModeRandomDelta
)

type PaddingMode int

const (
	PaddingModeZeros PaddingMode = iota
	PaddingModeANSIX923
	PaddingModePKCS7
	PaddingModeISO10126
)

type CipherContext struct {
	cipher      ISymmetricCipher
	key         []uint8
	mode        CipherMode
	paddingMode PaddingMode
	iv          []uint8
	blockSize   int
	parallel    bool
}

func NewCipherContext(
	cipher ISymmetricCipher,
	key []uint8,
	mode CipherMode,
	paddingMode PaddingMode,
	iv []uint8,
	blockSize int,
	parallel bool,
) (*CipherContext, error) {

	if cipher == nil {
		return nil, fmt.Errorf("cipher implementation cannot be nil")
	}

	ctx := &CipherContext{
		cipher:      cipher,
		key:         make([]uint8, len(key)),
		mode:        mode,
		paddingMode: paddingMode,
		blockSize:   blockSize,
		parallel:    parallel,
	}

	copy(ctx.key, key)

	err := ctx.SetKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to set key: %w", err)
	}

	if len(iv) == 0 && mode != CipherModeECB {
		ctx.iv = make([]uint8, blockSize)
	} else {
		ctx.iv = make([]uint8, len(iv))
		copy(ctx.iv, iv)
	}

	return ctx, nil
}

func (ctx *CipherContext) xorBlocks(dest []uint8, src []uint8) []uint8 {
	minSize := len(dest)
	if len(src) < minSize {
		minSize = len(src)
	}

	result := make([]uint8, minSize)
	for i := 0; i < minSize; i++ {
		result[i] = dest[i] ^ src[i]
	}
	return result
}

func (ctx *CipherContext) incrementCounter(counter []uint8) {
	for i := len(counter) - 1; i >= 0; i-- {
		counter[i]++
		if counter[i] != 0 {
			break
		}
	}
}

func (ctx *CipherContext) applyPadding(data []uint8) ([]uint8, error) {
	if data == nil {
		return nil, fmt.Errorf("data cannot be nil")
	}

	dataLength := len(data)
	paddingLength := ctx.blockSize - (dataLength % ctx.blockSize)
	if paddingLength == 0 {
		paddingLength = ctx.blockSize
	}

	padded := make([]uint8, dataLength+paddingLength)
	copy(padded, data)

	switch ctx.paddingMode {
	case PaddingModeZeros:
		// Уже скопировали данные, остальная часть автоматически нули

	case PaddingModePKCS7:
		for i := dataLength; i < len(padded); i++ {
			padded[i] = uint8(paddingLength)
		}

	case PaddingModeANSIX923:
		for i := dataLength; i < len(padded)-1; i++ {
			padded[i] = 0
		}
		padded[len(padded)-1] = uint8(paddingLength)

	case PaddingModeISO10126:
		if paddingLength > 1 {
			randomBytes := make([]uint8, paddingLength-1)
			_, err := rand.Read(randomBytes)
			if err != nil {
				return nil, fmt.Errorf("failed to generate random bytes: %w", err)
			}
			copy(padded[dataLength:dataLength+paddingLength-1], randomBytes)
		}
		padded[len(padded)-1] = uint8(paddingLength)

	default:
		return nil, fmt.Errorf("unsupported padding mode")
	}

	return padded, nil
}

func (ctx *CipherContext) removePadding(data []uint8) ([]uint8, error) {
	if len(data) == 0 {
		return data, nil
	}

	paddingLength := int(data[len(data)-1])

	if paddingLength <= 0 || paddingLength > ctx.blockSize || paddingLength > len(data) {
		return data, nil
	}

	switch ctx.paddingMode {
	case PaddingModePKCS7:
		for i := len(data) - paddingLength; i < len(data); i++ {
			if data[i] != uint8(paddingLength) {
				return data, nil
			}
		}
		return data[:len(data)-paddingLength], nil

	case PaddingModeANSIX923:
		for i := len(data) - paddingLength; i < len(data)-1; i++ {
			if data[i] != 0 {
				return data, nil
			}
		}
		return data[:len(data)-paddingLength], nil

	case PaddingModeISO10126:
		return data[:len(data)-paddingLength], nil

	case PaddingModeZeros:
		for i := len(data) - 1; i >= 0; i-- {
			if data[i] != 0 {
				return data[:i+1], nil
			}
		}
		return []uint8{}, nil

	default:
		return data, nil
	}
}

func (ctx *CipherContext) encryptECBParallel(padded []uint8) ([]uint8, error) {
	numBlocks := len(padded) / ctx.blockSize
	ciphertext := make([]uint8, len(padded))

	numThreads := runtime.NumCPU()
	if numThreads == 0 {
		numThreads = 4
	}

	var wg sync.WaitGroup
	errors := make(chan error, numThreads)

	blocksPerThread := (numBlocks + numThreads - 1) / numThreads

	for t := 0; t < numThreads; t++ {
		startBlock := t * blocksPerThread
		endBlock := startBlock + blocksPerThread
		if endBlock > numBlocks {
			endBlock = numBlocks
		}

		if startBlock >= numBlocks {
			break
		}

		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()

			for i := start; i < end; i++ {
				block := padded[i*ctx.blockSize : (i+1)*ctx.blockSize]

				encryptedBlock, err := ctx.cipher.EncryptBlock(block)
				if err != nil {
					errors <- fmt.Errorf("encryption failed for block %d: %w", i, err)
					return
				}

				copy(ciphertext[i*ctx.blockSize:], encryptedBlock)
			}
		}(startBlock, endBlock)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		return nil, err
	}

	return ciphertext, nil
}

func (ctx *CipherContext) decryptECBParallel(ciphertext []uint8) ([]uint8, error) {
	numBlocks := len(ciphertext) / ctx.blockSize
	plaintext := make([]uint8, len(ciphertext))

	numThreads := runtime.NumCPU()
	if numThreads == 0 {
		numThreads = 4
	}

	var wg sync.WaitGroup
	errors := make(chan error, numThreads)

	blocksPerThread := (numBlocks + numThreads - 1) / numThreads

	for t := 0; t < numThreads; t++ {
		startBlock := t * blocksPerThread
		endBlock := startBlock + blocksPerThread
		if endBlock > numBlocks {
			endBlock = numBlocks
		}

		if startBlock >= numBlocks {
			break
		}

		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()

			for i := start; i < end; i++ {
				block := ciphertext[i*ctx.blockSize : (i+1)*ctx.blockSize]

				decryptedBlock, err := ctx.cipher.DecryptBlock(block)
				if err != nil {
					errors <- fmt.Errorf("decryption failed for block %d: %w", i, err)
					return
				}

				copy(plaintext[i*ctx.blockSize:], decryptedBlock)
			}
		}(startBlock, endBlock)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		return nil, err
	}

	return plaintext, nil
}

func (ctx *CipherContext) encryptCTRParallel(padded []uint8) ([]uint8, error) {
	numBlocks := len(padded) / ctx.blockSize
	ciphertext := make([]uint8, len(padded))

	numThreads := runtime.NumCPU()
	if numThreads == 0 {
		numThreads = 4
	}
	if numThreads > numBlocks {
		numThreads = numBlocks
	}

	var wg sync.WaitGroup
	errors := make(chan error, numThreads)
	mutex := &sync.Mutex{}

	blocksPerThread := (numBlocks + numThreads - 1) / numThreads

	for t := 0; t < numThreads; t++ {
		startBlock := t * blocksPerThread
		endBlock := startBlock + blocksPerThread
		if endBlock > numBlocks {
			endBlock = numBlocks
		}

		if startBlock >= numBlocks {
			break
		}

		wg.Add(1)
		go func(start, end int, threadID int) {
			defer wg.Done()

			localCounter := make([]uint8, len(ctx.iv))
			mutex.Lock()
			copy(localCounter, ctx.iv)
			for i := 0; i < start; i++ {
				ctx.incrementCounter(localCounter)
			}
			mutex.Unlock()

			for i := start; i < end; i++ {
				block := padded[i*ctx.blockSize : (i+1)*ctx.blockSize]

				encryptedCounter, err := ctx.cipher.EncryptBlock(localCounter)
				if err != nil {
					errors <- fmt.Errorf("counter encryption failed for block %d: %w", i, err)
					return
				}

				xored := ctx.xorBlocks(encryptedCounter, block)
				copy(ciphertext[i*ctx.blockSize:], xored)

				ctx.incrementCounter(localCounter)
			}
		}(startBlock, endBlock, t)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		return nil, err
	}

	return ciphertext, nil
}

func (ctx *CipherContext) decryptCTRParallel(ciphertext []uint8) ([]uint8, error) {
	return ctx.encryptCTRParallel(ciphertext)
}

func (ctx *CipherContext) Encrypt(plaintext []uint8, parallel bool) ([]uint8, error) {
	if plaintext == nil {
		return nil, fmt.Errorf("plaintext cannot be nil")
	}

	padded, err := ctx.applyPadding(plaintext)
	if err != nil {
		return nil, fmt.Errorf("padding failed: %w", err)
	}

	if ctx.mode == CipherModeECB && parallel {
		return ctx.encryptECBParallel(padded)
	} else if ctx.mode == CipherModeCTR && parallel {
		return ctx.encryptCTRParallel(padded)
	}

	ciphertext := make([]uint8, 0, len(padded))

	currentBlock := make([]uint8, ctx.blockSize)
	copy(currentBlock, ctx.iv)

	for i := 0; i < len(padded); i += ctx.blockSize {
		end := i + ctx.blockSize
		if end > len(padded) {
			end = len(padded)
		}

		block := make([]uint8, ctx.blockSize)
		copy(block, padded[i:end])

		if len(block) < ctx.blockSize {
			block = append(block, make([]uint8, ctx.blockSize-len(block))...)
		}

		var encryptedBlock []uint8

		switch ctx.mode {
		case CipherModeECB:
			encryptedBlock, err = ctx.cipher.EncryptBlock(block)
			if err != nil {
				return nil, fmt.Errorf("ECB encryption failed: %w", err)
			}

		case CipherModeCBC:
			xored := ctx.xorBlocks(block, currentBlock)
			encryptedBlock, err = ctx.cipher.EncryptBlock(xored)
			if err != nil {
				return nil, fmt.Errorf("CBC encryption failed: %w", err)
			}
			currentBlock = encryptedBlock

		case CipherModePCBC:
			xored := ctx.xorBlocks(block, currentBlock)
			encryptedBlock, err = ctx.cipher.EncryptBlock(xored)
			if err != nil {
				return nil, fmt.Errorf("PCBC encryption failed: %w", err)
			}
			temp := make([]uint8, len(block))
			copy(temp, block)
			currentBlock = ctx.xorBlocks(temp, encryptedBlock)

		case CipherModeCFB:
			encryptedBlock, err = ctx.cipher.EncryptBlock(currentBlock)
			if err != nil {
				return nil, fmt.Errorf("CFB encryption failed: %w", err)
			}
			encryptedBlock = ctx.xorBlocks(encryptedBlock, block)
			currentBlock = encryptedBlock

		case CipherModeOFB:
			currentBlock, err = ctx.cipher.EncryptBlock(currentBlock)
			if err != nil {
				return nil, fmt.Errorf("OFB encryption failed: %w", err)
			}
			encryptedBlock = ctx.xorBlocks(currentBlock, block)

		case CipherModeCTR:
			encryptedCounter, err := ctx.cipher.EncryptBlock(currentBlock)
			if err != nil {
				return nil, fmt.Errorf("CTR encryption failed: %w", err)
			}
			encryptedBlock = ctx.xorBlocks(encryptedCounter, block)
			ctx.incrementCounter(currentBlock)

		case CipherModeRandomDelta:
			delta := make([]uint8, ctx.blockSize)
			_, err := rand.Read(delta)
			if err != nil {
				return nil, fmt.Errorf("failed to generate random delta: %w", err)
			}
			xored := ctx.xorBlocks(block, delta)
			encryptedBlock, err = ctx.cipher.EncryptBlock(xored)
			if err != nil {
				return nil, fmt.Errorf("random delta encryption failed: %w", err)
			}
			ciphertext = append(ciphertext, delta...)

		default:
			return nil, fmt.Errorf("unsupported cipher mode")
		}

		ciphertext = append(ciphertext, encryptedBlock...)
	}

	return ciphertext, nil
}

func (ctx *CipherContext) Decrypt(ciphertext []uint8, parallel bool) ([]uint8, error) {
	if ciphertext == nil {
		return nil, fmt.Errorf("ciphertext cannot be nil")
	}

	if ctx.mode == CipherModeECB && parallel {
		plaintext, err := ctx.decryptECBParallel(ciphertext)
		if err != nil {
			return nil, err
		}
		return ctx.removePadding(plaintext)
	} else if ctx.mode == CipherModeCTR && parallel {
		plaintext, err := ctx.encryptCTRParallel(ciphertext)
		if err != nil {
			return nil, err
		}
		return ctx.removePadding(plaintext)
	}

	plaintext := make([]uint8, 0, len(ciphertext))

	currentBlock := make([]uint8, len(ctx.iv))
	copy(currentBlock, ctx.iv)

	step := ctx.blockSize
	if ctx.mode == CipherModeRandomDelta {
		step = ctx.blockSize * 2
	}

	for i := 0; i < len(ciphertext); i += step {
		if i+ctx.blockSize > len(ciphertext) {
			break
		}

		var block []uint8
		var delta []uint8

		if ctx.mode == CipherModeRandomDelta {
			delta = ciphertext[i : i+ctx.blockSize]
			end := i + step
			if end > len(ciphertext) {
				end = len(ciphertext)
			}
			block = ciphertext[i+ctx.blockSize : end]
		} else {
			end := i + ctx.blockSize
			if end > len(ciphertext) {
				end = len(ciphertext)
			}
			block = ciphertext[i:end]
		}

		if len(block) < ctx.blockSize {
			block = append(block, make([]uint8, ctx.blockSize-len(block))...)
		}

		var decryptedBlock []uint8
		var err error

		switch ctx.mode {
		case CipherModeECB:
			decryptedBlock, err = ctx.cipher.DecryptBlock(block)
			if err != nil {
				return nil, fmt.Errorf("ECB decryption failed: %w", err)
			}

		case CipherModeCBC:
			decryptedBlock, err = ctx.cipher.DecryptBlock(block)
			if err != nil {
				return nil, fmt.Errorf("CBC decryption failed: %w", err)
			}
			decryptedBlock = ctx.xorBlocks(decryptedBlock, currentBlock)
			currentBlock = block

		case CipherModePCBC:
			encryptedCopy := make([]uint8, len(block))
			copy(encryptedCopy, block)
			decryptedBlock, err = ctx.cipher.DecryptBlock(block)
			if err != nil {
				return nil, fmt.Errorf("PCBC decryption failed: %w", err)
			}
			decryptedBlock = ctx.xorBlocks(decryptedBlock, currentBlock)
			currentBlock = ctx.xorBlocks(decryptedBlock, encryptedCopy)

		case CipherModeCFB:
			decryptedBlock, err = ctx.cipher.EncryptBlock(currentBlock)
			if err != nil {
				return nil, fmt.Errorf("CFB decryption failed: %w", err)
			}
			decryptedBlock = ctx.xorBlocks(decryptedBlock, block)
			currentBlock = block

		case CipherModeOFB:
			currentBlock, err = ctx.cipher.EncryptBlock(currentBlock)
			if err != nil {
				return nil, fmt.Errorf("OFB decryption failed: %w", err)
			}
			decryptedBlock = ctx.xorBlocks(currentBlock, block)

		case CipherModeCTR:
			encryptedCounter, err := ctx.cipher.EncryptBlock(currentBlock)
			if err != nil {
				return nil, fmt.Errorf("CTR decryption failed: %w", err)
			}
			decryptedBlock = ctx.xorBlocks(encryptedCounter, block)
			ctx.incrementCounter(currentBlock)

		case CipherModeRandomDelta:
			decryptedBlock, err = ctx.cipher.DecryptBlock(block)
			if err != nil {
				return nil, fmt.Errorf("random delta decryption failed: %w", err)
			}
			decryptedBlock = ctx.xorBlocks(decryptedBlock, delta)

		default:
			return nil, fmt.Errorf("unsupported cipher mode")
		}

		plaintext = append(plaintext, decryptedBlock...)
	}

	return ctx.removePadding(plaintext)
}

func (ctx *CipherContext) EncryptFile(inputPath string, outputPath string) error {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	encrypted, err := ctx.Encrypt(data, ctx.parallel)
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	err = os.WriteFile(outputPath, encrypted, 0644)
	if err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	return nil
}

func (ctx *CipherContext) DecryptFile(inputPath string, outputPath string) error {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	decrypted, err := ctx.Decrypt(data, ctx.parallel)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	err = os.WriteFile(outputPath, decrypted, 0644)
	if err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	return nil
}

func (ctx *CipherContext) SetKey(newKey []uint8) error {
	ctx.key = make([]uint8, len(newKey))
	copy(ctx.key, newKey)
	return ctx.cipher.SetKey(ctx.key)
}

func (ctx *CipherContext) SetMode(newMode CipherMode) {
	ctx.mode = newMode
}

func (ctx *CipherContext) SetPaddingMode(newPaddingMode PaddingMode) {
	ctx.paddingMode = newPaddingMode
}

func (ctx *CipherContext) SetIV(newIV []uint8) {
	ctx.iv = make([]uint8, len(newIV))
	copy(ctx.iv, newIV)
}

func (ctx *CipherContext) GetMode() CipherMode {
	return ctx.mode
}

func (ctx *CipherContext) GetBlockSize() int {
	return ctx.blockSize
}

func GenerateRandomBytes(data []byte) (int, error) {
	return rand.Read(data)
}