package cripta

import (
	"fmt"
)

type DESKeySchedule struct{}

var PC1 = []int{
	57, 49, 41, 33, 25, 17, 9,
	1, 58, 50, 42, 34, 26, 18,
	10, 2, 59, 51, 43, 35, 27,
	19, 11, 3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,
	7, 62, 54, 46, 38, 30, 22,
	14, 6, 61, 53, 45, 37, 29,
	21, 13, 5, 28, 20, 12, 4,
}

var PC2 = []int{
	14, 17, 11, 24, 1, 5,
	3, 28, 15, 6, 21, 10,
	23, 19, 12, 4, 26, 8,
	16, 7, 27, 20, 13, 2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32,
}

var SHIFT_SCHEDULE = []int{
	1, 1, 2, 2, 2, 2, 2, 2,
	1, 2, 2, 2, 2, 2, 2, 1,
}

func (dks *DESKeySchedule) leftShift28(data []uint8, shifts int) ([]uint8, error) {
	if len(data) != 4 {
		return nil, fmt.Errorf("data must be 4 bytes (28 bits used)")
	}

	var value uint32
	value |= (uint32(data[0]) << 24)
	value |= (uint32(data[1]) << 16)
	value |= (uint32(data[2]) << 8)
	value |= uint32(data[3])

	mask28 := uint32(0x0FFFFFFF)
	value &= mask28

	value = ((value << shifts) | (value >> (28 - shifts))) & mask28

	result := make([]uint8, 4)
	result[0] = uint8((value >> 24) & 0xFF)
	result[1] = uint8((value >> 16) & 0xFF)
	result[2] = uint8((value >> 8) & 0xFF)
	result[3] = uint8(value & 0xFF)

	return result, nil
}

func (dks *DESKeySchedule) GenerateRoundKeys(masterKey []uint8) ([][]uint8, error) {
	if len(masterKey) != 8 {
		return nil, fmt.Errorf("DES key must be 8 bytes (64 bits)")
	}

	roundKeys := make([][]uint8, 0, 16)

	permutedKey, err := PermuteBits(masterKey, PC1, false, 1)
	if err != nil {
		return nil, fmt.Errorf("PC1 permutation failed: %w", err)
	}

	C := make([]uint8, 4)
	D := make([]uint8, 4)

	for i := 0; i < 28; i++ {
		byteIdx := i / 8
		bitIdx := 7 - (i % 8)
		srcByteIdx := i / 8
		srcBitIdx := 7 - (i % 8)

		bit := (permutedKey[srcByteIdx] >> srcBitIdx) & 1
		C[byteIdx] |= (bit << bitIdx)
	}

	for i := 0; i < 28; i++ {
		byteIdx := i / 8
		bitIdx := 7 - (i % 8)
		srcByteIdx := (i + 28) / 8
		srcBitIdx := 7 - ((i + 28) % 8)

		bit := (permutedKey[srcByteIdx] >> srcBitIdx) & 1
		D[byteIdx] |= (bit << bitIdx)
	}

	for round := 0; round < 16; round++ {
		C, err = dks.leftShift28(C, SHIFT_SCHEDULE[round])
		if err != nil {
			return nil, fmt.Errorf("left shift C failed in round %d: %w", round, err)
		}

		D, err = dks.leftShift28(D, SHIFT_SCHEDULE[round])
		if err != nil {
			return nil, fmt.Errorf("left shift D failed in round %d: %w", round, err)
		}

		CD := make([]uint8, 7)

		for i := 0; i < 28; i++ {
			srcByteIdx := i / 8
			srcBitIdx := 7 - (i % 8)
			dstByteIdx := i / 8
			dstBitIdx := 7 - (i % 8)

			bit := (C[srcByteIdx] >> srcBitIdx) & 1
			CD[dstByteIdx] |= (bit << dstBitIdx)
		}

		for i := 0; i < 28; i++ {
			srcByteIdx := i / 8
			srcBitIdx := 7 - (i % 8)
			dstByteIdx := (i + 28) / 8
			dstBitIdx := 7 - ((i + 28) % 8)

			bit := (D[srcByteIdx] >> srcBitIdx) & 1
			CD[dstByteIdx] |= (bit << dstBitIdx)
		}

		roundKey, err := PermuteBits(CD, PC2, false, 1)
		if err != nil {
			return nil, fmt.Errorf("PC2 permutation failed in round %d: %w", round, err)
		}

		roundKeys = append(roundKeys, roundKey)
	}

	return roundKeys, nil
}