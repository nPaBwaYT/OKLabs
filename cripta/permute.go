package cripta

import "fmt"

func PermuteBits(value []uint8, rule []int, indexFromLSB bool, startBitNum int) ([]uint8, error) {
    outputBits := len(rule)
    outputBytes := (outputBits + 7) / 8
    
    result := make([]uint8, outputBytes)
    
    for i := 0; i < outputBits; i++ {
        sourcePos := rule[i] - startBitNum
        
        if sourcePos < 0 || sourcePos >= len(value)*8 {
            return nil, fmt.Errorf("position %d out of bounds", rule[i])
        }
        
        var sourceByte, sourceBit int
        
        if indexFromLSB {
            sourceByte = sourcePos / 8
            sourceBit = sourcePos % 8
        } else {
            sourceByte = sourcePos / 8
            sourceBit = 7 - (sourcePos % 8)
        }
        
        if sourceByte >= len(value) {
            return nil, fmt.Errorf("source byte index %d out of bounds", sourceByte)
        }
        
        bitValue := (value[sourceByte] >> sourceBit) & 1
        
        var destByte, destBit int
        
        if indexFromLSB {
            destByte = i / 8
            destBit = i % 8
        } else {
            destByte = i / 8
            destBit = 7 - (i % 8)
        }
        
        if destByte < len(result) {
            result[destByte] |= (bitValue << destBit)
        }
    }
    
    return result, nil
}

func PrintBinary(data []uint8, label string) error {
    fmt.Printf("%s: ", label)
    for _, byteVal := range data {
        binaryStr := fmt.Sprintf("%08b", byteVal)
        fmt.Printf("%s ", binaryStr)
    }
    fmt.Println()
	return nil
}