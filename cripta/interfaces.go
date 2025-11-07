package cripta

type IKeySchedule interface {
	GenerateRoundKeys(masterKey []uint8) ([][]uint8, error)
}

type IRoundFunction interface {
	Apply(inputBlock []uint8, roundKey []uint8) ([]uint8, error)
}

type ISymmetricCipher interface {
	SetKey(key []uint8) error
	EncryptBlock(plainBlock []uint8) ([]uint8, error)
	DecryptBlock(cipherBlock []uint8) ([]uint8, error)
}