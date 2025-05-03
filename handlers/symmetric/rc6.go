package symmetric

import (
	"bytes"
	"errors"
	"math/bits"
)

type RC6Encryption struct {
	P32, Q32 uint32
	Rounds   int
	WBit     int
	LgW      int
	Modulo   uint32
	Key      []uint32
}

// NewRC6Encryption 初始化 RC6Encryption
func NewRC6Encryption(key []byte, rounds, wBit, lgW int) *RC6Encryption {
	rc6 := &RC6Encryption{
		P32:    0xB7E15163,
		Q32:    0x9E3779B9,
		Rounds: rounds,
		WBit:   wBit,
		LgW:    lgW,
		Modulo: 1 << wBit,
		Key:    make([]uint32, 2*rounds+4),
	}
	rc6.keyGeneration(key)
	return rc6
}

// keyGeneration 生成密钥
func (rc6 *RC6Encryption) keyGeneration(key []byte) {
	c := len(key) / 4
	L := make([]uint32, c)
	for i := 0; i < c; i++ {
		L[i] = uint32(key[4*i]) | uint32(key[4*i+1])<<8 | uint32(key[4*i+2])<<16 | uint32(key[4*i+3])<<24
	}

	rc6.Key[0] = rc6.P32
	for i := 1; i < len(rc6.Key); i++ {
		rc6.Key[i] = rc6.Key[i-1] + rc6.Q32
	}

	A, B, i, j := uint32(0), uint32(0), 0, 0
	v := 3 * max(c, len(rc6.Key))
	for s := 0; s < v; s++ {
		A = bits.RotateLeft32(rc6.Key[i]+A+B, 3)
		rc6.Key[i] = A
		B = bits.RotateLeft32(L[j]+A+B, int((A+B)%32))
		L[j] = B
		i = (i + 1) % len(rc6.Key)
		j = (j + 1) % c
	}
}

// EncryptBlock 加密单个块
func (rc6 *RC6Encryption) EncryptBlock(data [4]uint32) [4]uint32 {
	A, B, C, D := data[0], data[1], data[2], data[3]
	B += rc6.Key[0]
	D += rc6.Key[1]

	for i := 1; i <= rc6.Rounds; i++ {
		T := bits.RotateLeft32(B*(2*B+1), rc6.LgW)
		U := bits.RotateLeft32(D*(2*D+1), rc6.LgW)
		A = bits.RotateLeft32(A^T, int(U%32)) + rc6.Key[2*i]
		C = bits.RotateLeft32(C^U, int(T%32)) + rc6.Key[2*i+1]
		A, B, C, D = B, C, D, A
	}

	A += rc6.Key[2*rc6.Rounds+2]
	C += rc6.Key[2*rc6.Rounds+3]
	return [4]uint32{A, B, C, D}
}

// DecryptBlock 解密单个块
func (rc6 *RC6Encryption) DecryptBlock(data [4]uint32) [4]uint32 {
	A, B, C, D := data[0], data[1], data[2], data[3]
	C -= rc6.Key[2*rc6.Rounds+3]
	A -= rc6.Key[2*rc6.Rounds+2]

	for i := rc6.Rounds; i >= 1; i-- {
		A, B, C, D = D, A, B, C
		U := bits.RotateLeft32(D*(2*D+1), rc6.LgW)
		T := bits.RotateLeft32(B*(2*B+1), rc6.LgW)
		C = bits.RotateLeft32(C-rc6.Key[2*i+1], -int(T%32)) ^ U
		A = bits.RotateLeft32(A-rc6.Key[2*i], -int(U%32)) ^ T
	}

	D -= rc6.Key[1]
	B -= rc6.Key[0]
	return [4]uint32{A, B, C, D}
}

// EncryptECB 实现 ECB 模式加密
func (rc6 *RC6Encryption) EncryptECB(data []byte) []byte {
	blockSize := 16
	data = PKCS7Padding(data, blockSize)
	encrypted := make([]byte, len(data))

	for i := 0; i < len(data); i += blockSize {
		block := [4]uint32{
			uint32(data[i]) | uint32(data[i+1])<<8 | uint32(data[i+2])<<16 | uint32(data[i+3])<<24,
			uint32(data[i+4]) | uint32(data[i+5])<<8 | uint32(data[i+6])<<16 | uint32(data[i+7])<<24,
			uint32(data[i+8]) | uint32(data[i+9])<<8 | uint32(data[i+10])<<16 | uint32(data[i+11])<<24,
			uint32(data[i+12]) | uint32(data[i+13])<<8 | uint32(data[i+14])<<16 | uint32(data[i+15])<<24,
		}
		encryptedBlock := rc6.EncryptBlock(block)
		for j := 0; j < 4; j++ {
			encrypted[i+j*4] = byte(encryptedBlock[j])
			encrypted[i+j*4+1] = byte(encryptedBlock[j] >> 8)
			encrypted[i+j*4+2] = byte(encryptedBlock[j] >> 16)
			encrypted[i+j*4+3] = byte(encryptedBlock[j] >> 24)
		}
	}
	return encrypted
}

// DecryptECB 实现 ECB 模式解密
func (rc6 *RC6Encryption) DecryptECB(data []byte) ([]byte, error) {
	blockSize := 16
	if len(data)%blockSize != 0 {
		return nil, errors.New("invalid data length")
	}
	decrypted := make([]byte, len(data))

	for i := 0; i < len(data); i += blockSize {
		block := [4]uint32{
			uint32(data[i]) | uint32(data[i+1])<<8 | uint32(data[i+2])<<16 | uint32(data[i+3])<<24,
			uint32(data[i+4]) | uint32(data[i+5])<<8 | uint32(data[i+6])<<16 | uint32(data[i+7])<<24,
			uint32(data[i+8]) | uint32(data[i+9])<<8 | uint32(data[i+10])<<16 | uint32(data[i+11])<<24,
			uint32(data[i+12]) | uint32(data[i+13])<<8 | uint32(data[i+14])<<16 | uint32(data[i+15])<<24,
		}
		decryptedBlock := rc6.DecryptBlock(block)
		for j := 0; j < 4; j++ {
			decrypted[i+j*4] = byte(decryptedBlock[j])
			decrypted[i+j*4+1] = byte(decryptedBlock[j] >> 8)
			decrypted[i+j*4+2] = byte(decryptedBlock[j] >> 16)
			decrypted[i+j*4+3] = byte(decryptedBlock[j] >> 24)
		}
	}
	return RemovePKCS7Padding(decrypted)
}

// EncryptCBC 实现 CBC 模式加密
func (rc6 *RC6Encryption) EncryptCBC(data, iv []byte) []byte {
	blockSize := 16
	data = PKCS7Padding(data, blockSize)
	encrypted := make([]byte, len(data))
	prevBlock := iv

	for i := 0; i < len(data); i += blockSize {
		block := [4]uint32{
			uint32(data[i]^prevBlock[0]) | uint32(data[i+1]^prevBlock[1])<<8 | uint32(data[i+2]^prevBlock[2])<<16 | uint32(data[i+3]^prevBlock[3])<<24,
			uint32(data[i+4]^prevBlock[4]) | uint32(data[i+5]^prevBlock[5])<<8 | uint32(data[i+6]^prevBlock[6])<<16 | uint32(data[i+7]^prevBlock[7])<<24,
			uint32(data[i+8]^prevBlock[8]) | uint32(data[i+9]^prevBlock[9])<<8 | uint32(data[i+10]^prevBlock[10])<<16 | uint32(data[i+11]^prevBlock[11])<<24,
			uint32(data[i+12]^prevBlock[12]) | uint32(data[i+13]^prevBlock[13])<<8 | uint32(data[i+14]^prevBlock[14])<<16 | uint32(data[i+15]^prevBlock[15])<<24,
		}
		encryptedBlock := rc6.EncryptBlock(block)
		for j := 0; j < 4; j++ {
			encrypted[i+j*4] = byte(encryptedBlock[j])
			encrypted[i+j*4+1] = byte(encryptedBlock[j] >> 8)
			encrypted[i+j*4+2] = byte(encryptedBlock[j] >> 16)
			encrypted[i+j*4+3] = byte(encryptedBlock[j] >> 24)
		}
		prevBlock = encrypted[i : i+blockSize]
	}
	return encrypted
}

// DecryptCBC 实现 CBC 模式解密
func (rc6 *RC6Encryption) DecryptCBC(data, iv []byte) ([]byte, error) {
	blockSize := 16
	if len(data)%blockSize != 0 {
		return nil, errors.New("invalid data length")
	}
	decrypted := make([]byte, len(data))
	prevBlock := iv

	for i := 0; i < len(data); i += blockSize {
		block := [4]uint32{
			uint32(data[i]) | uint32(data[i+1])<<8 | uint32(data[i+2])<<16 | uint32(data[i+3])<<24,
			uint32(data[i+4]) | uint32(data[i+5])<<8 | uint32(data[i+6])<<16 | uint32(data[i+7])<<24,
			uint32(data[i+8]) | uint32(data[i+9])<<8 | uint32(data[i+10])<<16 | uint32(data[i+11])<<24,
			uint32(data[i+12]) | uint32(data[i+13])<<8 | uint32(data[i+14])<<16 | uint32(data[i+15])<<24,
		}
		decryptedBlock := rc6.DecryptBlock(block)
		for j := 0; j < 4; j++ {
			decrypted[i+j*4] = byte(decryptedBlock[j]) ^ prevBlock[j*4]
			decrypted[i+j*4+1] = byte(decryptedBlock[j]>>8) ^ prevBlock[j*4+1]
			decrypted[i+j*4+2] = byte(decryptedBlock[j]>>16) ^ prevBlock[j*4+2]
			decrypted[i+j*4+3] = byte(decryptedBlock[j]>>24) ^ prevBlock[j*4+3]
		}
		prevBlock = data[i : i+blockSize]
	}
	return RemovePKCS7Padding(decrypted)
}

// PKCS7Padding 添加 PKCS#7 填充
func PKCS7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// RemovePKCS7Padding 移除 PKCS#7 填充
func RemovePKCS7Padding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("data is empty")
	}
	padding := int(data[length-1])
	if padding > length {
		return nil, errors.New("invalid padding")
	}
	return data[:length-padding], nil
}

// max 返回两个整数的最大值
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
