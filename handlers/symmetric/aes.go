package symmetric

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
)

// AESConfig 配置结构体
type AESConfig struct {
	Key          []byte
	KeyLength    int    // 128, 192, 256
	IV           []byte // Initialization Vector
	Mode         string // CBC, CFB, OFB, CTR, GCM, ECB
	Nonce        []byte // GCM模式下的Nonce
	AuthData     []byte // GCM模式下的验证数据
	InputFormat  string // Raw, Hex
	OutputFormat string // Raw, Hex
}

// Encrypt 加密函数
func EncryptAES(config AESConfig, plaintext string) (string, error) {
	// 检查密钥长度
	if len(config.Key)*8 != config.KeyLength {
		return "", errors.New("invalid key length")
	}

	// 根据 InputFormat 处理输入明文
	var plaintextBytes []byte
	var err error
	if config.InputFormat == "Hex" {
		plaintextBytes, err = hex.DecodeString(plaintext)
		if err != nil {
			return "", errors.New("invalid hex input for plaintext")
		}
	} else {
		plaintextBytes = []byte(plaintext)
	}

	// 创建AES块
	block, err := aes.NewCipher(config.Key)
	if err != nil {
		return "", err
	}

	var ciphertext []byte
	switch config.Mode {
	case "CBC":
		if len(config.IV) != aes.BlockSize {
			return "", errors.New("invalid IV length for CBC mode")
		}
		ciphertext, err = encryptCBC(block, config.IV, plaintextBytes)
	case "CFB":
		if len(config.IV) != aes.BlockSize {
			return "", errors.New("invalid IV length for CFB mode")
		}
		ciphertext, err = encryptCFB(block, config.IV, plaintextBytes)
	case "OFB":
		if len(config.IV) != aes.BlockSize {
			return "", errors.New("invalid IV length for OFB mode")
		}
		ciphertext, err = encryptOFB(block, config.IV, plaintextBytes)
	case "CTR":
		ciphertext, err = encryptCTR(block, config.IV, plaintextBytes)
	case "GCM":
		if len(config.Nonce) != 12 {
			return "", errors.New("invalid Nonce length for GCM mode")
		}
		ciphertext, err = encryptGCM(block, config.Nonce, config.AuthData, plaintextBytes)
	case "ECB":
		ciphertext, err = encryptECB(block, plaintextBytes)
	default:
		return "", errors.New("unsupported mode")
	}

	if err != nil {
		return "", err
	}

	// 输出格式
	if config.OutputFormat == "Hex" {
		return hex.EncodeToString(ciphertext), nil
	}
	return string(ciphertext), nil
}

// Decrypt 解密函数
func DecryptAES(config AESConfig, ciphertext string) (string, error) {
	// 检查密钥长度
	if len(config.Key)*8 != config.KeyLength {
		return "", errors.New("invalid key length")
	}

	// 根据 InputFormat 处理输入密文
	var ciphertextBytes []byte
	var err error
	if config.InputFormat == "Hex" {
		ciphertextBytes, err = hex.DecodeString(ciphertext)
		if err != nil {
			return "", errors.New("invalid hex input for ciphertext")
		}
	} else {
		ciphertextBytes = []byte(ciphertext)
	}

	// 创建AES块
	block, err := aes.NewCipher(config.Key)
	if err != nil {
		return "", err
	}

	var plaintext []byte
	switch config.Mode {
	case "CBC":
		if len(config.IV) != aes.BlockSize {
			return "", errors.New("invalid IV length for CBC mode")
		}
		plaintext, err = decryptCBC(block, config.IV, ciphertextBytes)
	case "CFB":
		if len(config.IV) != aes.BlockSize {
			return "", errors.New("invalid IV length for CFB mode")
		}
		plaintext, err = decryptCFB(block, config.IV, ciphertextBytes)
	case "OFB":
		if len(config.IV) != aes.BlockSize {
			return "", errors.New("invalid IV length for OFB mode")
		}
		plaintext, err = decryptOFB(block, config.IV, ciphertextBytes)
	case "CTR":
		plaintext, err = decryptCTR(block, config.IV, ciphertextBytes)
	case "GCM":
		if len(config.Nonce) != 12 {
			return "", errors.New("invalid Nonce length for GCM mode")
		}
		plaintext, err = decryptGCM(block, config.Nonce, config.AuthData, ciphertextBytes)
	case "ECB":
		plaintext, err = decryptECB(block, ciphertextBytes)
	default:
		return "", errors.New("unsupported mode")
	}

	if err != nil {
		return "", err
	}

	// 输出格式
	if config.OutputFormat == "Hex" {
		return hex.EncodeToString(plaintext), nil
	}
	return string(plaintext), nil
}

// CBC模式加密
func encryptCBC(block cipher.Block, iv, plaintext []byte) ([]byte, error) {
	plaintext = pkcs7Padding(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)
	return ciphertext, nil
}

// CBC模式解密
func decryptCBC(block cipher.Block, iv, ciphertext []byte) ([]byte, error) {
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)
	return pkcs7Unpadding(plaintext, aes.BlockSize)
}

// CFB模式加密
func encryptCFB(block cipher.Block, iv, plaintext []byte) ([]byte, error) {
	stream := cipher.NewCFBEncrypter(block, iv)
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}

// CFB模式解密
func decryptCFB(block cipher.Block, iv, ciphertext []byte) ([]byte, error) {
	stream := cipher.NewCFBDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
}

// OFB模式加密
func encryptOFB(block cipher.Block, iv, plaintext []byte) ([]byte, error) {
	stream := cipher.NewOFB(block, iv)
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}

// OFB模式解密
func decryptOFB(block cipher.Block, iv, ciphertext []byte) ([]byte, error) {
	stream := cipher.NewOFB(block, iv)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
}

// CTR模式加密
func encryptCTR(block cipher.Block, iv, plaintext []byte) ([]byte, error) {
	stream := cipher.NewCTR(block, iv)
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}

// CTR模式解密
func decryptCTR(block cipher.Block, iv, ciphertext []byte) ([]byte, error) {
	stream := cipher.NewCTR(block, iv)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
}

// GCM模式加密
func encryptGCM(block cipher.Block, nonce, authData, plaintext []byte) ([]byte, error) {
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext := aesGCM.Seal(nil, nonce, plaintext, authData)
	return ciphertext, nil
}

// GCM模式解密
func decryptGCM(block cipher.Block, nonce, authData, ciphertext []byte) ([]byte, error) {
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, authData)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// ECB模式加密
func encryptECB(block cipher.Block, plaintext []byte) ([]byte, error) {
	plaintext = pkcs7Padding(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(plaintext))
	for start := 0; start < len(plaintext); start += block.BlockSize() {
		block.Encrypt(ciphertext[start:start+block.BlockSize()], plaintext[start:start+block.BlockSize()])
	}
	return ciphertext, nil
}

// ECB模式解密
func decryptECB(block cipher.Block, ciphertext []byte) ([]byte, error) {
	plaintext := make([]byte, len(ciphertext))
	for start := 0; start < len(ciphertext); start += block.BlockSize() {
		block.Decrypt(plaintext[start:start+block.BlockSize()], ciphertext[start:start+block.BlockSize()])
	}
	return pkcs7Unpadding(plaintext, aes.BlockSize)
}

// PKCS7填充
func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// PKCS7去填充
func pkcs7Unpadding(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 || length%blockSize != 0 {
		return nil, errors.New("invalid padding size")
	}
	padding := int(data[length-1])
	if padding > blockSize || padding == 0 {
		return nil, errors.New("invalid padding")
	}
	return data[:length-padding], nil
}
