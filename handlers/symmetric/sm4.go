package symmetric

import (
	"encoding/hex"
	"errors"
	"github.com/tjfoc/gmsm/sm4"
)

// SM4Config 配置结构体
type SM4Config struct {
	Key          []byte
	IV           []byte
	Mode         string
	InputFormat  string
	OutputFormat string
}

//SM4默认key长度为128bits，所以不予设置

// Encrypt 加密函数
func EncryptSM4(config SM4Config, plaintext string) (string, error) {
	// 根据输入格式处理明文
	var plaintextBytes []byte
	if config.InputFormat == "Hex" {
		var err error
		plaintextBytes, err = hex.DecodeString(plaintext)
		if err != nil {
			return "", errors.New("invalid hex input for plaintext")
		}
	} else {
		plaintextBytes = []byte(plaintext)
	}

	// 创建SM4块
	block, err := sm4.NewCipher(config.Key)
	if err != nil {
		return "", err
	}

	var ciphertext []byte
	switch config.Mode {
	case "CBC":
		ciphertext, err = encryptCBC(block, config.IV, plaintextBytes)
	case "CFB":
		ciphertext, err = encryptCFB(block, config.IV, plaintextBytes)
	case "OFB":
		ciphertext, err = encryptOFB(block, config.IV, plaintextBytes)
	case "CTR":
		ciphertext, err = encryptCTR(block, config.IV, plaintextBytes)
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
func DecryptSM4(config SM4Config, ciphertext string) (string, error) {
	// 根据输入格式处理密文
	var ciphertextBytes []byte
	if config.InputFormat == "Hex" {
		var err error
		ciphertextBytes, err = hex.DecodeString(ciphertext)
		if err != nil {
			return "", errors.New("invalid hex input for ciphertext")
		}
	} else {
		ciphertextBytes = []byte(ciphertext)
	}

	// 创建SM4块
	block, err := sm4.NewCipher(config.Key)
	if err != nil {
		return "", err
	}

	var plaintext []byte
	switch config.Mode {
	case "CBC":
		plaintext, err = decryptCBC(block, config.IV, ciphertextBytes)
	case "CFB":
		plaintext, err = decryptCFB(block, config.IV, ciphertextBytes)
	case "OFB":
		plaintext, err = decryptOFB(block, config.IV, ciphertextBytes)
	case "CTR":
		plaintext, err = decryptCTR(block, config.IV, ciphertextBytes)
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
