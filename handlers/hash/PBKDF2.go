package hash

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"golang.org/x/crypto/pbkdf2"
	"hash"
)

// ComputePBKDF2 使用 PBKDF2 算法生成密钥
func ComputePBKDF2(text, salt string, iterations, keyLength int, hashFunc string) (string, error) {
	// 根据用户选择的哈希函数
	var h func() hash.Hash
	switch hashFunc {
	case "SHA1":
		h = sha1.New
	case "SHA256":
		h = sha256.New
	case "SHA512":
		h = sha512.New
	default:
		return "", errors.New("不支持的哈希函数")
	}

	// 使用 PBKDF2 生成密钥
	key := pbkdf2.Key([]byte(text), []byte(salt), iterations, keyLength, h)
	// 返回十六进制编码的密钥
	return hex.EncodeToString(key), nil
}
