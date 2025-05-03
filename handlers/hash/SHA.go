package hash

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
)

// ComputeSHA 计算并打印输入文本的 SHA1、SHA224、SHA256、SHA384 和 SHA512 摘要
func ComputeSHA(input string, hashType string) (string, error) {
	data := []byte(input)

	switch hashType {
	case "SHA1":
		hash := sha1.Sum(data)
		return fmt.Sprintf("%x", hash), nil
	case "SHA224":
		hash := sha256.Sum224(data)
		return fmt.Sprintf("%x", hash), nil
	case "SHA256":
		hash := sha256.Sum256(data)
		return fmt.Sprintf("%x", hash), nil
	case "SHA384":
		hash := sha512.Sum384(data)
		return fmt.Sprintf("%x", hash), nil
	case "SHA512":
		hash := sha512.Sum512(data)
		return fmt.Sprintf("%x", hash), nil
	default:
		return "", errors.New("unsupported hash type")
	}
}
