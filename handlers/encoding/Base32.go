package encoding

import (
	"encoding/base32"
	"errors"
)

// Base32Encode 对输入字符串进行Base32编码
func Base32Encode(input string) string {
	encoder := base32.StdEncoding
	return encoder.EncodeToString([]byte(input))
}

// Base32Decode 对Base32编码的字符串进行解码
func Base32Decode(input string) (string, error) {
	decoder := base32.StdEncoding
	decoded, err := decoder.DecodeString(input)
	if err != nil {
		return "", errors.New("解码失败: 输入的Base32字符串无效")
	}
	return string(decoded), nil
}
