package encoding

import (
	"encoding/base64"
	"errors"
)

// Base64Encode 对输入字符串进行Base64编码
func Base64Encode(input string) string {
	return base64.StdEncoding.EncodeToString([]byte(input))
}

// Base64Decode 对Base64编码的字符串进行解码
func Base64Decode(input string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return "", errors.New("解码失败: 输入的Base64字符串无效")
	}
	return string(decoded), nil
}
