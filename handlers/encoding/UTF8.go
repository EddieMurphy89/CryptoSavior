package encoding

import (
	"errors"
	"unicode/utf8"
)

// UTF8Encode 将字符串转换为UTF-8编码
func UTF8Encode(input string) string {
	return string([]byte(input))
}

// UTF8Decode 将UTF-8编码的字符串解码为普通字符串
func UTF8Decode(input string) (string, error) {
	if !utf8.ValidString(input) {
		return "", errors.New("解码失败: 输入的UTF-8字符串无效")
	}
	return input, nil
}
