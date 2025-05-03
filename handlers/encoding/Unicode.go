package encoding

import (
	"encoding/hex"
	"errors"
	"unicode/utf8"
)

// UnicodeEncode 将字符串转换为Unicode编码
func UnicodeEncode(input string) string {
	result := ""
	for _, r := range input {
		result += "\\u" + hex.EncodeToString([]byte(string(r)))
	}
	return result
}

// UnicodeDecode 将Unicode编码的字符串解码为普通字符串
func UnicodeDecode(input string) (string, error) {
	var result string
	for len(input) > 0 {
		if len(input) < 6 || input[:2] != "\\u" {
			return "", errors.New("解码失败: 输入的Unicode字符串无效")
		}
		r, size := utf8.DecodeRuneInString(input[2:])
		if r == utf8.RuneError {
			return "", errors.New("解码失败: 无效的Unicode字符")
		}
		result += string(r)
		input = input[size+2:]
	}
	return result, nil
}
