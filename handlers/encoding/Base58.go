package encoding

import (
	"errors"
	"github.com/btcsuite/btcutil/base58"
)

// Base58Encode 对输入字符串进行Base58编码
func Base58Encode(input string) string {
	return base58.Encode([]byte(input))
}

// Base58Decode 对Base58编码的字符串进行解码
func Base58Decode(input string) (string, error) {
	decoded := base58.Decode(input)
	if len(decoded) == 0 {
		return "", errors.New("解码失败: 输入的Base58字符串无效")
	}
	return string(decoded), nil
}
