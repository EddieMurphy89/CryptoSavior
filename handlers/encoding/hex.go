package encoding

import (
	"encoding/hex"
	"errors"
)

// HexEncode 对输入字符串进行Hex编码
func HexEncode(input string) string {
	return hex.EncodeToString([]byte(input))
}

// HexDecode 对Hex编码的字符串进行解码
func HexDecode(input string) (string, error) {
	decoded, err := hex.DecodeString(input)
	if err != nil {
		return "", errors.New("解码失败: 输入的Hex字符串无效")
	}
	return string(decoded), nil
}
