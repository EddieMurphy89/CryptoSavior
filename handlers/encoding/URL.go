package encoding

import (
	"errors"
	"net/url"
)

// URLEncode 对输入字符串进行URL编码
func URLEncode(input string) string {
	return url.QueryEscape(input)
}

// URLDecode 对URL编码的字符串进行解码
func URLDecode(input string) (string, error) {
	decoded, err := url.QueryUnescape(input)
	if err != nil {
		return "", errors.New("解码失败: 输入的URL字符串无效")
	}
	return decoded, nil
}
