package hash

import (
	"crypto/md5"
	"fmt"
	"strings"
)

// ComputeMD5 计算输入文本的 MD5 哈希值，返回四种格式
func ComputeMD5(input string) (map[string]string, error) {
	data := []byte(input)
	hash := md5.Sum(data)

	// 32位小写
	md5_32_lower := fmt.Sprintf("%x", hash)
	// 32位大写
	md5_32_upper := fmt.Sprintf("%X", hash)
	// 16位小写
	md5_16_lower := md5_32_lower[8:24]
	// 16位大写
	md5_16_upper := strings.ToUpper(md5_16_lower)

	return map[string]string{
		"MD5-16 小写": md5_16_lower,
		"MD5-16 大写": md5_16_upper,
		"MD5-32 小写": md5_32_lower,
		"MD5-32 大写": md5_32_upper,
	}, nil
}
