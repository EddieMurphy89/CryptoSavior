package encoding

// Rot13 对输入字符串进行ROT13加解密
func Rot13(input string) string {
	result := make([]rune, len(input))
	for i, char := range input {
		switch {
		case char >= 'a' && char <= 'z':
			result[i] = 'a' + (char-'a'+13)%26
		case char >= 'A' && char <= 'Z':
			result[i] = 'A' + (char-'A'+13)%26
		default:
			result[i] = char
		}
	}
	return string(result)
}
