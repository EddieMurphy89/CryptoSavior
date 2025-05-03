package hash

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"hash"
	"strings"
)

// ComputeHMACSHA 计算 HMAC-SHA
func ComputeHMACSHA(text, key, shaType string) (string, error) {
	var hashFunc func() hash.Hash

	switch shaType {
	case "SHA1":
		hashFunc = sha1.New
	case "SHA224":
		hashFunc = sha256.New224
	case "SHA256":
		hashFunc = sha256.New
	case "SHA384":
		hashFunc = sha512.New384
	case "SHA512":
		hashFunc = sha512.New
	default:
		return "", errors.New("unsupported SHA type")
	}

	h := hmac.New(hashFunc, []byte(key))
	h.Write([]byte(text))
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ComputeHMACMD5 计算 HMAC-MD5
func ComputeHMACMD5(text, key, md5Type string) (string, error) {
	h := hmac.New(md5.New, []byte(key))
	h.Write([]byte(text))
	result := h.Sum(nil)

	switch md5Type {
	case "lowercase":
		return hex.EncodeToString(result), nil
	case "uppercase":
		return strings.ToUpper(hex.EncodeToString(result)), nil
	default:
		return "", errors.New("unsupported MD5 type")
	}
}
