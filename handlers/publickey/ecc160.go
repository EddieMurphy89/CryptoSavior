package publickey

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
)

// GenerateECCKeyPair 生成 ECC 密钥对
func GenerateECCKeyPair(curve elliptic.Curve) ([]byte, *big.Int, *big.Int, error) {
	privateKey, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	return privateKey, x, y, nil
}

// EccEncrypt 使用公钥加密
func EccEncrypt(curve elliptic.Curve, plaintext []byte, publicKeyBase64 string) ([]byte, error) {
	// 解析公钥
	publicKey, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil {
		return nil, err
	}
	x, y := elliptic.Unmarshal(curve, publicKey)
	if x == nil || y == nil {
		return nil, errors.New("无效的公钥")
	}

	// 生成临时密钥对
	privateKey, ephemeralX, ephemeralY, err := GenerateECCKeyPair(curve)
	if err != nil {
		return nil, err
	}

	// 计算共享密钥
	sharedX, _ := curve.ScalarMult(x, y, privateKey)
	sharedKey := sha256.Sum256(sharedX.Bytes())

	// 加密明文
	ciphertext := make([]byte, len(plaintext))
	for i := range plaintext {
		ciphertext[i] = plaintext[i] ^ sharedKey[i%len(sharedKey)]
	}

	// 返回密文和临时公钥
	ephemeralPublicKey := elliptic.Marshal(curve, ephemeralX, ephemeralY)
	return append(ephemeralPublicKey, ciphertext...), nil
}

// EccDecrypt 使用私钥解密
func EccDecrypt(curve elliptic.Curve, ciphertext []byte, privateKeyBase64 string) ([]byte, error) {
	// 解析私钥
	privateKey, err := base64.StdEncoding.DecodeString(privateKeyBase64)
	if err != nil {
		return nil, err
	}

	// 提取临时公钥
	byteLen := (curve.Params().BitSize + 7) / 8
	if len(ciphertext) < 1+2*byteLen {
		return nil, errors.New("无效的密文")
	}
	ephemeralPublicKey := ciphertext[:1+2*byteLen]
	ciphertext = ciphertext[1+2*byteLen:]

	// 解析临时公钥
	x, y := elliptic.Unmarshal(curve, ephemeralPublicKey)
	if x == nil || y == nil {
		return nil, errors.New("无效的临时公钥")
	}

	// 计算共享密钥
	sharedX, _ := curve.ScalarMult(x, y, privateKey)
	sharedKey := sha256.Sum256(sharedX.Bytes())

	// 解密密文
	plaintext := make([]byte, len(ciphertext))
	for i := range ciphertext {
		plaintext[i] = ciphertext[i] ^ sharedKey[i%len(sharedKey)]
	}

	return plaintext, nil
}
