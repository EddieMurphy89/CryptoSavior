package publickey

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

func RsaEncrypt(plainText, publicKey []byte) ([]byte, error) {
	// 使用 RSA 公钥加密
	pubKey, err := parsePublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, plainText, nil)
}

func RsaDecrypt(cipherText, privateKey []byte) ([]byte, error) {
	// 使用 RSA 私钥解密
	privKey, err := parsePrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, cipherText, nil)
}

// GenerateRSAKeyPair 生成 1024 位的 RSA 密钥对，并以 PEM 和 Base64 格式返回
func GenerateRSAKeyPair() (string, string, string, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return "", "", "", "", err
	}

	// 编码私钥为 PEM 格式
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// 编码公钥为 PEM 格式
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey),
	})

	// 编码私钥为 Base64 格式
	privateKeyBase64 := base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(privateKey))

	// 编码公钥为 Base64 格式
	publicKeyBase64 := base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(&privateKey.PublicKey))

	return string(privateKeyPEM), string(publicKeyPEM), privateKeyBase64, publicKeyBase64, nil
}

// parsePublicKey 解析 Base64 格式的公钥
func parsePublicKey(key []byte) (*rsa.PublicKey, error) {
	decodedKey, err := base64.StdEncoding.DecodeString(string(key))
	if err != nil {
		return nil, errors.New("无效的公钥: Base64 解码失败")
	}

	publicKey, err := x509.ParsePKCS1PublicKey(decodedKey)
	if err != nil {
		return nil, errors.New("无效的公钥: 解析失败")
	}

	return publicKey, nil
}

// parsePrivateKey 解析 Base64 格式的私钥
func parsePrivateKey(key []byte) (*rsa.PrivateKey, error) {
	decodedKey, err := base64.StdEncoding.DecodeString(string(key))
	if err != nil {
		return nil, errors.New("无效的私钥: Base64 解码失败")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(decodedKey)
	if err != nil {
		return nil, errors.New("无效的私钥: 解析失败")
	}

	return privateKey, nil
}
