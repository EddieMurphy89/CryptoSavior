package publickey

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"errors"
)

// SignRSASHA1 使用 Base64 编码的私钥对文本进行签名
func SignRSASHA1(data []byte, privateKeyBase64 string) ([]byte, error) {
	// 解码 Base64 私钥
	privateKeyBytes, err := base64.StdEncoding.DecodeString(privateKeyBase64)
	if err != nil {
		return nil, errors.New("私钥解码失败")
	}

	// 解析私钥
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBytes)
	if err != nil {
		return nil, errors.New("解析私钥失败")
	}

	// 计算数据的哈希值
	hash := sha1.New()
	hash.Write(data)
	hashed := hash.Sum(nil)

	// 使用私钥签名
	signature, err := rsa.SignPKCS1v15(nil, privateKey, crypto.SHA1, hashed)
	if err != nil {
		return nil, errors.New("签名失败")
	}

	return signature, nil
}

// VerifyRSASHA1 使用 Base64 编码的公钥验证签名
func VerifyRSASHA1(data, signature []byte, publicKeyBase64 string) (bool, error) {
	// 解码 Base64 公钥
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil {
		return false, errors.New("公钥解码失败")
	}

	// 解析公钥
	publicKey, err := x509.ParsePKCS1PublicKey(publicKeyBytes)
	if err != nil {
		return false, errors.New("解析公钥失败")
	}

	// 计算数据的哈希值
	hash := sha1.New()
	hash.Write(data)
	hashed := hash.Sum(nil)

	// 验证签名
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA1, hashed, signature)
	if err != nil {
		return false, nil
	}

	return true, nil
}
