package publickey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"math/big"
)

// ECDSASignature 表示 ECDSA 签名的结构
type ECDSASignature struct {
	R, S *big.Int
}

// SignECDSA 使用私钥对数据进行签名
func SignECDSA(data []byte, privateKeyBase64 string, curve elliptic.Curve) ([]byte, error) {
	// 解码 Base64 私钥
	privateKeyBytes, err := base64.StdEncoding.DecodeString(privateKeyBase64)
	if err != nil {
		return nil, errors.New("私钥解码失败")
	}

	// 解析私钥
	privateKey, err := x509.ParseECPrivateKey(privateKeyBytes)
	if err != nil {
		return nil, errors.New("解析私钥失败")
	}

	// 计算数据的哈希值
	hash := sha256.Sum256(data)

	// 签名
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, errors.New("签名失败")
	}

	// 序列化签名
	signature, err := asn1.Marshal(ECDSASignature{R: r, S: s})
	if err != nil {
		return nil, errors.New("签名序列化失败")
	}

	return signature, nil
}

// VerifyECDSA 使用公钥验证签名
func VerifyECDSA(data, signature []byte, publicKeyBase64 string, curve elliptic.Curve) (bool, error) {
	// 解码 Base64 公钥
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil {
		return false, errors.New("公钥解码失败")
	}

	// 解析公钥
	x, y := elliptic.Unmarshal(curve, publicKeyBytes)
	if x == nil || y == nil {
		return false, errors.New("解析公钥失败")
	}
	publicKey := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}

	// 计算数据的哈希值
	hash := sha256.Sum256(data)

	// 反序列化签名
	var ecdsaSignature ECDSASignature
	_, err = asn1.Unmarshal(signature, &ecdsaSignature)
	if err != nil {
		return false, errors.New("签名反序列化失败")
	}

	// 验证签名
	isValid := ecdsa.Verify(publicKey, hash[:], ecdsaSignature.R, ecdsaSignature.S)
	return isValid, nil
}

// GenerateECDSAKey 生成 ECDSA 密钥对
func GenerateECDSAKey(curve elliptic.Curve) ([]byte, *big.Int, *big.Int, error) {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, nil, errors.New("密钥生成失败")
	}

	// 序列化私钥
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, nil, errors.New("私钥序列化失败")
	}

	return privateKeyBytes, privateKey.PublicKey.X, privateKey.PublicKey.Y, nil
}
