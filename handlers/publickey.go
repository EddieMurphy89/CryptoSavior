package handlers

import (
	"CryptoSavior/handlers/publickey"
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
	"github.com/fd/secp160r1"
	"github.com/gin-gonic/gin"
	"github.com/pedroalbanese/secp160r2"
	"net/http"
)

func RSA1024Handler(c *gin.Context) {
	action := c.PostForm("action")
	text := c.PostForm("text")
	publicKey := c.PostForm("publicKey")
	privateKey := c.PostForm("privateKey")

	switch action {
	case "encrypt":
		if text == "" || publicKey == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "加密需要文本和公钥"})
			return
		}

		// 调用加密函数
		encryptedText, err := publickey.RsaEncrypt([]byte(text), []byte(publicKey))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "加密失败", "details": err.Error()})
			return
		}

		// 返回加密结果
		c.JSON(http.StatusOK, gin.H{"result": base64.StdEncoding.EncodeToString(encryptedText)})

	case "decrypt":
		if text == "" || privateKey == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "解密需要文本和私钥"})
			return
		}

		// 解码加密文本
		decodedCipherText, err := base64.StdEncoding.DecodeString(text)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "加密文本格式错误", "details": err.Error()})
			return
		}

		// 调用解密函数
		decryptedText, err := publickey.RsaDecrypt(decodedCipherText, []byte(privateKey))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "解密失败", "details": err.Error()})
			return
		}

		// 返回解密结果
		c.JSON(http.StatusOK, gin.H{"result": string(decryptedText)})

	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的操作类型"})
	}
}

func GenerateRSAKey(c *gin.Context) {
	privateKeyPEM, publicKeyPEM, privateKeyBase64, publicKeyBase64, err := publickey.GenerateRSAKeyPair()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成密钥对失败", "details": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"privateKeyPEM":    privateKeyPEM,
		"publicKeyPEM":     publicKeyPEM,
		"privateKeyBase64": privateKeyBase64,
		"publicKeyBase64":  publicKeyBase64,
	})
}

func ECC160Handler(c *gin.Context) {
	action := c.PostForm("action")
	text := c.PostForm("text")
	publicKey := c.PostForm("publicKey")
	privateKey := c.PostForm("privateKey")
	curveType := c.PostForm("curve") // 获取曲线类型

	var curve elliptic.Curve
	switch curveType {
	case "secp160r1":
		curve = secp160r1.P160()
	case "secp160r2":
		curve = secp160r2.P160()
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的曲线类型"})
		return
	}

	switch action {
	case "encrypt":
		if text == "" || publicKey == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "加密需要文本和公钥"})
			return
		}

		// 调用加密函数
		encryptedText, err := publickey.EccEncrypt(curve, []byte(text), publicKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "加密失败", "details": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"result": base64.StdEncoding.EncodeToString(encryptedText)})

	case "decrypt":
		if text == "" || privateKey == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "解密需要文本和私钥"})
			return
		}

		// 解码加密文本
		decodedCipherText, err := base64.StdEncoding.DecodeString(text)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "加密文本格式错误", "details": err.Error()})
			return
		}

		// 调用解密函数
		decryptedText, err := publickey.EccDecrypt(curve, decodedCipherText, privateKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "解密失败", "details": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"result": string(decryptedText)})

	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的操作类型"})
	}
}

func GenerateECC160Key(c *gin.Context) {
	curveType := c.PostForm("curve") // 获取曲线类型

	var curve elliptic.Curve
	switch curveType {
	case "secp160r1":
		curve = secp160r1.P160()
	case "secp160r2":
		curve = secp160r2.P160()
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的曲线类型"})
		return
	}

	// 调用生成密钥对函数
	privateKey, publicKeyX, publicKeyY, err := publickey.GenerateECCKeyPair(curve)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成密钥对失败", "details": err.Error()})
		return
	}

	// 序列化公钥为 Base64 格式
	publicKey := elliptic.Marshal(curve, publicKeyX, publicKeyY)
	publicKeyBase64 := base64.StdEncoding.EncodeToString(publicKey)

	// 序列化私钥为 Base64 格式
	privateKeyBase64 := base64.StdEncoding.EncodeToString(privateKey)

	// 返回结果
	c.JSON(http.StatusOK, gin.H{
		"privateKeyBase64": privateKeyBase64,
		"publicKeyBase64":  publicKeyBase64,
	})
}

// RSASHA1Handler 处理 RSA-SHA1 签名和验签请求
func RSASHA1Handler(c *gin.Context) {
	action := c.PostForm("action")
	text := c.PostForm("text")
	privateKey := c.PostForm("privateKey")
	publicKey := c.PostForm("publicKey")

	switch action {
	case "sign":
		// 签名逻辑
		signature, err := publickey.SignRSASHA1([]byte(text), privateKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("签名失败: %v", err)})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "签名成功", "signature": base64.StdEncoding.EncodeToString(signature)})

	case "verify":
		// 从请求体中读取签名数据
		signatureBase64 := c.PostForm("signature")
		if signatureBase64 == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "签名数据不能为空"})
			return
		}

		// 解码签名数据
		signature, err := base64.StdEncoding.DecodeString(signatureBase64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "签名数据格式错误", "details": err.Error()})
			return
		}

		// 验签逻辑
		isValid, err := publickey.VerifyRSASHA1([]byte(text), signature, publicKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("验签失败: %v", err)})
			return
		}

		// 返回验签结果
		if isValid {
			c.JSON(http.StatusOK, gin.H{"message": "验签成功"})
		} else {
			c.JSON(http.StatusOK, gin.H{"message": "验签失败"})
		}

	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的操作类型"})
	}
}

func ECDSAHandler(c *gin.Context) {
	action := c.PostForm("action")
	text := c.PostForm("text")
	privateKey := c.PostForm("privateKey")
	publicKey := c.PostForm("publicKey")
	curveName := c.PostForm("curve")

	// 根据曲线名称选择椭圆曲线
	var curve elliptic.Curve
	switch curveName {
	case "P224":
		curve = elliptic.P224()
	case "P256":
		curve = elliptic.P256()
	case "P384":
		curve = elliptic.P384()
	case "P521":
		curve = elliptic.P521()
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的曲线名称"})
		return
	}

	switch action {
	case "sign":
		// 签名逻辑
		signature, err := publickey.SignECDSA([]byte(text), privateKey, curve)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("签名失败: %v", err)})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "签名成功", "signature": base64.StdEncoding.EncodeToString(signature)})

	case "verify":
		// 从请求体中读取签名数据
		signatureBase64 := c.PostForm("signature")
		if signatureBase64 == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "签名数据不能为空"})
			return
		}

		// 解码签名数据
		signature, err := base64.StdEncoding.DecodeString(signatureBase64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "签名数据格式错误", "details": err.Error()})
			return
		}

		// 验签逻辑
		isValid, err := publickey.VerifyECDSA([]byte(text), signature, publicKey, curve)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("验签失败: %v", err)})
			return
		}

		// 返回验签结果
		if isValid {
			c.JSON(http.StatusOK, gin.H{"message": "验签成功"})
		} else {
			c.JSON(http.StatusOK, gin.H{"message": "验签失败"})
		}

	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的操作类型"})
	}
}

func GenerateECDSAKey(c *gin.Context) {
	curveName := c.PostForm("curve")

	// 根据曲线名称选择椭圆曲线
	var curve elliptic.Curve
	switch curveName {
	case "P224":
		curve = elliptic.P224()
	case "P256":
		curve = elliptic.P256()
	case "P384":
		curve = elliptic.P384()
	case "P521":
		curve = elliptic.P521()
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的曲线名称"})
		return
	}

	// 生成密钥对
	privateKey, publicKeyX, publicKeyY, err := publickey.GenerateECDSAKey(curve)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("密钥生成失败: %v", err)})
		return
	}

	// 序列化密钥
	privateKeyBase64 := base64.StdEncoding.EncodeToString(privateKey)
	publicKey := elliptic.Marshal(curve, publicKeyX, publicKeyY)
	publicKeyBase64 := base64.StdEncoding.EncodeToString(publicKey)

	// 返回结果
	c.JSON(http.StatusOK, gin.H{
		"privateKeyBase64": privateKeyBase64,
		"publicKeyBase64":  publicKeyBase64,
	})
}
