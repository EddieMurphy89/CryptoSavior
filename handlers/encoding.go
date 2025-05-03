package handlers

import (
	"CryptoSavior/handlers/encoding"
	"encoding/base64"
	"encoding/hex"
	"github.com/gin-gonic/gin"
	"net/http"
)

func Base32Handler(c *gin.Context) {
	action := c.PostForm("action") // "encode" 或 "decode"
	text := c.PostForm("text")     // 用户输入的文本

	var result string
	var err error

	if action == "encrypt" {
		result = encoding.Base32Encode(text)
	} else if action == "decrypt" {
		result, err = encoding.Base32Decode(text)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的操作类型"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"result": result})
}

func Base58Handler(c *gin.Context) {
	action := c.PostForm("action")
	text := c.PostForm("text")

	var result string
	var err error

	if action == "encrypt" {
		result = encoding.Base58Encode(text)
	} else if action == "decrypt" {
		result, err = encoding.Base58Decode(text)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的操作类型"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"result": result})
}

func Base64Handler(c *gin.Context) {
	action := c.PostForm("action")
	text := c.PostForm("text")

	var result string
	var err error

	if action == "encrypt" {
		result = encoding.Base64Encode(text)
	} else if action == "decrypt" {
		result, err = encoding.Base64Decode(text)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的操作类型"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"result": result})
}

func HexHandler(c *gin.Context) {
	action := c.PostForm("action")
	text := c.PostForm("text")

	var result string
	var err error

	if action == "encrypt" {
		result = encoding.HexEncode(text)
	} else if action == "decrypt" {
		result, err = encoding.HexDecode(text)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的操作类型"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"result": result})
}

func Rot13Handler(c *gin.Context) {
	// ROT13 的加解密逻辑可以直接复用，因为它是对称的
	text := c.PostForm("text")
	result := encoding.Rot13(text)
	c.JSON(http.StatusOK, gin.H{"result": result})
}

func UnicodeHandler(c *gin.Context) {
	action := c.PostForm("action")
	text := c.PostForm("text")

	var result string
	var err error

	if action == "encrypt" {
		result = encoding.UnicodeEncode(text)
	} else if action == "decrypt" {
		result, err = encoding.UnicodeDecode(text)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的操作类型"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"result": result})
}

func URLHandler(c *gin.Context) {
	action := c.PostForm("action")
	text := c.PostForm("text")

	var result string
	var err error

	if action == "encrypt" {
		result = encoding.URLEncode(text)
	} else if action == "decrypt" {
		result, err = encoding.URLDecode(text)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的操作类型"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"result": result})
}

func UTF8Handler(c *gin.Context) {
	action := c.PostForm("action")
	text := c.PostForm("text")

	var result string
	var err error

	if action == "encrypt" {
		result = encoding.UTF8Encode(text)
	} else if action == "decrypt" {
		result, err = encoding.UTF8Decode(text)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的操作类型"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"result": result})
}

func Hex4Base64Handler(c *gin.Context) {
	action := c.PostForm("action")
	text := c.PostForm("text")

	var result string
	var _ error

	if action == "hex2base64" {
		// Hex 转 Base64
		bytes, err := hex.DecodeString(text)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "无效的Hex字符串"})
			return
		}
		result = base64.StdEncoding.EncodeToString(bytes)
	} else if action == "base642hex" {
		// Base64 转 Hex
		bytes, err := base64.StdEncoding.DecodeString(text)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "无效的Base64字符串"})
			return
		}
		result = hex.EncodeToString(bytes)
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的操作类型"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"result": result})
}
