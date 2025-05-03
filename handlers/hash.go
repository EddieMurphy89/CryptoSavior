package handlers

import (
	"CryptoSavior/handlers/hash"
	"encoding/hex"
	"github.com/gin-gonic/gin"
	"net/http"
	"strconv"
)

// SHA 处理函数
func SHAHandler(c *gin.Context) {
	text := c.PostForm("text")
	hashTypes := []string{"SHA1", "SHA224", "SHA256", "SHA384", "SHA512"}

	results := make(map[string]string)
	for _, hashType := range hashTypes {
		result, err := hash.ComputeSHA(text, hashType)
		if err != nil {
			results[hashType] = "Error: " + err.Error()
		} else {
			results[hashType] = result
		}
	}

	c.JSON(http.StatusOK, gin.H{"results": results})
}

// MD5 处理函数
func MD5Handler(c *gin.Context) {
	text := c.PostForm("text")

	result, err := hash.ComputeMD5(text)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"result": result})
}

// HMAC 处理函数
func HMACHandler(c *gin.Context) {
	text := c.PostForm("text")
	key := c.PostForm("key")
	hmacType := c.PostForm("type")

	var result string
	var err error

	switch hmacType {
	case "HMAC-SHA":
		shaTypes := []string{"SHA1", "SHA224", "SHA256", "SHA384", "SHA512"}
		results := make(map[string]string)
		for _, shaType := range shaTypes {
			result, err = hash.ComputeHMACSHA(text, key, shaType)
			if err != nil {
				results["HMAC-"+shaType] = "Error: " + err.Error()
			} else {
				results["HMAC-"+shaType] = result
			}
		}
		c.JSON(http.StatusOK, gin.H{"results": results})
	case "HMAC-MD5":
		md5Types := []string{"lowercase", "uppercase"}
		results := make(map[string]string)
		for _, md5Type := range md5Types {
			result, err = hash.ComputeHMACMD5(text, key, md5Type)
			if err != nil {
				if md5Type == "lowercase" {
					results["HMAC-MD5 小写"] = "Error: " + err.Error()
				} else {
					results["HMAC-MD5 大写"] = "Error: " + err.Error()
				}
			} else {
				if md5Type == "lowercase" {
					results["HMAC-MD5 小写"] = result
				} else {
					results["HMAC-MD5 大写"] = result
				}
			}
		}
		c.JSON(http.StatusOK, gin.H{"results": results})
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unsupported HMAC type"})
	}
}

// RIPEMD 处理函数
func RIPEMDHandler(c *gin.Context) {
	// 从表单中获取参数
	text := c.PostForm("text")
	hashTypes := []string{"RIPEMD-128", "RIPEMD-160", "RIPEMD-256", "RIPEMD-320"}

	// 存储不同类型的哈希结果
	results := make(map[string]string)

	for _, hashType := range hashTypes {
		// 获取哈希函数
		hasher, err := hash.GetRIPEMDHasher(hashType)
		if err != nil {
			results[hashType] = "Error: " + err.Error()
			continue
		}

		// 计算哈希值
		hasher.Write([]byte(text))
		hashValue := hasher.Sum(nil)
		results[hashType] = hex.EncodeToString(hashValue)
	}

	// 返回结果
	c.JSON(http.StatusOK, gin.H{"results": results})
}

// PBKDF2 处理函数
func PBKDF2Handler(c *gin.Context) {
	// 从表单中获取参数
	text := c.PostForm("text")
	salt := c.PostForm("salt")
	iterationsStr := c.PostForm("iterations")
	keyLengthStr := c.PostForm("key")
	hashFunc := c.PostForm("hash")

	// 转换迭代次数为整数
	iterations, err := strconv.Atoi(iterationsStr)
	if err != nil || iterations <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的迭代次数"})
		return
	}

	// 根据选择的密钥长度设置字节数
	var keyLength int
	switch keyLengthStr {
	case "128":
		keyLength = 16 // 128 bits = 16 bytes
	case "256":
		keyLength = 32 // 256 bits = 32 bytes
	case "512":
		keyLength = 64 // 512 bits = 64 bytes
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的密钥长度"})
		return
	}

	// 调用 PBKDF2 加密函数
	result, err := hash.ComputePBKDF2(text, salt, iterations, keyLength, hashFunc)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 返回加密结果
	c.JSON(http.StatusOK, gin.H{"result": result})
}
