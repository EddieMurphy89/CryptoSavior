package handlers

import (
	"CryptoSavior/handlers/symmetric"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/gin-gonic/gin"
	"net/http"
	"strconv"
)

// 将密钥或 IV 转换为 Hex 格式
func convertToHex(input, format string) ([]byte, error) {
	switch format {
	case "UTF8", "Latin1":
		return []byte(input), nil
	case "Base64":
		return base64.StdEncoding.DecodeString(input)
	default:
		return nil, errors.New("unsupported format")
	}
}

func AESHandler(c *gin.Context) {
	mode := c.PostForm("mode")
	text := c.PostForm("text")
	key := c.PostForm("key")
	keylength := c.PostForm("keylength")
	iv := c.PostForm("iv")
	keyformat := c.PostForm("keyFormat")
	ivformat := c.PostForm("ivFormat")
	inputFormat := c.PostForm("inputFormat")
	outputFormat := c.PostForm("outputFormat")
	action := c.PostForm("action")

	var result string
	var err error
	var keyHex []byte
	var ivHex []byte

	// 转换密钥
	if keyformat == "Hex" {
		keyHex, err = hex.DecodeString(key)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Hex key"})
			return
		}
	} else {
		keyHex, err = convertToHex(key, keyformat)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid key format"})
			return
		}
	}

	// 转换 IV
	if ivformat == "Hex" {
		ivHex, err = hex.DecodeString(iv)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Hex IV"})
			return
		}
	} else {
		ivHex, err = convertToHex(iv, ivformat)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid IV format"})
			return
		}
	}

	// 将 keylength 转换为整数
	keyLen, err := strconv.Atoi(keylength)
	if err != nil || (keyLen != 128 && keyLen != 192 && keyLen != 256) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid key length"})
		return
	}

	config := symmetric.AESConfig{
		Key:          keyHex,
		KeyLength:    keyLen,
		IV:           ivHex,
		Mode:         mode,
		Nonce:        nil,
		AuthData:     nil,
		InputFormat:  inputFormat,
		OutputFormat: outputFormat,
	}

	if action == "encrypt" {
		result, err = symmetric.EncryptAES(config, text)
	} else if action == "decrypt" {
		result, err = symmetric.DecryptAES(config, text)
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid action"})
		return
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"result": result})
}

func SM4Handler(c *gin.Context) {
	mode := c.PostForm("mode")
	text := c.PostForm("text")
	key := c.PostForm("key")
	iv := c.PostForm("iv")
	keyformat := c.PostForm("keyFormat")
	ivformat := c.PostForm("ivFormat")
	inputFormat := c.PostForm("inputFormat")
	outputFormat := c.PostForm("outputFormat")
	action := c.PostForm("action")

	var result string
	var err error
	var keyHex []byte
	var ivHex []byte

	// 转换密钥
	if keyformat == "Hex" {
		keyHex, err = hex.DecodeString(key)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Hex key"})
			return
		}
	} else {
		keyHex, err = convertToHex(key, keyformat)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid key format"})
			return
		}
	}

	// 转换 IV
	if ivformat == "Hex" {
		ivHex, err = hex.DecodeString(iv)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Hex IV"})
			return
		}
	} else {
		ivHex, err = convertToHex(iv, ivformat)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid IV format"})
			return
		}
	}

	config := symmetric.SM4Config{
		Key:          keyHex,
		IV:           ivHex,
		Mode:         mode,
		InputFormat:  inputFormat,
		OutputFormat: outputFormat,
	}

	if action == "encrypt" {
		result, err = symmetric.EncryptSM4(config, text)
	} else if action == "decrypt" {
		result, err = symmetric.DecryptSM4(config, text)
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid action"})
		return
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"result": result})
}

func RC6Handler(c *gin.Context) {
	mode := c.PostForm("mode")
	text := c.PostForm("text")
	key := c.PostForm("key")
	iv := c.PostForm("iv")
	keyformat := c.PostForm("keyFormat")
	ivformat := c.PostForm("ivFormat")
	inputFormat := c.PostForm("inputFormat")
	outputFormat := c.PostForm("outputFormat")
	action := c.PostForm("action")

	var result string
	var err error
	var keyHex []byte
	var ivHex []byte

	// 转换密钥
	if keyformat == "Hex" {
		keyHex, err = hex.DecodeString(key)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Hex key"})
			return
		}
	} else {
		keyHex, err = convertToHex(key, keyformat)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid key format"})
			return
		}
	}

	rc6 := symmetric.NewRC6Encryption(keyHex, 20, 32, 5)

	// 转换 IV（仅在 CBC 模式下需要）
	if mode == "CBC" {
		if ivformat == "Hex" {
			ivHex, err = hex.DecodeString(iv)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Hex IV"})
				return
			}
		} else {
			ivHex, err = convertToHex(iv, ivformat)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid IV format"})
				return
			}
		}
	}

	if action == "encrypt" {

		var plaintextBytes []byte
		if inputFormat == "Hex" {
			plaintextBytes, err = hex.DecodeString(text)
		} else {
			plaintextBytes = []byte(text)
		}

		var encrypted []byte
		if mode == "ECB" {
			encrypted = rc6.EncryptECB(plaintextBytes)
		} else if mode == "CBC" {
			encrypted = rc6.EncryptCBC(plaintextBytes, ivHex)
		}

		result = string(encrypted)

		if outputFormat == "Hex" {
			result = hex.EncodeToString(encrypted)
		}

	} else if action == "decrypt" {

		var ciphertextBytes []byte
		if inputFormat == "Hex" {
			ciphertextBytes, err = hex.DecodeString(text)
		} else {
			ciphertextBytes = []byte(text)
		}

		var decrypted []byte
		if mode == "ECB" {
			decrypted, _ = rc6.DecryptECB(ciphertextBytes)
		} else if mode == "CBC" {
			decrypted, _ = rc6.DecryptCBC(ciphertextBytes, ivHex)
		}

		result = string(decrypted)

		if outputFormat == "Hex" {
			result = hex.EncodeToString(decrypted)
		}
		
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid action"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"result": result})
}
