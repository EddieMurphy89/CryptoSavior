package main

import (
	"CryptoSavior/handlers"
	"github.com/gin-gonic/gin"
	"net/http"
)

func main() {
	r := gin.Default()

	// 加载模板文件
	r.LoadHTMLGlob("templates/*")
	r.Static("/img", "./img")

	// 首页路由
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})

	// 对称密码算法路由
	r.GET("/symmetric", func(c *gin.Context) {
		c.HTML(http.StatusOK, "symmetric.html", nil)
	})
	r.POST("/aes", handlers.AESHandler)
	r.POST("/sm4", handlers.SM4Handler)
	r.POST("/rc6", handlers.RC6Handler)

	// 哈希算法路由
	r.GET("/hash", func(c *gin.Context) {
		c.HTML(http.StatusOK, "hash.html", nil)
	})
	r.POST("/sha", handlers.SHAHandler)
	r.POST("/md5", handlers.MD5Handler)
	r.POST("/hmac", handlers.HMACHandler)
	r.POST("/ripemd", handlers.RIPEMDHandler)
	r.POST("/pbkdf2", handlers.PBKDF2Handler)

	// 编码算法路由
	r.GET("/encoding", func(c *gin.Context) {
		c.HTML(http.StatusOK, "encoding.html", nil)
	})
	r.POST("/base32", handlers.Base32Handler)
	r.POST("/base58", handlers.Base58Handler)
	r.POST("/base64", handlers.Base64Handler)
	r.POST("/hex", handlers.HexHandler)
	r.POST("/rot13", handlers.Rot13Handler)
	r.POST("/unicode", handlers.UnicodeHandler)
	r.POST("/url", handlers.URLHandler)
	r.POST("/utf8", handlers.UTF8Handler)
	r.POST("/hex4base64", handlers.Hex4Base64Handler)

	// 公钥密码算法路由
	r.GET("/publickey", func(c *gin.Context) {
		c.HTML(http.StatusOK, "publickey.html", nil)
	})
	r.POST("/rsa1024", handlers.RSA1024Handler)
	r.POST("/generate_rsa", handlers.GenerateRSAKey)
	r.POST("/ecc160", handlers.ECC160Handler)
	r.POST("/generate_ecc160", handlers.GenerateECC160Key)
	r.POST("/rsaSha1", handlers.RSASHA1Handler)
	r.POST("/ecdsa", handlers.ECDSAHandler)
	r.POST("/generate_ecdsa", handlers.GenerateECDSAKey)

	// 启动服务
	r.Run(":8080")
}
