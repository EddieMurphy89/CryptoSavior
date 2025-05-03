package hash

import (
	"errors"
	"github.com/C0MM4ND/go-ripemd"
	"hash"
	"strings"
)

// GetRIPEMDHasher 根据类型返回对应的哈希函数
func GetRIPEMDHasher(hashType string) (hash.Hash, error) {
	switch strings.ToUpper(hashType) {
	case "RIPEMD-128":
		return ripemd.New128(), nil
	case "RIPEMD-160":
		return ripemd.New160(), nil
	case "RIPEMD-256":
		return ripemd.New256(), nil
	case "RIPEMD-320":
		return ripemd.New320(), nil
	default:
		return nil, errors.New("不支持的 RIPEMD 类型")
	}
}
