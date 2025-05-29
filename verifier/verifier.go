package verifier

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
)

// Verifier 验证器结构体
type Verifier struct {
	publicKey *ecdsa.PublicKey
	mu        sync.RWMutex
}

// NewVerifierFromPEMFile 从PEM文件创建验证器
func NewVerifierFromPEMFile(publicKeyPath string) (*Verifier, error) {
	// 读取公钥文件
	publicKeyPEM, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, err
	}

	// 解码PEM格式
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, errors.New("无法解码PEM格式")
	}

	var ecdsaPub *ecdsa.PublicKey

	switch block.Type {
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		var ok bool
		ecdsaPub, ok = cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("证书不是ECDSA公钥")
		}
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		var ok bool
		ecdsaPub, ok = pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("公钥不是ECDSA类型")
		}
	default:
		return nil, errors.New("不支持的PEM类型: " + block.Type)
	}

	return &Verifier{
		publicKey: ecdsaPub,
	}, nil
}

// VerifyString 验证字符串签名
func (v *Verifier) VerifyString(data, signature string) error {
	// 添加填充字符
	signature = addPadding(signature)

	// 解码签名
	sigBytes, err := base64.URLEncoding.DecodeString(signature)
	if err != nil {
		return err
	}

	// 计算数据的SHA256哈希
	hash := sha256.Sum256([]byte(data))

	// 使用ASN.1格式验证签名
	if !ecdsa.VerifyASN1(v.publicKey, hash[:], sigBytes) {
		return errors.New("签名验证失败")
	}

	return nil
}

// VerifyFile 验证文件签名
func (v *Verifier) VerifyFile(filePath, signature string) error {
	// 加锁保护文件读取
	v.mu.Lock()
	defer v.mu.Unlock()

	// 添加填充字符
	signature = addPadding(signature)

	// 解码签名
	sigBytes, err := base64.URLEncoding.DecodeString(signature)
	if err != nil {
		return err
	}

	// 打开文件
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// 计算文件的SHA256哈希
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}

	// 使用ASN.1格式验证签名
	if !ecdsa.VerifyASN1(v.publicKey, hash.Sum(nil), sigBytes) {
		return errors.New("签名验证失败")
	}

	return nil
}

// addPadding 添加Base64填充字符
func addPadding(s string) string {
	// 计算需要添加的填充字符数量
	padding := 4 - (len(s) % 4)
	if padding == 4 {
		return s
	}
	return s + strings.Repeat("=", padding)
}
