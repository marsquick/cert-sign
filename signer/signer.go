package signer

import (
	"crypto/ecdsa"
	"crypto/rand"
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

// Signer 签名器结构体
type Signer struct {
	privateKey *ecdsa.PrivateKey
	mu         sync.RWMutex // 用于保护文件操作
}

// NewSignerFromPEMFile 从PEM文件创建签名器
func NewSignerFromPEMFile(privateKeyPath string) (*Signer, error) {
	// 读取私钥文件
	privateKeyPEM, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, err
	}

	// 解码PEM格式
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, errors.New("无法解码PEM格式")
	}

	// 解析私钥
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &Signer{
		privateKey: privateKey,
	}, nil
}

// SignString 对字符串进行签名
func (s *Signer) SignString(data string) (string, error) {
	// 计算数据的SHA256哈希
	hash := sha256.Sum256([]byte(data))

	// 使用ECDSA进行签名
	r, s_, err := ecdsa.Sign(rand.Reader, s.privateKey, hash[:])
	if err != nil {
		return "", err
	}

	// 将r和s组合成签名
	signature := append(r.Bytes(), s_.Bytes()...)

	// 使用URL安全的Base64编码
	encoded := base64.URLEncoding.EncodeToString(signature)
	// 移除末尾的填充字符
	encoded = strings.TrimRight(encoded, "=")

	return encoded, nil
}

// SignFile 对文件进行签名
func (s *Signer) SignFile(filePath string) (string, error) {
	// 加锁保护文件读取
	s.mu.Lock()
	defer s.mu.Unlock()

	// 打开文件
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// 计算文件的SHA256哈希
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	// 使用ECDSA进行签名
	r, s_, err := ecdsa.Sign(rand.Reader, s.privateKey, hash.Sum(nil))
	if err != nil {
		return "", err
	}

	// r, s 补齐为32字节
	rBytes := r.Bytes()
	sBytes := s_.Bytes()
	if len(rBytes) < 32 {
		pad := make([]byte, 32-len(rBytes))
		rBytes = append(pad, rBytes...)
	}
	if len(sBytes) < 32 {
		pad := make([]byte, 32-len(sBytes))
		sBytes = append(pad, sBytes...)
	}

	// 将r和s组合成签名
	signature := append(rBytes, sBytes...)

	// 使用URL安全的Base64编码
	encoded := base64.URLEncoding.EncodeToString(signature)
	// 移除末尾的填充字符
	encoded = strings.TrimRight(encoded, "=")

	return encoded, nil
}
