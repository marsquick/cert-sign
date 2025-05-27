package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// 生成测试用的ECC密钥对和证书
func generateTestKeyPair(t *testing.T) (publicKeyPath string, privateKey *ecdsa.PrivateKey) {
	// 生成私钥
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成私钥失败: %v", err)
	}

	// 创建证书模板
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// 创建证书
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("创建证书失败: %v", err)
	}

	// 将证书转换为PEM格式
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	// 创建临时文件
	publicKeyPath = filepath.Join(t.TempDir(), "cert.pem")

	// 写入证书文件
	if err := os.WriteFile(publicKeyPath, certPEM, 0644); err != nil {
		t.Fatalf("写入证书文件失败: %v", err)
	}

	return publicKeyPath, privateKey
}

func TestNewVerifierFromPEMFile(t *testing.T) {
	publicKeyPath, _ := generateTestKeyPair(t)

	// 测试从文件创建验证器
	verifier, err := NewVerifierFromPEMFile(publicKeyPath)
	if err != nil {
		t.Fatalf("创建验证器失败: %v", err)
	}
	if verifier == nil {
		t.Fatal("验证器为空")
	}
}

func TestVerifyString(t *testing.T) {
	publicKeyPath, privateKey := generateTestKeyPair(t)

	// 创建验证器
	v, err := NewVerifierFromPEMFile(publicKeyPath)
	if err != nil {
		t.Fatalf("创建验证器失败: %v", err)
	}

	// 测试数据
	data := "Hello, World!"

	// 签名
	hash := sha256.Sum256([]byte(data))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}

	// 组合签名
	signature := append(r.Bytes(), s.Bytes()...)
	encoded := base64.URLEncoding.EncodeToString(signature)
	encoded = strings.TrimRight(encoded, "=")

	// 验证签名
	err = v.VerifyString(data, encoded)
	if err != nil {
		t.Fatalf("验证签名失败: %v", err)
	}

	// 测试错误数据
	err = v.VerifyString(data+"invalid", encoded)
	if err == nil {
		t.Fatal("验证应该失败")
	}
}

func TestVerifyFile(t *testing.T) {
	publicKeyPath, privateKey := generateTestKeyPair(t)

	// 创建验证器
	v, err := NewVerifierFromPEMFile(publicKeyPath)
	if err != nil {
		t.Fatalf("创建验证器失败: %v", err)
	}

	// 创建测试文件
	testData := []byte("Hello, World!")
	testFile := filepath.Join(t.TempDir(), "test.txt")
	if err := os.WriteFile(testFile, testData, 0644); err != nil {
		t.Fatalf("创建测试文件失败: %v", err)
	}

	// 签名
	hash := sha256.New()
	hash.Write(testData)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash.Sum(nil))
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}

	// 组合签名
	signature := append(r.Bytes(), s.Bytes()...)
	encoded := base64.URLEncoding.EncodeToString(signature)
	encoded = strings.TrimRight(encoded, "=")

	// 验证签名
	err = v.VerifyFile(testFile, encoded)
	if err != nil {
		t.Fatalf("验证签名失败: %v", err)
	}

	// 测试错误数据
	if err := os.WriteFile(testFile, []byte("invalid data"), 0644); err != nil {
		t.Fatalf("修改测试文件失败: %v", err)
	}
	err = v.VerifyFile(testFile, encoded)
	if err == nil {
		t.Fatal("验证应该失败")
	}
}

func TestConcurrentVerification(t *testing.T) {
	publicKeyPath, privateKey := generateTestKeyPair(t)

	// 创建验证器
	v, err := NewVerifierFromPEMFile(publicKeyPath)
	if err != nil {
		t.Fatalf("创建验证器失败: %v", err)
	}

	// 创建测试文件
	testData := []byte("Hello, World!")
	testFile := filepath.Join(t.TempDir(), "test.txt")
	if err := os.WriteFile(testFile, testData, 0644); err != nil {
		t.Fatalf("创建测试文件失败: %v", err)
	}

	// 生成签名
	hash := sha256.New()
	hash.Write(testData)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash.Sum(nil))
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}

	// 组合签名
	signature := append(r.Bytes(), s.Bytes()...)
	encoded := base64.URLEncoding.EncodeToString(signature)
	encoded = strings.TrimRight(encoded, "=")

	// 并发测试
	var wg sync.WaitGroup
	concurrentCount := 10
	errors := make(chan error, concurrentCount*2)

	// 并发验证字符串
	for i := 0; i < concurrentCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := v.VerifyString("Hello, World!", encoded)
			errors <- err
		}()
	}

	// 并发验证文件
	for i := 0; i < concurrentCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := v.VerifyFile(testFile, encoded)
			errors <- err
		}()
	}

	// 等待所有goroutine完成
	wg.Wait()
	close(errors)

	// 验证所有结果
	for err := range errors {
		if err != nil {
			t.Errorf("验证失败: %v", err)
		}
	}
}

func BenchmarkVerifyString(b *testing.B) {
	publicKeyPath, privateKey := generateTestKeyPair(&testing.T{})
	v, err := NewVerifierFromPEMFile(publicKeyPath)
	if err != nil {
		b.Fatalf("创建验证器失败: %v", err)
	}
	data := "Hello, World!"
	hash := sha256.Sum256([]byte(data))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		b.Fatalf("签名失败: %v", err)
	}
	signature := append(r.Bytes(), s.Bytes()...)
	encoded := base64.URLEncoding.EncodeToString(signature)
	encoded = strings.TrimRight(encoded, "=")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := v.VerifyString(data, encoded)
		if err != nil {
			b.Fatalf("验签失败: %v", err)
		}
	}
}

func BenchmarkVerifyFile(b *testing.B) {
	publicKeyPath, privateKey := generateTestKeyPair(&testing.T{})
	v, err := NewVerifierFromPEMFile(publicKeyPath)
	if err != nil {
		b.Fatalf("创建验证器失败: %v", err)
	}
	testData := []byte("Hello, World! This is a file for benchmark testing.")
	testFile := filepath.Join(b.TempDir(), "bench.txt")
	if err := os.WriteFile(testFile, testData, 0644); err != nil {
		b.Fatalf("创建测试文件失败: %v", err)
	}
	hash := sha256.New()
	hash.Write(testData)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash.Sum(nil))
	if err != nil {
		b.Fatalf("签名失败: %v", err)
	}
	signature := append(r.Bytes(), s.Bytes()...)
	encoded := base64.URLEncoding.EncodeToString(signature)
	encoded = strings.TrimRight(encoded, "=")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := v.VerifyFile(testFile, encoded)
		if err != nil {
			b.Fatalf("验签失败: %v", err)
		}
	}
}
