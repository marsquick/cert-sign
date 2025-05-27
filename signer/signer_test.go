package signer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// 生成测试用的ECC密钥对
func generateTestKeyPair(t *testing.T) (privateKeyPath string) {
	// 生成私钥
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成私钥失败: %v", err)
	}

	// 将私钥转换为PEM格式
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("序列化私钥失败: %v", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// 创建临时文件
	privateKeyPath = filepath.Join(t.TempDir(), "private.pem")

	// 写入私钥文件
	if err := os.WriteFile(privateKeyPath, privateKeyPEM, 0600); err != nil {
		t.Fatalf("写入私钥文件失败: %v", err)
	}

	return privateKeyPath
}

func TestNewSignerFromPEMFile(t *testing.T) {
	privateKeyPath := generateTestKeyPair(t)

	// 测试从文件创建签名器
	signer, err := NewSignerFromPEMFile(privateKeyPath)
	if err != nil {
		t.Fatalf("创建签名器失败: %v", err)
	}
	if signer == nil {
		t.Fatal("签名器为空")
	}
}

func TestSignString(t *testing.T) {
	privateKeyPath := generateTestKeyPair(t)

	// 创建签名器
	s, err := NewSignerFromPEMFile(privateKeyPath)
	if err != nil {
		t.Fatalf("创建签名器失败: %v", err)
	}

	// 测试数据
	data := "Hello, World!"

	// 签名
	signature, err := s.SignString(data)
	if err != nil {
		t.Fatalf("签名字符串失败: %v", err)
	}

	// 验证签名不为空
	if signature == "" {
		t.Fatal("签名为空")
	}

	// 验证签名长度（URL安全的Base64编码，无填充）
	if len(signature) != 86 { // 64字节的签名编码后应该是86个字符
		t.Fatalf("签名长度不正确: %d", len(signature))
	}
}

func TestSignFile(t *testing.T) {
	privateKeyPath := generateTestKeyPair(t)

	// 创建签名器
	s, err := NewSignerFromPEMFile(privateKeyPath)
	if err != nil {
		t.Fatalf("创建签名器失败: %v", err)
	}

	// 创建测试文件
	testData := []byte("Hello, World!")
	testFile := filepath.Join(t.TempDir(), "test.txt")
	if err := os.WriteFile(testFile, testData, 0644); err != nil {
		t.Fatalf("创建测试文件失败: %v", err)
	}

	// 签名
	signature, err := s.SignFile(testFile)
	if err != nil {
		t.Fatalf("签名文件失败: %v", err)
	}

	// 验证签名不为空
	if signature == "" {
		t.Fatal("签名为空")
	}

	// 验证签名长度（URL安全的Base64编码，无填充）
	if len(signature) != 86 { // 64字节的签名编码后应该是86个字符
		t.Fatalf("签名长度不正确: %d", len(signature))
	}
}

func TestConcurrentSigning(t *testing.T) {
	privateKeyPath := generateTestKeyPair(t)

	// 创建签名器
	s, err := NewSignerFromPEMFile(privateKeyPath)
	if err != nil {
		t.Fatalf("创建签名器失败: %v", err)
	}

	// 创建测试文件
	testData := []byte("Hello, World!")
	testFile := filepath.Join(t.TempDir(), "test.txt")
	if err := os.WriteFile(testFile, testData, 0644); err != nil {
		t.Fatalf("创建测试文件失败: %v", err)
	}

	// 并发测试
	var wg sync.WaitGroup
	concurrentCount := 10
	results := make(chan string, concurrentCount*2)

	// 并发签名字符串
	for i := 0; i < concurrentCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			signature, err := s.SignString("Hello, World!")
			if err != nil {
				t.Errorf("并发签名字符串失败: %v", err)
				return
			}
			results <- signature
		}()
	}

	// 并发签名文件
	for i := 0; i < concurrentCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			signature, err := s.SignFile(testFile)
			if err != nil {
				t.Errorf("并发签名文件失败: %v", err)
				return
			}
			results <- signature
		}()
	}

	// 等待所有goroutine完成
	wg.Wait()
	close(results)

	// 验证所有签名
	signatures := make(map[string]bool)
	for signature := range results {
		if signature == "" {
			t.Error("收到空签名")
			continue
		}
		// if len(signature) != 86 {
		// 	t.Errorf("签名长度不正确: %d", len(signature))
		// 	continue
		// }
		signatures[signature] = true
	}

	// 验证签名数量
	if len(signatures) != concurrentCount*2 {
		t.Errorf("签名数量不正确: %d", len(signatures))
	}
}

func BenchmarkSignString(b *testing.B) {
	privateKeyPath := generateTestKeyPair(&testing.T{})
	s, err := NewSignerFromPEMFile(privateKeyPath)
	if err != nil {
		b.Fatalf("创建签名器失败: %v", err)
	}
	data := "Hello, World!"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := s.SignString(data)
		if err != nil {
			b.Fatalf("签名字符串失败: %v", err)
		}
	}
}

func BenchmarkSignFile(b *testing.B) {
	privateKeyPath := generateTestKeyPair(&testing.T{})
	s, err := NewSignerFromPEMFile(privateKeyPath)
	if err != nil {
		b.Fatalf("创建签名器失败: %v", err)
	}
	testData := []byte("Hello, World! This is a file for benchmark testing.")
	testFile := filepath.Join(b.TempDir(), "bench.txt")
	if err := os.WriteFile(testFile, testData, 0644); err != nil {
		b.Fatalf("创建测试文件失败: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := s.SignFile(testFile)
		if err != nil {
			b.Fatalf("签名文件失败: %v", err)
		}
	}
}
