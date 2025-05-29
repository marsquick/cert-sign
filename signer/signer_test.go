package signer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/marsquick/cert-sign/verifier"
)

// 生成测试用的ECC密钥对
func generateTestKeyPair(t *testing.T) (privateKeyPath, publicKeyPath string) {
	// 生成私钥
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatalf("生成私钥失败: %v", err)
	}

	// 将私钥编码为PEM格式
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("编码私钥失败: %v", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// 创建私钥临时文件
	privateKeyFile, err := os.CreateTemp("", "private_key_*.pem")
	if err != nil {
		t.Fatalf("创建私钥临时文件失败: %v", err)
	}
	defer privateKeyFile.Close()

	// 写入私钥
	if _, err := privateKeyFile.Write(privateKeyPEM); err != nil {
		t.Fatalf("写入私钥失败: %v", err)
	}

	// 将公钥编码为PEM格式
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("编码公钥失败: %v", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	// 创建公钥临时文件
	publicKeyFile, err := os.CreateTemp("", "public_key_*.pem")
	if err != nil {
		t.Fatalf("创建公钥临时文件失败: %v", err)
	}
	defer publicKeyFile.Close()

	// 写入公钥
	if _, err := publicKeyFile.Write(publicKeyPEM); err != nil {
		t.Fatalf("写入公钥失败: %v", err)
	}

	return privateKeyFile.Name(), publicKeyFile.Name()
}

func TestNewSignerFromPEMFile(t *testing.T) {
	privateKeyPath, _ := generateTestKeyPair(t)

	// 创建签名器
	s, err := NewSignerFromPEMFile(privateKeyPath)
	if err != nil {
		t.Fatalf("创建签名器失败: %v", err)
	}

	// 验证私钥是否正确加载
	if s.privateKey == nil {
		t.Fatal("私钥未正确加载")
	}
}

func TestSignString(t *testing.T) {
	privateKeyPath, _ := generateTestKeyPair(t)

	// 创建签名器
	s, err := NewSignerFromPEMFile(privateKeyPath)
	if err != nil {
		t.Fatalf("创建签名器失败: %v", err)
	}

	// 测试数据
	testData := []string{
		"Hello, World!",
		"这是一个很长的测试字符串，用来验证不同长度的输入是否会产生相同长度的签名。",
		"短",
	}

	for _, data := range testData {
		// 签名
		signature, err := s.SignString(data)
		if err != nil {
			t.Fatalf("签名字符串失败: %v", err)
		}

		// 打印测试数据
		t.Logf("测试数据: %s", data)
		t.Logf("数据长度: %d 字节", len(data))
		t.Logf("签名结果: %s", signature)
		t.Logf("签名长度: %d 字符", len(signature))
		t.Logf("---")

		// 验证签名不为空
		if signature == "" {
			t.Fatal("签名为空")
		}

		// 验证签名长度（URL安全的Base64编码，无填充）
		// ASN.1 格式的 ECDSA P-256 签名长度约为 70-72 字节，编码后约为 94-96 字符
		if len(signature) < 94 || len(signature) > 96 {
			t.Fatalf("签名长度不正确: %d，期望: 94-96", len(signature))
		}
	}
}

func TestSignFile(t *testing.T) {
	privateKeyPath, _ := generateTestKeyPair(t)

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

	// 打印测试数据
	t.Logf("测试文件内容: %s", string(testData))
	t.Logf("文件大小: %d 字节", len(testData))
	t.Logf("签名结果: %s", signature)
	t.Logf("签名长度: %d 字符", len(signature))
	t.Logf("---")

	// 验证签名不为空
	if signature == "" {
		t.Fatal("签名为空")
	}

	// 验证签名长度（URL安全的Base64编码，无填充）
	// ASN.1 格式的 ECDSA P-256 签名长度约为 70-72 字节，编码后约为 94-96 字符
	if len(signature) < 94 || len(signature) > 96 {
		t.Fatalf("签名长度不正确: %d，期望: 94-96", len(signature))
	}
}

func TestConcurrentSigning(t *testing.T) {
	privateKeyPath, _ := generateTestKeyPair(t)

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
	privateKeyPath, _ := generateTestKeyPair(&testing.T{})
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
	privateKeyPath, _ := generateTestKeyPair(&testing.T{})
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

func TestMassiveSigningAndVerifying(t *testing.T) {
	privateKeyPath, publicKeyPath := generateTestKeyPair(t)

	// 创建签名器
	s, err := NewSignerFromPEMFile(privateKeyPath)
	if err != nil {
		t.Fatalf("创建签名器失败: %v", err)
	}

	// 创建验证器（用 verifier 包）
	v, err := verifier.NewVerifierFromPEMFile(publicKeyPath)
	if err != nil {
		t.Fatalf("创建验证器失败: %v", err)
	}

	// 生成随机字符串的函数
	generateRandomString := func(length int) string {
		const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		b := make([]byte, length)
		for i := range b {
			b[i] = charset[rand.Intn(len(charset))]
		}
		return string(b)
	}

	// 测试次数
	testCount := 10_000_000
	successCount := 0
	errorCount := 0

	// 记录开始时间
	startTime := time.Now()

	// 每100万次打印一次进度
	progressInterval := 1_000_000

	for i := 0; i < testCount; i++ {
		// 生成随机长度的字符串（1-1000字符）
		randomLength := rand.Intn(1000) + 1
		data := generateRandomString(randomLength)

		// 签名
		signature, err := s.SignString(data)
		if err != nil {
			t.Logf("签名失败 [%d]: %v", i, err)
			errorCount++
			continue
		}

		// 用 verifier 包验证签名
		err = v.VerifyString(data, signature)
		if err != nil {
			t.Logf("验证失败 [%d]: %v", i, err)
			errorCount++
			continue
		}

		successCount++

		// 打印进度
		if (i+1)%progressInterval == 0 {
			elapsed := time.Since(startTime)
			rate := float64(i+1) / elapsed.Seconds()
			t.Logf("进度: %d/%d (%.2f%%) - 成功率: %.2f%% - 速度: %.2f 次/秒",
				i+1, testCount,
				float64(i+1)*100/float64(testCount),
				float64(successCount)*100/float64(i+1),
				rate)
		}
	}

	// 打印最终结果
	elapsed := time.Since(startTime)
	t.Logf("\n测试完成:")
	t.Logf("总测试次数: %d", testCount)
	t.Logf("成功次数: %d", successCount)
	t.Logf("失败次数: %d", errorCount)
	t.Logf("总耗时: %v", elapsed)
	t.Logf("平均速度: %.2f 次/秒", float64(testCount)/elapsed.Seconds())

	// 验证成功率
	if errorCount > 0 {
		t.Fatalf("测试过程中出现错误，错误次数: %d", errorCount)
	}
}
