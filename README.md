# cert-sign

一个基于 ECDSA 的数字签名工具，支持字符串和文件的签名与验证。

## 特性

- 使用 ECDSA P-256 曲线进行签名
- 支持字符串和文件的签名与验证
- 支持 URL 安全的 Base64 编码签名
- 自动适配 X.509 证书和公钥格式
- 线程安全的实现
- 高性能的签名和验证

## 安装

```bash
go get github.com/marsquick/cert-sign
```

## 使用方法

### 1. 生成密钥对

使用 OpenSSL 生成 ECDSA 密钥对（推荐方式）：

```bash
# 方法1：使用 genpkey 命令（推荐）
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out private.key

# 方法2：使用 ecparam 命令
openssl ecparam -name prime256v1 -genkey -noout -out private.key

# 生成公钥
openssl ec -in private.key -pubout -out public.pem

# 生成自签名证书（可选）
openssl req -new -x509 -key private.key -out cert.pem -days 365 -subj "/CN=Test"
```

注意：请确保使用 `-noout` 参数生成私钥，以避免生成 EC PARAMETERS 格式的文件。

### 2. 签名

```go
package main

import (
    "fmt"
    "github.com/yourusername/cert-sign/signer"
)

func main() {
    // 创建签名器
    s, err := signer.NewSignerFromPEMFile("private.key")
    if err != nil {
        panic(err)
    }

    // 签名字符串
    signature, err := s.SignString("Hello, World!")
    if err != nil {
        panic(err)
    }
    fmt.Printf("Signature: %s\n", signature)

    // 签名文件
    signature, err = s.SignFile("example.txt")
    if err != nil {
        panic(err)
    }
    fmt.Printf("File Signature: %s\n", signature)
}
```

### 3. 验证

```go
package main

import (
    "fmt"
    "github.com/yourusername/cert-sign/verifier"
)

func main() {
    // 创建验证器（支持证书和公钥格式）
    v, err := verifier.NewVerifierFromPEMFile("public.pem") // 或 "cert.pem"
    if err != nil {
        panic(err)
    }

    // 验证字符串签名
    err = v.VerifyString("Hello, World!", signature)
    if err != nil {
        fmt.Printf("验证失败: %v\n", err)
    } else {
        fmt.Println("验证成功")
    }

    // 验证文件签名
    err = v.VerifyFile("example.txt", signature)
    if err != nil {
        fmt.Printf("验证失败: %v\n", err)
    } else {
        fmt.Println("验证成功")
    }
}
```

## 命令行工具

```bash
# 签名字符串
./cert-sign sign -k private.key -s "Hello, World!"

# 签名文件
./cert-sign sign -k private.key -f example.txt

# 验证字符串签名
./cert-sign verify -p public.pem -s "Hello, World!" -t "base64_encoded_signature"

# 验证文件签名
./cert-sign verify -p public.pem -f example.txt -t "base64_encoded_signature"
```

## 性能

基准测试结果（在 Apple M1 上）：

```
BenchmarkSignString-12    58364    19399 ns/op
BenchmarkSignFile-12      31774    33162 ns/op
BenchmarkVerifyString-12  22334    55484 ns/op
BenchmarkVerifyFile-12    17811    69281 ns/op
```

## 注意事项

1. 签名使用 URL 安全的 Base64 编码，不包含填充字符（=）
2. 验证器支持两种格式的公钥文件：
   - X.509 证书（CERTIFICATE）
   - 公钥（PUBLIC KEY）
3. 签名和验证操作都是线程安全的
4. 文件操作使用互斥锁保护，确保并发安全

## 许可证

Apache License 2.0

Copyright 2024 MarsQuick

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. 