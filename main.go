package main

import (
	"fmt"
	"os"

	"cert-sign/signer"
	"cert-sign/verifier"

	"github.com/spf13/cobra"
)

var (
	// 签名命令参数
	privateKeyPath string
	inputFile      string
	inputString    string

	// 验证命令参数
	publicKeyPath string
	signature     string
)

var rootCmd = &cobra.Command{
	Use:   "cert-sign",
	Short: "证书签名工具",
	Long:  `一个用于数据签名和验证的命令行工具，支持字符串和文件的签名验证。`,
}

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "签名数据",
	Long:  `使用私钥对字符串或文件进行签名。`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// 检查私钥文件
		if privateKeyPath == "" {
			return fmt.Errorf("必须指定私钥文件路径 (-k)")
		}

		// 创建签名器
		s, err := signer.NewSignerFromPEMFile(privateKeyPath)
		if err != nil {
			return fmt.Errorf("创建签名器失败: %v", err)
		}

		// 检查输入
		if inputFile == "" && inputString == "" {
			return fmt.Errorf("必须指定要签名的文件 (-f) 或字符串 (-s)")
		}

		// 签名文件
		if inputFile != "" {
			signature, err := s.SignFile(inputFile)
			if err != nil {
				return fmt.Errorf("签名文件失败: %v", err)
			}
			fmt.Printf("文件签名结果: %s\n", signature)
		}

		// 签名字符串
		if inputString != "" {
			signature, err := s.SignString(inputString)
			if err != nil {
				return fmt.Errorf("签名字符串失败: %v", err)
			}
			fmt.Printf("字符串签名结果: %s\n", signature)
		}

		return nil
	},
}

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "验证签名",
	Long:  `使用公钥验证字符串或文件的签名。`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// 检查公钥文件
		if publicKeyPath == "" {
			return fmt.Errorf("必须指定公钥文件路径 (-p)")
		}

		// 检查签名
		if signature == "" {
			return fmt.Errorf("必须指定签名 (-t)")
		}

		// 创建验证器
		v, err := verifier.NewVerifierFromPEMFile(publicKeyPath)
		if err != nil {
			return fmt.Errorf("创建验证器失败: %v", err)
		}

		// 检查输入
		if inputFile == "" && inputString == "" {
			return fmt.Errorf("必须指定要验证的文件 (-f) 或字符串 (-s)")
		}

		// 验证文件
		if inputFile != "" {
			err := v.VerifyFile(inputFile, signature)
			if err != nil {
				return fmt.Errorf("验证文件签名失败: %v", err)
			}
			fmt.Println("文件签名验证成功")
		}

		// 验证字符串
		if inputString != "" {
			err := v.VerifyString(inputString, signature)
			if err != nil {
				return fmt.Errorf("验证字符串签名失败: %v", err)
			}
			fmt.Println("字符串签名验证成功")
		}

		return nil
	},
}

func init() {
	// 添加签名命令
	rootCmd.AddCommand(signCmd)
	signCmd.Flags().StringVarP(&privateKeyPath, "key", "k", "", "私钥文件路径 (必需)")
	signCmd.Flags().StringVarP(&inputFile, "file", "f", "", "要签名的文件路径")
	signCmd.Flags().StringVarP(&inputString, "string", "s", "", "要签名的字符串")
	signCmd.MarkFlagRequired("key")

	// 添加验证命令
	rootCmd.AddCommand(verifyCmd)
	verifyCmd.Flags().StringVarP(&publicKeyPath, "pubkey", "p", "", "公钥文件路径 (必需)")
	verifyCmd.Flags().StringVarP(&inputFile, "file", "f", "", "要验证的文件路径")
	verifyCmd.Flags().StringVarP(&inputString, "string", "s", "", "要验证的字符串")
	verifyCmd.Flags().StringVarP(&signature, "signature", "t", "", "签名 (必需)")
	verifyCmd.MarkFlagRequired("pubkey")
	verifyCmd.MarkFlagRequired("signature")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
