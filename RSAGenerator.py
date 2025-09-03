package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
)

// OrchsymRSA256KeyGenerator 秘钥对生成类
type OrchsymRSA256KeyGenerator struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// NewOrchsymRSA256KeyGenerator 创建新的RSA密钥对生成器
func NewOrchsymRSA256KeyGenerator(keySize int) (*OrchsymRSA256KeyGenerator, error) {
	// 生成RSA私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %v", err)
	}

	return &OrchsymRSA256KeyGenerator{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
	}, nil
}

// GetPublicKey 获取公钥
func (k *OrchsymRSA256KeyGenerator) GetPublicKey() *rsa.PublicKey {
	return k.publicKey
}

// GetPrivateKey 获取私钥
func (k *OrchsymRSA256KeyGenerator) GetPrivateKey() *rsa.PrivateKey {
	return k.privateKey
}

// String 转换为字符串表示形式
func (k *OrchsymRSA256KeyGenerator) String() string {
	// 序列化公钥为DER格式然后Base64编码
	publicKeyDER, err := x509.MarshalPKIXPublicKey(k.publicKey)
	if err != nil {
		return fmt.Sprintf("Error marshaling public key: %v", err)
	}
	publicKeyB64 := base64.StdEncoding.EncodeToString(publicKeyDER)

	// 序列化私钥为DER格式然后Base64编码
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(k.privateKey)
	if err != nil {
		return fmt.Sprintf("Error marshaling private key: %v", err)
	}
	privateKeyB64 := base64.StdEncoding.EncodeToString(privateKeyDER)

	return fmt.Sprintf("publicKey = \n%s\nprivateKey = \n%s", publicKeyB64, privateKeyB64)
}

// GetPublicKeyPEM 获取PEM格式的公钥
func (k *OrchsymRSA256KeyGenerator) GetPublicKeyPEM() (string, error) {
	publicKeyDER, err := x509.MarshalPKIXPublicKey(k.publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %v", err)
	}

	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	}

	return string(pem.EncodeToMemory(publicKeyBlock)), nil
}

// GetPrivateKeyPEM 获取PEM格式的私钥
func (k *OrchsymRSA256KeyGenerator) GetPrivateKeyPEM() (string, error) {
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(k.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal private key: %v", err)
	}

	privateKeyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	}

	return string(pem.EncodeToMemory(privateKeyBlock)), nil
}


func main() {
		// 创建2048位RSA密钥对生成器
		keyGenerator,err := NewOrchsymRSA256KeyGenerator(2048)
		if err != nil {
			log.Fatalf("Failed to create key generator: %v", err)
		}
	
		// 获取密钥
		// publicKey := keyGenerator.GetPublicKey()
		// privateKey := keyGenerator.GetPrivateKey()
	
		// 打印密钥
		fmt.Println(keyGenerator.String())
	
		// 如果需要PEM格式的密钥
		publicPEM, err := keyGenerator.GetPublicKeyPEM()
		if err != nil {
			log.Fatalf("Failed to get public key PEM: %v", err)
		}
	
		privatePEM, err := keyGenerator.GetPrivateKeyPEM()
		if err != nil {
			log.Fatalf("Failed to get private key PEM: %v", err)
		}
	
		fmt.Println("\nPEM格式公钥:")
		fmt.Println(publicPEM)
	
		fmt.Println("PEM格式私钥:")
		fmt.Println(privatePEM)
	
}