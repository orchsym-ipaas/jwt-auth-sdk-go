package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JwtGenerator JWT Token生成类
type JwtGenerator struct {
	token string
}

// NewJwtGenerator 创建JWT生成器实例
func NewJwtGenerator(keyStr, clientID string, tokenPeriod int, algorithm string) (*JwtGenerator, error) {
	if algorithm == "" {
		return &JwtGenerator{token: ""}, nil
	}

	// 计算过期时间
	expiresTime := time.Now().Add(time.Duration(tokenPeriod) * time.Second)

	var tokenString string
	var err error

	switch algorithm {
	case "RS256":
		tokenString, err = generateRS256Token(keyStr, clientID, expiresTime)
	case "HS256":
		tokenString, err = generateHS256Token(keyStr, clientID, expiresTime)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s. Only 'RS256' and 'HS256' are supported", algorithm)
	}

	if err != nil {
		return nil, err
	}

	return &JwtGenerator{token: tokenString}, nil
}

// generateRS256Token 生成RS256算法的JWT token
func generateRS256Token(privateKeyStr, clientID string, expiresTime time.Time) (string, error) {
	// 解码base64私钥
	privateKeyBytes, err := base64.StdEncoding.DecodeString(privateKeyStr)
	if err != nil {
		return "", fmt.Errorf("failed to decode private key: %v", err)
	}

	// 解析PKCS8格式的私钥
	privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %v", err)
	}

	// 类型断言为RSA私钥
	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("not an RSA private key")
	}

	// 创建token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": clientID,
		"exp": expiresTime.Unix(),
	})

	// 签名token
	tokenString, err := token.SignedString(rsaPrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %v", err)
	}

	return tokenString, nil
}

// generateHS256Token 生成HS256算法的JWT token
func generateHS256Token(secret, clientID string, expiresTime time.Time) (string, error) {
	// 创建token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": clientID,
		"exp": expiresTime.Unix(),
	})

	// 签名token
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %v", err)
	}

	return tokenString, nil
}

// GetToken 获取生成的token
func (j *JwtGenerator) GetToken() string {
	return j.token
}

// String 字符串表示
func (j *JwtGenerator) String() string {
	return fmt.Sprintf("token = \n%s", j.token)
}
