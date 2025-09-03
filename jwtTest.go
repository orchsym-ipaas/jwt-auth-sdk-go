package main


import (
	"log"
	"net/http"
	"fmt"
	"time"

	"jwt-auth-sdk-go/jwt"
)
// testHS256Request 测试HS256 JWT认证请求
func testHS256Request() {
	// 配置参数
	appCode := "b3JjaHN5bS1qd3QtYXV0aDM5MjU0"
	clientID := "38e935c4-666a-48ba-8c64-7c0e21ff6b4f"
	secretCode := "fadwsfteawsfd"
	tokenPeriod := 250
	algorithm := "HS256"
	url := "http://orchsym-gateway.baishancloud.com/env-101/por-17834/propath/bsy/get"

	// 生成JWT token
	jwtGenerator, err := jwt.NewJwtGenerator(secretCode, clientID, tokenPeriod, algorithm)
	if err != nil {
		log.Printf("Failed to generate token: %v", err)
		return
	}

	token := jwtGenerator.GetToken()
	fmt.Printf("Generated Token: %s\n", token)

	// 设置请求头
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("Failed to create request: %v", err)
		return
	}

	req.Header.Add("orchsym-app-code", appCode)
	req.Header.Add("Authorization", "bearer "+token)

	fmt.Printf("Headers: %v\n", req.Header)

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("Status Code: %d\n", resp.StatusCode)

	// 读取响应体
	body := make([]byte, 1024)
	n, _ := resp.Body.Read(body)
	fmt.Printf("Response: %s\n", string(body[:n]))
}

// testRS256Request 测试RS256 JWT认证请求
func testRS256Request() {
	// 配置参数
	appCode := "b3JjaHN5bS1qd3QtYXV0aDM5MjMz"
	clientID := "fb7cc604-3732-446c-b2bc-4f92c414eba2"
	privateKey := "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDViFrSfCpARiwkj4YFSIEqNv7OuYPNhM1E+qPVwYpb8eviEctR1/KzO0DHcAH/UTuoFOJK1/f6BeMU8ExEC3g/EGubKe3d+WUZXyoA0JDRkKKOjZW0Ad7s5ZVOYYjpc8sw6KuO0G5UNRoU7XP9t1BpUpcxuNfu5XdboF1GPHDZNrzACB7AU0wyt8FQMTXQvosJ4ofUVWZSd4tW8eGSYLYDBdqe7uocByAOg2fJg+62558fGhvh82SW3rVfcQO3o4JKS3J+pKjGywBa7x+JzfMpIryEYGjoh5pbogMdveuAX+457kiTy+XyjO0il+4Hke6B0gQiA4p3sT1CpSM1evPrAgMBAAECggEASsR9ZLE0TCAmCcE1gLkT/ReXngPoSjijdXE7l7e2fh5V5Wkso6I1KZvoQU0PbfpgJKj3WZSIkEOqcST412SavJ4/x2tljjFqvHkNaI6e/rohqT+bORXknFeBMZpGSdQRRDVcCNwjnZmgYc6JLEAZSF+ycCcUeOJhKjSbJGI6c1uq/Lm8DzKCeeKtkdmplejTqMzqQc86ZueGEwNS1o5QVKzq+3aWGZxI6DC6cZ7uT/oTaUn2t6nSoZZItn9cO2MIERcCs2+2X+IH6NsFoJnqsf5UVFuwp1kyQ/p1YrGwnGOCTzA3r3yBrwUgFhF9LLP8bSHLRv+w/EluGeUOKiLinQKBgQDpM2jYvE/boKC9L8PoUdMBE2HTzU6LN7rL9mG+rgojzjFMOVY+ihyIvvO9jP/zswBwkASXiQHNyqhZVhFIvFzqQTa6uo44mWQYPo+mYq2WokTzLf1WXgmjGRTWO8oow1XrRHKjzWSX37A7hpDIx5Fu+Xs2Aw23LNkyhX93pv2PVwKBgQDqaK/AzzY4LcNgEVSX1oAcx1iO3sbGJvWcAzkG8TMAddJhCzuZ9UzL1q99w9w9vV2Up1Ux3WiNYhTmTiY1QMYpgGAsT+7yy4389PcqcOZeqJn9DGxU6Z69mUfPOLjQqmsnqN0s7jSk5lXfoYhSkZa9IlaWsIiv96qdytP/RLFnjQKBgQCz778OvP7BcIeWcqyvLbOqONJbIydftHiluE5jWtboGclgDz3Es7ygpvZbY9h6qbvFHtrsMgL6T0zm4cokXXM0LW2VVy017uWU73DX6XwXps2c9fdsFNNKzaeORkQOf+pjxkTOr0TXCvpoc8Rzp8lH36h6XJDQrgJJQUjBglBTsQKBgQCG48EnkdYgk+0XDkIAsjW82dYTOQ1nn6m8onohjZEM1cA/ieg9W1RbBGquU5QcjykXzwcOj9uHaIagVR5VjLW70h0FwuW9H/fQNeM5sAhRNnKOlKSOZHWto1QYYgqwQTEyfFDydw0iS03lR54b7Z2xrt3nDyVJJZsv/DTsc0onTQKBgQCPRZcrFLHH6DegCmkyD2Q3AMWLz92Eg5EoDDC6YMkU6T6NE8UJy1FEECKZIno6FowxCmV6tHFltICJ43aqLnxoEL9hCyniuiEyPmmxeFIxc4rhPW54+mmfZbNAJZ1zdF6xKwT1oiTA8XLu3motwORVZQ5w8gr2Gx+L/Khr4/2nOg=="
	tokenPeriod := 250
	algorithm := "RS256"
	url := "http://orchsym-gateway.baishancloud.com/env-101/por-17834/propath/bsy/get"

	// 生成JWT token
	jwtGenerator, err := jwt.NewJwtGenerator(privateKey, clientID, tokenPeriod, algorithm)
	if err != nil {
		log.Printf("Failed to generate token: %v", err)
		return
	}

	token := jwtGenerator.GetToken()
	fmt.Printf("Generated Token: %s\n", token)

	// 设置请求头
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("Failed to create request: %v", err)
		return
	}

	req.Header.Add("orchsym-app-code", appCode)
	req.Header.Add("Authorization", "bearer "+token)

	fmt.Printf("Request headers: %v\n", req.Header)

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("Status Code: %d\n", resp.StatusCode)

	// 读取响应体
	body := make([]byte, 1024)
	n, _ := resp.Body.Read(body)
	fmt.Printf("Response: %s\n", string(body[:n]))
}

func main() {
	fmt.Println("=== Testing HS256 ===")
	testHS256Request()

	fmt.Println("\n=== Testing RS256 ===")
	testRS256Request()
	
}