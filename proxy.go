package main

import (
	"cos-proxy/controller"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/tencentyun/cos-go-sdk-v5"
)

// getLocalIPv4s 会检测并返回本机所有的非环回 IPv4 地址
func getLocalIPv4s() ([]string, error) {
	var ips []string
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %w", err)
	}

	for _, i := range interfaces {
		addrs, err := i.Addrs()
		if err != nil {
			log.Printf("Warning: could not get addresses for interface %s: %v", i.Name, err)
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			if ipnet, ok := addr.(*net.IPNet); ok {
				ip = ipnet.IP
			} else {
				continue
			}
			if ip.To4() != nil && !ip.IsLoopback() {
				ips = append(ips, ip.String())
			}
		}
	}
	return ips, nil
}

// requestLoggingMiddleware 记录所有到达的请求 (最外层,用于调试)
func requestLoggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Printf("🔵 RAW REQUEST: %s %s %s | Host: %s | From: %s",
			c.Request.Method, c.Request.URL.Path, c.Request.URL.RawQuery, c.Request.Host, c.ClientIP())
		c.Next()
	}
}

// ipWhitelistMiddleware 是一个 Gin 中间件，用于检查IP白名单
func ipWhitelistMiddleware(allowedIPs map[string]bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 对于 GET 和 HEAD 请求，所有IP都允许访问
		if c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead {
			c.Next()
			return
		}

		// 优先从 X-Real-IP 获取 IP，这是常见的反向代理头部
		clientIP := c.GetHeader("X-Real-IP")
		if clientIP == "" {
			// 如果 X-Real-IP 不存在，则回退到 Gin 的默认 IP 获取方式 (通常是 RemoteAddr)
			clientIP = c.ClientIP()
		}
		if !allowedIPs[clientIP] {
			log.Printf("Forbidden: IP %s is not in the whitelist for method %s.", clientIP, c.Request.Method)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Forbidden: IP not allowed"})
			return
		}

		log.Printf("Allowed: IP %s is in the whitelist for method %s.", clientIP, c.Request.Method)
		c.Next()
	}
}

func main() {
	// --- 配置信息 ---
	// 从环境变量中读取基础域名，例如 "proxy.example.com"
	baseDomain := os.Getenv("BASE_DOMAIN")
	if baseDomain == "" {
		log.Println("Warning: BASE_DOMAIN environment variable is not set. Virtual-hosted style requests may not work correctly.")
	}
	whitelistStr := os.Getenv("WHITELIST_IPS")
	listenAddr := ":8080"
	bucketURL := os.Getenv("COS_BUCKET_URL_INTERNAL")
	secretID := os.Getenv("TENCENTCLOUD_SECRET_ID")
	secretKey := os.Getenv("TENCENTCLOUD_SECRET_KEY")

	if bucketURL == "" || secretID == "" || secretKey == "" {
		log.Fatal("Missing required environment variables: COS_BUCKET_URL_INTERNAL, TENCENTCLOUD_SECRET_ID, TENCENTCLOUD_SECRET_KEY")
	}

	// --- IP 白名单处理 ---
	allowedIPs := make(map[string]bool)
	if whitelistStr != "" {
		ips := strings.Split(whitelistStr, ",")
		for _, ip := range ips {
			trimmedIP := strings.TrimSpace(ip)
			if trimmedIP != "" {
				allowedIPs[trimmedIP] = true
			}
		}
	}
	log.Printf("Loaded %d IP(s) from WHITELIST_IPS env var.", len(allowedIPs))

	localIPs, err := getLocalIPv4s()
	if err != nil {
		log.Printf("Warning: Failed to get local IPs, will only use IPs from env var. Error: %v", err)
	} else {
		for _, ip := range localIPs {
			if !allowedIPs[ip] {
				allowedIPs[ip] = true
			}
		}
		log.Printf("Automatically added %d local IP(s) to the whitelist: %v", len(localIPs), localIPs)
	}

	finalAllowedList := []string{}
	for ip := range allowedIPs {
		finalAllowedList = append(finalAllowedList, ip)
	}
	log.Printf("Total %d unique IPs are whitelisted for write operations: %v", len(finalAllowedList), finalAllowedList)

	// --- COS 客户端初始化 ---
	u, err := url.Parse(bucketURL)
	if err != nil {
		log.Fatalf("Invalid COS_BUCKET_URL_INTERNAL: %v", err)
	}
	baseURL := &cos.BaseURL{BucketURL: u}
	cosClient := cos.NewClient(baseURL, &http.Client{
		Transport: &cos.AuthorizationTransport{
			SecretID:  secretID,
			SecretKey: secretKey,
		},
	})
	log.Printf("Proxying requests to COS bucket: %s", u.Host)

	// --- Gin 服务器初始化 ---
	router := gin.Default()

	// --- 中间件设置 ---
	router.Use(requestLoggingMiddleware())
	router.Use(ipWhitelistMiddleware(allowedIPs))

	// --- 路由和控制器设置 ---
	s3Controller := controllers.NewS3Controller(baseDomain, cosClient)
	s3Controller.RegisterRoutes(router)

	// --- 启动服务器 ---
	log.Printf("Starting S3 compatible proxy server on %s", listenAddr)
	if err := router.Run(listenAddr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}