package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net" // 新增 "net" 包用于获取本机 IP
	"net/http"
	"net/url"
	"os"
	"strings"

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
			// 进行类型断言，判断地址是否为 IP 地址
			if ipnet, ok := addr.(*net.IPNet); ok {
				ip = ipnet.IP
			} else {
				continue
			}

			// 我们只需要 IPv4 地址，并且排除掉环回地址 (127.0.0.1)
			if ip.To4() != nil && !ip.IsLoopback() {
				ips = append(ips, ip.String())
			}
		}
	}
	return ips, nil
}

// ipWhitelistMiddleware 是一个HTTP中间件，用于检查IP白名单
func ipWhitelistMiddleware(next http.Handler, allowedIPs map[string]bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 对于 GET 和 HEAD 请求，所有IP都允许访问
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}

		// 对于 PUT, DELETE, POST 等修改操作，需要校验IP白名单
		// 从 Nginx 设置的 'X-Real-IP' 头获取真实IP
		clientIP := r.Header.Get("X-Real-IP")
		if clientIP == "" {
			// 如果没有这个头，说明请求可能没有经过Nginx，直接拒绝
			log.Printf("Forbidden: Missing X-Real-IP header. RemoteAddr: %s", r.RemoteAddr)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// 检查IP是否在白名单中
		if !allowedIPs[clientIP] {
			log.Printf("Forbidden: IP %s is not in the whitelist for method %s.", clientIP, r.Method)
			http.Error(w, "Forbidden: IP not allowed", http.StatusForbidden)
			return
		}

		// IP校验通过，处理后续请求
		log.Printf("Allowed: IP %s is in the whitelist for method %s.", clientIP, r.Method)
		next.ServeHTTP(w, r)
	})
}

// COSProxyHandler 持有 COS 客户端
type COSProxyHandler struct {
	client *cos.Client
}

// ServeHTTP 是处理所有传入请求的核心方法
func (h *COSProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	objectKey := strings.TrimPrefix(r.URL.Path, "/")
	if objectKey == "" {
		http.Error(w, "Object key is missing in the URL path.", http.StatusBadRequest)
		return
	}

	log.Printf("Processing request: Method=%s, ObjectKey=%s, FromIP=%s\n", r.Method, objectKey, r.Header.Get("X-Real-IP"))

	switch r.Method {
	case http.MethodGet:
		h.handleGetObject(w, r, objectKey)
	case http.MethodPut:
		h.handlePutObject(w, r, objectKey)
	case http.MethodDelete:
		h.handleDeleteObject(w, r, objectKey)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGetObject 处理获取对象请求
func (h *COSProxyHandler) handleGetObject(w http.ResponseWriter, r *http.Request, key string) {
	resp, err := h.client.Object.Get(context.Background(), key, nil)
	if err != nil {
		handleCOSError(w, err)
		return
	}
	defer resp.Body.Close()
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// handlePutObject 处理上传对象请求
func (h *COSProxyHandler) handlePutObject(w http.ResponseWriter, r *http.Request, key string) {
	resp, err := h.client.Object.Put(context.Background(), key, r.Body, nil)
	if err != nil {
		handleCOSError(w, err)
		return
	}
	defer resp.Body.Close()
	w.WriteHeader(resp.StatusCode)
}

// handleDeleteObject 处理删除对象请求
func (h *COSProxyHandler) handleDeleteObject(w http.ResponseWriter, r *http.Request, key string) {
	resp, err := h.client.Object.Delete(context.Background(), key)
	if err != nil {
		handleCOSError(w, err)
		return
	}
	defer resp.Body.Close()
	w.WriteHeader(resp.StatusCode)
}

// handleCOSError 是一个辅助函数，用于处理来自 COS SDK 的错误
func handleCOSError(w http.ResponseWriter, err error) {
	if cosErr, ok := err.(*cos.ErrorResponse); ok {
		log.Printf("COS Error: Code=%s, Message=%s, RequestID=%s", cosErr.Code, cosErr.Message, cosErr.RequestID)
		http.Error(w, cosErr.Message, cosErr.Response.StatusCode)
		return
	}
	log.Printf("Internal Server Error: %v", err)
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}

func main() {
	// --- 配置信息 ---
	bucketURL := os.Getenv("COS_BUCKET_URL_INTERNAL")
	secretID := os.Getenv("TENCENTCLOUD_SECRET_ID")
	secretKey := os.Getenv("TENCENTCLOUD_SECRET_KEY")
	whitelistStr := os.Getenv("WHITELIST_IPS")
	listenAddr := ":8080"

	if bucketURL == "" || secretID == "" || secretKey == "" {
		log.Fatal("Missing required environment variables: COS_BUCKET_URL_INTERNAL, TENCENTCLOUD_SECRET_ID, TENCENTCLOUD_SECRET_KEY")
	}

	// --- IP 白名单处理 ---
	// 1. 从环境变量加载配置的 IP
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

	// 2. 自动检测并添加本机 IP
	localIPs, err := getLocalIPv4s()
	if err != nil {
		log.Printf("Warning: Failed to get local IPs, will only use IPs from env var. Error: %v", err)
	} else {
		for _, ip := range localIPs {
			if !allowedIPs[ip] { // 避免重复添加
				allowedIPs[ip] = true
			}
		}
		log.Printf("Automatically added %d local IP(s) to the whitelist: %v", len(localIPs), localIPs)
	}
	
	totalAllowed := 0
	finalAllowedList := []string{}
	for ip := range allowedIPs {
		totalAllowed++
		finalAllowedList = append(finalAllowedList, ip)
	}
	log.Printf("Total %d unique IPs are whitelisted for write operations: %v", totalAllowed, finalAllowedList)


	// --- 客户端初始化 ---
	u, err := url.Parse(bucketURL)
	if err != nil {
		log.Fatalf("Invalid COS_BUCKET_URL_INTERNAL: %v", err)
	}
	baseURL := &cos.BaseURL{BucketURL: u}

	client := cos.NewClient(baseURL, &http.Client{
		Transport: &cos.AuthorizationTransport{
			SecretID:  secretID,
			SecretKey: secretKey,
		},
	})

	// --- 启动服务器 ---
	proxyHandler := &COSProxyHandler{
		client: client,
	}
	handlerWithWhitelist := ipWhitelistMiddleware(proxyHandler, allowedIPs)

	log.Printf("Starting COS proxy server on %s", listenAddr)
	log.Printf("Proxying requests to COS bucket: %s", u.Host)

	if err := http.ListenAndServe(listenAddr, handlerWithWhitelist); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}