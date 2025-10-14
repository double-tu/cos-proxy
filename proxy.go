package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net" // 新增 "net" 包用于获取本机 IP
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/tencentyun/cos-go-sdk-v5"
	"golang.org/x/sync/errgroup"
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

// requestLoggingMiddleware 记录所有到达的请求 (最外层,用于调试)
func requestLoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("🔵 RAW REQUEST: %s %s %s | Host: %s | From: %s",
			r.Method, r.URL.Path, r.URL.RawQuery, r.Host, r.RemoteAddr)
		next.ServeHTTP(w, r)
	})
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
			// 如果 X-Real-IP 头为空，则尝试从 RemoteAddr 获取 IP
			// 这对于不经过 Nginx 的本地直接访问是必要的
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				// 如果解析 RemoteAddr 失败，则记录错误并拒绝请求
				log.Printf("Bad Request: could not split host port from %s: %v", r.RemoteAddr, err)
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}
			clientIP = host
		}

		// 如果最终 clientIP 仍然为空，则拒绝请求
		if clientIP == "" {
			log.Printf("Forbidden: Could not determine client IP. RemoteAddr: %s", r.RemoteAddr)
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

// COSProxyHandler 持有 COS 客户端和认证信息
type COSProxyHandler struct {
	client    *cos.Client
	secretID  string
	secretKey string
}

// ServeHTTP 是处理所有传入请求的核心方法
func (h *COSProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	objectKey := strings.TrimPrefix(r.URL.Path, "/")
	// 对于 POST 请求，objectKey 可能在表单数据中，而不是在 URL 路径中
	if objectKey == "" && r.Method != http.MethodPost {
		http.Error(w, "Object key is missing in the URL path.", http.StatusBadRequest)
		return
	}

	// 详细的请求日志
	log.Printf("========== Incoming Request ==========")
	log.Printf("Method: %s", r.Method)
	log.Printf("URL Path: %s", r.URL.Path)
	log.Printf("URL RawQuery: %s", r.URL.RawQuery)
	log.Printf("Object Key: %s", objectKey)
	log.Printf("Content-Type: %s", r.Header.Get("Content-Type"))
	log.Printf("Content-Length: %d", r.ContentLength)
	log.Printf("From IP: %s", r.Header.Get("X-Real-IP"))
	log.Printf("RemoteAddr: %s", r.RemoteAddr)
	log.Printf("User-Agent: %s", r.Header.Get("User-Agent"))

	switch r.Method {
	case http.MethodGet:
		h.handleGetObject(w, r, objectKey)
	case http.MethodPut:
		// 所有 PUT 请求（无论是简单上传还是分块上传的 part）都由 handlePutObject 处理
		h.handlePutObject(w, r, objectKey)
	case http.MethodDelete:
		h.handleDeleteObject(w, r, objectKey)
	case http.MethodPost:
		queryParams := r.URL.Query()
		// 分块上传的 POST 请求（初始化、完成）也由 handlePutObject 处理
		if queryParams.Has("uploads") || queryParams.Has("uploadId") {
			h.handlePutObject(w, r, objectKey)
		} else {
			// 其他 POST 请求（如表单上传）保持不变
			h.handlePostObject(w, r)
		}
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

// handlePutObject 处理所有上传请求，包括简单上传和分块上传
func (h *COSProxyHandler) handlePutObject(w http.ResponseWriter, r *http.Request, key string) {
	// 检查是否是分块上传的相关操作（初始化、完成、中止）
	// 这些操作没有请求体，直接透传
	queryParams := r.URL.Query()
	if (r.Method == http.MethodPost && (queryParams.Has("uploads") || queryParams.Has("uploadId"))) ||
		(r.Method == http.MethodDelete && queryParams.Has("uploadId")) {
		h.proxyMultipartRequest(w, r)
		return
	}

	// 对于 PUT 请求，根据 Content-Length 决定上传策略
	contentLength := r.ContentLength
	const simpleUploadThreshold int64 = 5 * 1024 * 1024 // 5MB

	if contentLength != -1 && contentLength < simpleUploadThreshold {
		// 文件较小，使用简单上传
		h.executeSimplePut(w, r, key)
	} else {
		// 文件较大或大小未知（流式），使用分块上传
		h.executeMultipartPut(w, r, key)
	}
}

// executeSimplePut 执行标准的 PutObject 操作
func (h *COSProxyHandler) executeSimplePut(w http.ResponseWriter, r *http.Request, key string) {
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	opt := &cos.ObjectPutOptions{
		ObjectPutHeaderOptions: &cos.ObjectPutHeaderOptions{
			ContentType:   contentType,
			ContentLength: r.ContentLength,
		},
	}

	// 传递自定义元数据
	for headerKey, values := range r.Header {
		if strings.HasPrefix(strings.ToLower(headerKey), "x-cos-meta-") {
			if opt.ObjectPutHeaderOptions.XCosMetaXXX == nil {
				opt.ObjectPutHeaderOptions.XCosMetaXXX = &http.Header{}
			}
			for _, value := range values {
				opt.ObjectPutHeaderOptions.XCosMetaXXX.Add(headerKey, value)
			}
		}
	}

	log.Printf("Executing simple PUT for key: %s, ContentLength: %d", key, r.ContentLength)
	resp, err := h.client.Object.Put(context.Background(), key, r.Body, opt)
	if err != nil {
		handleCOSError(w, err)
		return
	}
	defer resp.Body.Close()

	// 返回响应
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
	log.Printf("Successfully completed simple PUT for key: %s", key)
}

// executeMultipartPut 执行分块上传逻辑
func (h *COSProxyHandler) executeMultipartPut(w http.ResponseWriter, r *http.Request, key string) {
	log.Printf("Starting multipart upload for key: %s, ContentLength: %d", key, r.ContentLength)

	// 1. 初始化分块上传
	opt := &cos.InitiateMultipartUploadOptions{}
	if contentType := r.Header.Get("Content-Type"); contentType != "" {
		opt.ObjectPutHeaderOptions = &cos.ObjectPutHeaderOptions{ContentType: contentType}
	}
	initResult, _, err := h.client.Object.InitiateMultipartUpload(context.Background(), key, opt)
	if err != nil {
		handleCOSError(w, err)
		return
	}
	uploadID := initResult.UploadID
	log.Printf("Multipart upload initiated. UploadID: %s", uploadID)

	// 2. 并发上传分片
	const partSize = 8 * 1024 * 1024 // 固定分片大小为 8MB
	const concurrency = 5             // 并发数

	partsCh := make(chan partUpload, concurrency)
	uploadedCh := make(chan uploadedPart, concurrency)
	g, ctx := errgroup.WithContext(context.Background())

	// 启动上传 goroutine 池
	for i := 0; i < concurrency; i++ {
		g.Go(func() error {
			for part := range partsCh {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
					log.Printf("Uploading part %d for UploadID: %s", part.PartNumber, uploadID)
					resp, err := h.client.Object.UploadPart(ctx, key, uploadID, part.PartNumber, bytes.NewReader(part.Data), nil)
					if err != nil {
						log.Printf("Error uploading part %d: %v", part.PartNumber, err)
						return err
					}
					etag := resp.Header.Get("ETag")
					uploadedCh <- uploadedPart{PartNumber: part.PartNumber, ETag: etag}
					log.Printf("Successfully uploaded part %d, ETag: %s", part.PartNumber, etag)
				}
			}
			return nil
		})
	}

	// 启动读取和分发 goroutine
	g.Go(func() error {
		defer close(partsCh)
		partNumber := 1
		for {
			buffer := make([]byte, partSize)
			n, err := io.ReadFull(r.Body, buffer)

			if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
				log.Printf("Error reading request body: %v", err)
				return err
			}

			if n > 0 {
				select {
				case partsCh <- partUpload{PartNumber: partNumber, Data: buffer[:n]}:
					partNumber++
				case <-ctx.Done():
					return ctx.Err()
				}
			}

			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break // 读取完毕
			}
		}
		return nil
	})

	// 等待所有 goroutine 完成
	if err := g.Wait(); err != nil {
		log.Printf("Error during multipart upload, aborting... UploadID: %s, Error: %v", uploadID, err)
		// 发生错误，中止上传
		_, abortErr := h.client.Object.AbortMultipartUpload(context.Background(), key, uploadID)
		if abortErr != nil {
			log.Printf("Failed to abort multipart upload %s: %v", uploadID, abortErr)
		}
		http.Error(w, "Multipart upload failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	close(uploadedCh)

	// 3. 收集并排序已上传的分片
	var uploadedParts []cos.Object
	for part := range uploadedCh {
		uploadedParts = append(uploadedParts, cos.Object{PartNumber: part.PartNumber, ETag: part.ETag})
	}
	sort.Slice(uploadedParts, func(i, j int) bool {
		return uploadedParts[i].PartNumber < uploadedParts[j].PartNumber
	})

	// 4. 完成分块上传
	log.Printf("Completing multipart upload for UploadID: %s with %d parts", uploadID, len(uploadedParts))
	compOpt := &cos.CompleteMultipartUploadOptions{Parts: uploadedParts}
	completeResult, _, err := h.client.Object.CompleteMultipartUpload(context.Background(), key, uploadID, compOpt)
	if err != nil {
		handleCOSError(w, err)
		return
	}

	// 5. 返回成功响应
	log.Printf("Successfully completed multipart upload for key: %s", key)
	w.Header().Set("Content-Type", "application/xml")
	// 将 completeResult 序列化为 XML 并返回
	// 注意：这里为了简化，直接返回一个成功的消息。在生产环境中，应该返回 COS 返回的 XML。
	responseXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<CompleteMultipartUploadResult>
  <Location>%s</Location>
  <Bucket>%s</Bucket>
  <Key>%s</Key>
  <ETag>%s</ETag>
</CompleteMultipartUploadResult>`, completeResult.Location, initResult.Bucket, key, completeResult.ETag)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(responseXML))
}

// proxyMultipartRequest 仅用于透传 POST (uploads, uploadId) 和 DELETE (uploadId) 请求
func (h *COSProxyHandler) proxyMultipartRequest(w http.ResponseWriter, r *http.Request) {
	log.Printf("Proxying multipart management request: %s %s", r.Method, r.URL.RequestURI())
	targetURL := h.client.BaseURL.BucketURL.ResolveReference(r.URL)
	proxyReq, err := http.NewRequest(r.Method, targetURL.String(), r.Body)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	proxyReq.Header = r.Header.Clone()
	if r.ContentLength > 0 {
		proxyReq.ContentLength = r.ContentLength
	}

	authClient := &http.Client{
		Transport: &cos.AuthorizationTransport{
			SecretID:  h.secretID,
			SecretKey: h.secretKey,
			Transport: http.DefaultTransport,
		},
	}

	resp, err := authClient.Do(proxyReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
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

// handleDeleteObject 处理删除对象请求
func (h *COSProxyHandler) handleDeleteObject(w http.ResponseWriter, r *http.Request, key string) {
	resp, err := h.client.Object.Delete(context.Background(), key)
	if err != nil {
		handleCOSError(w, err)
		return
	}
	defer resp.Body.Close()
	// 先复制响应头
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// handlePostObject 处理通过 multipart/form-data 上传对象的请求
func (h *COSProxyHandler) handlePostObject(w http.ResponseWriter, r *http.Request) {
	// 1. 解析 multipart/form-data 请求
	// 设置内存限制为 128MB
	if err := r.ParseMultipartForm(128 << 20); err != nil {
		http.Error(w, "Failed to parse multipart form: "+err.Error(), http.StatusBadRequest)
		return
	}

	// 2. 从表单中获取 'key' 字段
	objectKey := r.FormValue("key")
	if objectKey == "" {
		http.Error(w, "Form field 'key' is required.", http.StatusBadRequest)
		return
	}

	// 3. 从表单中获取 'file' 字段
	var file multipart.File
	var header *multipart.FileHeader
	var err error
	file, header, err = r.FormFile("file")
	if err != nil {
		http.Error(w, "Failed to get file from form: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	// 4. 处理 key 中的 ${filename} 占位符
	finalObjectKey := strings.Replace(objectKey, "${filename}", header.Filename, -1)

	// 5. 获取文件的真实 Content-Type
	// 优先使用表单中文件的 Content-Type,如果没有则根据文件扩展名推断
	contentType := header.Header.Get("Content-Type")
	if contentType == "" {
		// 根据文件扩展名推断 Content-Type
		if strings.HasSuffix(strings.ToLower(header.Filename), ".webm") {
			contentType = "audio/webm"
		} else if strings.HasSuffix(strings.ToLower(header.Filename), ".mp3") {
			contentType = "audio/mpeg"
		} else if strings.HasSuffix(strings.ToLower(header.Filename), ".wav") {
			contentType = "audio/wav"
		} else if strings.HasSuffix(strings.ToLower(header.Filename), ".mp4") {
			contentType = "video/mp4"
		} else {
			contentType = "application/octet-stream"
		}
	}

	log.Printf("Uploading file '%s' to COS with key '%s', ContentType '%s', Size %d bytes",
		header.Filename, finalObjectKey, contentType, header.Size)

	// 6. 使用 SDK 上传文件流到 COS
	opt := &cos.ObjectPutOptions{
		ObjectPutHeaderOptions: &cos.ObjectPutHeaderOptions{
			ContentType:   contentType,
			ContentLength: header.Size,
		},
	}

	// 只传递特定的自定义元数据头部(x-cos-meta-*)
	for key, values := range r.Header {
		if strings.HasPrefix(strings.ToLower(key), "x-cos-meta-") {
			if opt.ObjectPutHeaderOptions.XCosMetaXXX == nil {
				opt.ObjectPutHeaderOptions.XCosMetaXXX = &http.Header{}
			}
			for _, value := range values {
				opt.ObjectPutHeaderOptions.XCosMetaXXX.Add(key, value)
			}
		}
	}

	resp, err := h.client.Object.Put(context.Background(), finalObjectKey, file, opt)
	if err != nil {
		handleCOSError(w, err)
		return
	}
	defer resp.Body.Close()

	log.Printf("COS POST Response: StatusCode=%d", resp.StatusCode)

	// 7. 返回成功响应
	// 先复制响应头
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// handleCOSError 是一个辅助函数，用于处理来自 COS SDK 的错误
func handleCOSError(w http.ResponseWriter, err error) {
	if cosErr, ok := err.(*cos.ErrorResponse); ok {
		log.Printf("COS Error: Code=%s, Message=%s, RequestID=%s", cosErr.Code, cosErr.Message, cosErr.RequestID)
		// 确保在函数结束时关闭响应体
		defer cosErr.Response.Body.Close()
		// 复制原始的COS错误响应头
		for key, values := range cosErr.Response.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		// 写入原始的COS错误状态码
		w.WriteHeader(cosErr.Response.StatusCode)
		// 复制原始的COS错误响应体 (XML)
		io.Copy(w, cosErr.Response.Body)
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
		client:    client,
		secretID:  secretID,
		secretKey: secretKey,
	}
	handlerWithWhitelist := ipWhitelistMiddleware(proxyHandler, allowedIPs)
	handlerWithLogging := requestLoggingMiddleware(handlerWithWhitelist)

	log.Printf("Starting COS proxy server on %s", listenAddr)
	log.Printf("Proxying requests to COS bucket: %s", u.Host)

	if err := http.ListenAndServe(listenAddr, handlerWithLogging); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}