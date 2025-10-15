package controllers

import (
	"encoding/xml"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/tencentyun/cos-go-sdk-v5"
)

// S3Controller 负责处理所有传入的 S3 API 兼容请求。
type S3Controller struct {
	// BaseDomain 是代理服务的基础域名，例如 "proxy.example.com"。
	// 这个字段对于解析虚拟托管类型 (Virtual-Hosted Style) 的请求至关重要。
	BaseDomain string
	CosClient  *cos.Client
}

// NewS3Controller 创建一个新的 S3Controller 实例。
// baseDomain 是代理服务配置的域名，用于区分存储桶名称。
func NewS3Controller(baseDomain string, cosClient *cos.Client) *S3Controller {
	return &S3Controller{
		BaseDomain: baseDomain,
		CosClient:  cosClient,
	}
}

// RegisterRoutes 将 S3 兼容的 API 路由注册到 Gin 引擎。
func (ctrl *S3Controller) RegisterRoutes(router *gin.Engine) {
	// 核心逻辑：由于 S3 路径可以非常灵活（例如 /bucket/key 或 /key），
	// 并且我们需要同时支持虚拟托管类型和路径类型，
	// 我们使用通配符路由来捕获所有请求，然后在处理函数内部进行分发。

	// 匹配所有路径的路由，覆盖所有 HTTP 方法
	router.Any("/*path", ctrl.s3RequestDispatcher)
}

// s3RequestDispatcher 是一个中央分发器，根据 HTTP 方法和查询参数将请求路由到正确的处理函数。
func (ctrl *S3Controller) s3RequestDispatcher(c *gin.Context) {
	// 关键：忽略所有客户端传入的认证信息
	// 在生产环境中，IP 白名单应在网络层（如 CVM 安全组、Nginx 或 iptables）强制执行。
	c.Request.Header.Del("Authorization")

	// 根据 S3 API 规范，分片上传操作通过查询参数来区分
	if _, ok := c.Request.URL.Query()["uploads"]; ok {
		// 这是 CreateMultipartUpload 请求
		ctrl.CreateMultipartUpload(c)
		return
	}
	if _, ok := c.Request.URL.Query()["uploadId"]; ok {
		switch c.Request.Method {
		case "PUT":
			// 这是 UploadPart 请求
			ctrl.UploadPart(c)
		case "POST":
			// 这是 CompleteMultipartUpload 请求
			ctrl.CompleteMultipartUpload(c)
		case "DELETE":
			// 这是 AbortMultipartUpload 请求
			ctrl.AbortMultipartUpload(c)
		default:
			c.XML(http.StatusBadRequest, gin.H{"error": "Invalid request method for multipart upload."})
		}
		return
	}

	// 处理单一对象操作
	switch c.Request.Method {
	case "GET":
		ctrl.GetObject(c)
	case "PUT":
		ctrl.PutObject(c)
	case "POST":
		// POST 通常用于基于浏览器的上传，它不遵循标准的 bucket/key 路径
		ctrl.PostObject(c)
	case "DELETE":
		ctrl.DeleteObject(c)
	default:
		c.XML(http.StatusMethodNotAllowed, gin.H{"error": "Method not allowed."})
	}
}

// =================================================================
// ============== 单一对象操作 (Single Object Operations) ==============
// =================================================================

// PutObject 处理 S3 的 PUT Object 请求。
// PUT /{bucket}/{key} 或 https://{bucket}.example.com/{key}
func (ctrl *S3Controller) PutObject(c *gin.Context) {
	_, key := ctrl.extractBucketAndKey(c)
	if key == "" {
		c.XML(http.StatusBadRequest, gin.H{"error": "Invalid key"})
		return
	}

	// 准备 COS SDK 的 PutObjectOptions
	opt := &cos.ObjectPutOptions{
		ObjectPutHeaderOptions: &cos.ObjectPutHeaderOptions{
			ContentType:   c.GetHeader("Content-Type"),
			ContentLength: c.Request.ContentLength,
		},
	}

	// 提取并设置自定义元数据 (x-amz-meta-* -> x-cos-meta-*)
	for h, v := range c.Request.Header {
		if strings.HasPrefix(strings.ToLower(h), "x-amz-meta-") {
			if opt.ObjectPutHeaderOptions.XCosMetaXXX == nil {
				opt.ObjectPutHeaderOptions.XCosMetaXXX = &http.Header{}
			}
			// 将 x-amz-meta- 转换为 x-cos-meta-
			cosMetaKey := "x-cos-meta-" + strings.TrimPrefix(strings.ToLower(h), "x-amz-meta-")
			opt.ObjectPutHeaderOptions.XCosMetaXXX.Set(cosMetaKey, v[0])
		}
	}

	// 调用 COS SDK 上传对象
	resp, err := ctrl.CosClient.Object.Put(c.Request.Context(), key, c.Request.Body, opt)
	if err != nil {
		ctrl.handleCOSError(c, err)
		return
	}
	defer resp.Body.Close()

	// 将 COS 返回的头部（特别是 ETag）透传给客户端
	for key, values := range resp.Header {
		for _, value := range values {
			c.Header(key, value)
		}
	}
	c.Status(resp.StatusCode)
}

// GetObject 处理 S3 的 GET Object 请求。
// GET /{bucket}/{key} 或 https://{bucket}.example.com/{key}
func (ctrl *S3Controller) GetObject(c *gin.Context) {
	_, key := ctrl.extractBucketAndKey(c)
	if key == "" {
		c.XML(http.StatusBadRequest, gin.H{"error": "Invalid key"})
		return
	}

	// 准备 COS SDK 的 GetObjectOptions，并透传 Range 头
	opt := &cos.ObjectGetOptions{}
	if rangeHeader := c.GetHeader("Range"); rangeHeader != "" {
		opt.Range = rangeHeader
	}

	// 调用 COS SDK 获取对象
	resp, err := ctrl.CosClient.Object.Get(c.Request.Context(), key, opt)
	if err != nil {
		ctrl.handleCOSError(c, err)
		return
	}
	defer resp.Body.Close()

	// 将 COS 返回的头部（Content-Type, Content-Length, ETag, Content-Range 等）透传给客户端
	for key, values := range resp.Header {
		for _, value := range values {
			c.Header(key, value)
		}
	}

	// 将 COS 的响应体流式传输给客户端
	c.DataFromReader(resp.StatusCode, resp.ContentLength, resp.Header.Get("Content-Type"), resp.Body, nil)
}

// DeleteObject 处理 S3 的 DELETE Object 请求。
// DELETE /{bucket}/{key} 或 https://{bucket}.example.com/{key}
func (ctrl *S3Controller) DeleteObject(c *gin.Context) {
	_, key := ctrl.extractBucketAndKey(c)
	if key == "" {
		c.XML(http.StatusBadRequest, gin.H{"error": "Invalid key"})
		return
	}

	// 调用 COS SDK 删除对象
	resp, err := ctrl.CosClient.Object.Delete(c.Request.Context(), key)
	if err != nil {
		ctrl.handleCOSError(c, err)
		return
	}
	defer resp.Body.Close()

	// 根据 S3 规范，成功删除（无论对象是否存在）都应返回 204 No Content
	// COS SDK 在对象不存在时也会返回 204，正好符合要求
	c.Status(http.StatusNoContent)
}

// PostObject 处理基于浏览器的表单上传 (POST Object)。
// POST /{bucket} (key 在表单字段中)
func (ctrl *S3Controller) PostObject(c *gin.Context) {
	// S3 POST 请求的 Content-Type 必须是 multipart/form-data
	if !strings.HasPrefix(c.GetHeader("Content-Type"), "multipart/form-data") {
		c.XML(http.StatusBadRequest, gin.H{"error": "Invalid Content-Type for POST upload"})
		return
	}

	form, err := c.MultipartForm()
	if err != nil {
		c.XML(http.StatusBadRequest, gin.H{"error": "Failed to parse multipart form"})
		return
	}

	// 提取 'key' 和 'file' 字段，忽略所有认证相关字段
	keyValues, okKey := form.Value["key"]
	fileHeaders, okFile := form.File["file"]
	if !okKey || len(keyValues) == 0 || !okFile || len(fileHeaders) == 0 {
		c.XML(http.StatusBadRequest, gin.H{"error": "'key' and 'file' fields are required"})
		return
	}
	key := keyValues[0]
	fileName := fileHeaders[0].Filename

	// 实现 ${filename} 占位符替换
	if strings.Contains(key, "${filename}") {
		key = strings.Replace(key, "${filename}", fileName, -1)
	}

	file, err := fileHeaders[0].Open()
	if err != nil {
		c.XML(http.StatusInternalServerError, gin.H{"error": "Failed to open uploaded file"})
		return
	}
	defer file.Close()

	// 准备 COS SDK 的 PutObjectOptions
	opt := &cos.ObjectPutOptions{
		ObjectPutHeaderOptions: &cos.ObjectPutHeaderOptions{
			ContentType:   fileHeaders[0].Header.Get("Content-Type"),
			ContentLength: fileHeaders[0].Size,
		},
	}

	// 调用 COS SDK 上传对象
	resp, err := ctrl.CosClient.Object.Put(c.Request.Context(), key, file, opt)
	if err != nil {
		ctrl.handleCOSError(c, err)
		return
	}
	defer resp.Body.Close()

	// 将 COS 返回的头部透传给客户端
	for h, values := range resp.Header {
		for _, value := range values {
			c.Header(h, value)
		}
	}
	c.Status(resp.StatusCode)
}

// ===================================================================
// ================= 分片上传 (Multipart Upload) =====================
// ===================================================================

// CreateMultipartUpload 处理初始化分片上传的请求。
// POST /{bucket}/{key}?uploads
func (ctrl *S3Controller) CreateMultipartUpload(c *gin.Context) {
	bucket, key := ctrl.extractBucketAndKey(c)
	if key == "" {
		c.XML(http.StatusBadRequest, gin.H{"error": "Invalid key"})
		return
	}

	// 准备 COS SDK 的 InitiateMultipartUploadOptions
	opt := &cos.InitiateMultipartUploadOptions{
		ObjectPutHeaderOptions: &cos.ObjectPutHeaderOptions{
			ContentType: c.GetHeader("Content-Type"),
		},
	}
	// 提取并设置自定义元数据
	for h, v := range c.Request.Header {
		if strings.HasPrefix(strings.ToLower(h), "x-amz-meta-") {
			if opt.ObjectPutHeaderOptions.XCosMetaXXX == nil {
				opt.ObjectPutHeaderOptions.XCosMetaXXX = &http.Header{}
			}
			cosMetaKey := "x-cos-meta-" + strings.TrimPrefix(strings.ToLower(h), "x-amz-meta-")
			opt.ObjectPutHeaderOptions.XCosMetaXXX.Set(cosMetaKey, v[0])
		}
	}

	// 调用 COS SDK 初始化分块上传
	result, resp, err := ctrl.CosClient.Object.InitiateMultipartUpload(c.Request.Context(), key, opt)
	if err != nil {
		ctrl.handleCOSError(c, err)
		return
	}

	if resp != nil {
		if resp.Body != nil {
			defer resp.Body.Close()
		}
		logCOSResponse("InitiateMultipartUpload", resp)
	}

	// 构造成 S3 标准的 XML 响应格式，并确保字段经过 XML 转义
	payload := struct {
		XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
		XMLNS    string   `xml:"xmlns,attr"`
		Bucket   string   `xml:"Bucket"`
		Key      string   `xml:"Key"`
		UploadID string   `xml:"UploadId"`
	}{
		XMLNS:    "http://s3.amazonaws.com/doc/2006-03-01/",
		Bucket:   bucket,
		Key:      key,
		UploadID: result.UploadID,
	}
	encoded, err := xml.MarshalIndent(payload, "", "  ")
	if err != nil {
		c.XML(http.StatusInternalServerError, gin.H{"error": "Failed to marshal CreateMultipartUpload response"})
		return
	}

	c.Data(http.StatusOK, "application/xml", []byte(xml.Header+string(encoded)))
}

// UploadPart 处理上传单个分片的请求。
// PUT /{bucket}/{key}?partNumber=N&uploadId=ID
func (ctrl *S3Controller) UploadPart(c *gin.Context) {
	_, key := ctrl.extractBucketAndKey(c)
	partNumber := c.Query("partNumber")
	uploadID := c.Query("uploadId")

	if key == "" || partNumber == "" || uploadID == "" {
		c.XML(http.StatusBadRequest, gin.H{"error": "Missing required parameters for UploadPart"})
		return
	}

	partNum, err := strconv.Atoi(partNumber)
	if err != nil {
		c.XML(http.StatusBadRequest, gin.H{"error": "Invalid partNumber"})
		return
	}

	// 调用 COS SDK 上传分片
	contentLength := c.Request.ContentLength
	if contentLength < 0 {
		c.XML(http.StatusLengthRequired, gin.H{"error": "Content-Length header is required for UploadPart"})
		return
	}

	uploadOpt := &cos.ObjectUploadPartOptions{
		ContentLength: contentLength,
	}
	if md5 := c.GetHeader("Content-MD5"); md5 != "" {
		uploadOpt.ContentMD5 = md5
	}
	if expect := c.GetHeader("Expect"); expect != "" {
		uploadOpt.Expect = expect
	}
	if sha1 := c.GetHeader("x-cos-content-sha1"); sha1 != "" {
		uploadOpt.XCosContentSHA1 = sha1
	}
	if sseAlg := c.GetHeader("x-amz-server-side-encryption-customer-algorithm"); sseAlg != "" {
		uploadOpt.XCosSSECustomerAglo = sseAlg
	}
	if sseKey := c.GetHeader("x-amz-server-side-encryption-customer-key"); sseKey != "" {
		uploadOpt.XCosSSECustomerKey = sseKey
	}
	if sseKeyMD5 := c.GetHeader("x-amz-server-side-encryption-customer-key-MD5"); sseKeyMD5 != "" {
		uploadOpt.XCosSSECustomerKeyMD5 = sseKeyMD5
	}
	if trafficLimit := c.GetHeader("x-cos-traffic-limit"); trafficLimit != "" {
		if uploadOpt.XOptionHeader == nil {
			uploadOpt.XOptionHeader = &http.Header{}
		}
		uploadOpt.XOptionHeader.Set("x-cos-traffic-limit", trafficLimit)
	}
	// 注意：COS SDK v5 的 UploadPart 方法会自动从 Reader 中计算 ContentLength
	resp, err := ctrl.CosClient.Object.UploadPart(c.Request.Context(), key, uploadID, partNum, c.Request.Body, uploadOpt)
	if err != nil {
		ctrl.handleCOSError(c, err)
		return
	}
	defer resp.Body.Close()

	logCOSResponse("UploadPart", resp)

	// 关键：从 COS 的响应中获取该分片的 ETag，并设置到响应头中
	etag := resp.Header.Get("ETag")
	if etag != "" {
		c.Header("ETag", etag)
	}

	c.Status(http.StatusOK)
}

// CompleteMultipartUpload 处理完成分片上传的请求。
// POST /{bucket}/{key}?uploadId=ID
func (ctrl *S3Controller) CompleteMultipartUpload(c *gin.Context) {
	bucket, key := ctrl.extractBucketAndKey(c)
	uploadID := c.Query("uploadId")

	if key == "" || uploadID == "" {
		c.XML(http.StatusBadRequest, gin.H{"error": "Missing required parameters for CompleteMultipartUpload"})
		return
	}

	// S3 规定请求体必须是 XML，Gin 的 ShouldBindXML 可以直接解析
	var completeUploadData struct {
		Parts []struct {
			PartNumber int    `xml:"PartNumber"`
			ETag       string `xml:"ETag"`
		} `xml:"Part"`
	}
	if err := c.ShouldBindXML(&completeUploadData); err != nil {
		c.XML(http.StatusBadRequest, gin.H{"error": "Invalid XML body"})
		return
	}

	// 将解析出的分片列表转换为 COS SDK 需要的格式
	cosParts := make([]cos.Object, len(completeUploadData.Parts))
	for i, p := range completeUploadData.Parts {
		cosParts[i] = cos.Object{
			PartNumber: p.PartNumber,
			// S3 ETag 规范会包含双引号，但 COS SDK 需要的是不含引号的原始 ETag
			ETag: strings.Trim(p.ETag, `"`),
		}
	}

	// 调用 COS SDK 完成分块上传
	compOpt := &cos.CompleteMultipartUploadOptions{Parts: cosParts}
	result, resp, err := ctrl.CosClient.Object.CompleteMultipartUpload(c.Request.Context(), key, uploadID, compOpt)
	if err != nil {
		ctrl.handleCOSError(c, err)
		return
	}

	if resp != nil {
		if resp.Body != nil {
			defer resp.Body.Close()
		}
		logCOSResponse("CompleteMultipartUpload", resp)
	}

	// 成功后，返回 S3 标准的成功 XML 响应，并确保字段经过 XML 转义
	responsePayload := struct {
		XMLName  xml.Name `xml:"CompleteMultipartUploadResult"`
		XMLNS    string   `xml:"xmlns,attr"`
		Location string   `xml:"Location"`
		Bucket   string   `xml:"Bucket"`
		Key      string   `xml:"Key"`
		ETag     string   `xml:"ETag"`
	}{
		XMLNS:    "http://s3.amazonaws.com/doc/2006-03-01/",
		Location: result.Location,
		Bucket:   bucket,
		Key:      key,
		ETag:     result.ETag,
	}
	encoded, err := xml.MarshalIndent(responsePayload, "", "  ")
	if err != nil {
		c.XML(http.StatusInternalServerError, gin.H{"error": "Failed to marshal CompleteMultipartUpload response"})
		return
	}

	c.Data(http.StatusOK, "application/xml", []byte(xml.Header+string(encoded)))
}

// AbortMultipartUpload 处理中止分片上传的请求。
// DELETE /{bucket}/{key}?uploadId=ID
func (ctrl *S3Controller) AbortMultipartUpload(c *gin.Context) {
	_, key := ctrl.extractBucketAndKey(c)
	uploadID := c.Query("uploadId")

	if key == "" || uploadID == "" {
		c.XML(http.StatusBadRequest, gin.H{"error": "Missing required parameters for AbortMultipartUpload"})
		return
	}

	// 调用 COS SDK 中止分块上传
	resp, err := ctrl.CosClient.Object.AbortMultipartUpload(c.Request.Context(), key, uploadID)
	if err != nil {
		ctrl.handleCOSError(c, err)
		return
	}
	if resp != nil {
		if resp.Body != nil {
			defer resp.Body.Close()
		}
		logCOSResponse("AbortMultipartUpload", resp)
	}

	// 根据 S3 规范，成功中止后应返回 204 No Content
	c.Status(http.StatusNoContent)
}

// ===================================================================
// ====================== 辅助函数 (Helpers) =======================
// ===================================================================

// extractBucketAndKey 从请求中解析出 bucket 和 key。
// 它实现了对虚拟托管类型 (bucket.domain.com) 和路径类型 (/bucket/key) 请求的兼容。
func (ctrl *S3Controller) extractBucketAndKey(c *gin.Context) (bucket, key string) {
	host := c.Request.Host
	path := c.Param("path") // 从 "/*path" 路由中获取

	// 1. 优先尝试虚拟托管类型 (Virtual-Hosted Style)
	// 例如: my-bucket.proxy.example.com
	if ctrl.BaseDomain != "" && strings.HasSuffix(host, ctrl.BaseDomain) {
		potentialBucket := strings.TrimSuffix(host, "."+ctrl.BaseDomain)
		if potentialBucket != "" && potentialBucket != host {
			bucket = potentialBucket
			key = strings.TrimPrefix(path, "/")
			return
		}
	}

	// 2. 回退到路径类型 (Path-Style)
	// 例如: /my-bucket/path/to/object.txt
	parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 2)
	if len(parts) >= 1 {
		bucket = parts[0]
	}
	if len(parts) == 2 {
		key = parts[1]
	}

	return
}

func logCOSResponse(operation string, resp *cos.Response) {
	if resp == nil || resp.Response == nil {
		return
	}

	dump, err := httputil.DumpResponse(resp.Response, true)
	if err != nil {
		log.Printf("failed to dump COS response for %s: %v", operation, err)
		return
	}

	log.Printf("COS %s response:\n%s", operation, string(dump))
}

// handleCOSError 是一个辅助函数，用于处理来自 COS SDK 的错误并返回 S3 兼容的 XML 响应。
func (ctrl *S3Controller) handleCOSError(c *gin.Context, err error) {
	if cosErr, ok := err.(*cos.ErrorResponse); ok {
		log.Printf("COS Error: Code=%s, Message=%s, RequestID=%s, StatusCode=%d", cosErr.Code, cosErr.Message, cosErr.RequestID, cosErr.Response.StatusCode)
		// 确保在函数结束时关闭原始响应体
		defer cosErr.Response.Body.Close()

		// 构建标准的 S3 XML 错误响应
		s3ErrorXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>%s</Code>
  <Message>%s</Message>
  <RequestId>%s</RequestId>
</Error>`, cosErr.Code, cosErr.Message, cosErr.RequestID)

		// 使用原始的HTTP状态码，但返回我们自己构建的、符合S3规范的XML
		c.Data(cosErr.Response.StatusCode, "application/xml; charset=utf-8", []byte(s3ErrorXML))
		return
	}

	// 对于非 COS SDK 的其他错误，返回通用的服务器错误
	log.Printf("Internal Server Error: %v", err)
	// 同样返回 S3 风格的错误 XML
	s3InternalErrorXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>InternalError</Code>
  <Message>%s</Message>
</Error>`, err.Error())
	c.Data(http.StatusInternalServerError, "application/xml; charset=utf-8", []byte(s3InternalErrorXML))
}
