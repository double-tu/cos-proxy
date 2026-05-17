package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestS3SignatureAuthenticatorVerifyAuthorizationHeader(t *testing.T) {
	auth := testAuthenticator()
	req := newSignedRequest(t, auth, "PUT", "http://s3.example.com/bucket/path/file.txt?x-id=PutObject", "hello")

	if err := auth.Verify(req); err != nil {
		t.Fatalf("expected valid signature, got %v", err)
	}
}

func TestS3SignatureAuthenticatorRejectsWrongSecret(t *testing.T) {
	signer := testAuthenticator()
	verifier := newS3SignatureAuthenticator("proxy-access", "wrong-secret")
	verifier.now = signer.now
	req := newSignedRequest(t, signer, "PUT", "http://s3.example.com/bucket/path/file.txt?x-id=PutObject", "hello")

	if err := verifier.Verify(req); err == nil {
		t.Fatal("expected invalid signature")
	}
}

func TestS3SignatureAuthenticatorVerifyPresignedURL(t *testing.T) {
	auth := testAuthenticator()
	req := newPresignedRequest(t, auth, "PUT", "http://s3.example.com/bucket/path/file.txt?x-id=PutObject", time.Hour)

	if err := auth.Verify(req); err != nil {
		t.Fatalf("expected valid presigned URL, got %v", err)
	}
}

func TestWriteAccessMiddlewareAllowsSignedRequestOutsideWhitelist(t *testing.T) {
	auth := testAuthenticator()
	req := newSignedRequest(t, auth, "PUT", "http://s3.example.com/bucket/path/file.txt?x-id=PutObject", "hello")
	req.Header.Set("X-Real-IP", "203.0.113.10")
	recorder := httptest.NewRecorder()

	writeAccessMiddleware(map[string]bool{}, auth)(newTestContext(recorder, req))

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected middleware to allow signed request, got status %d", recorder.Code)
	}
}

func TestWriteAccessMiddlewareRejectsUnsignedRequestOutsideWhitelist(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "http://s3.example.com/bucket/path/file.txt", nil)
	req.Header.Set("X-Real-IP", "203.0.113.10")
	recorder := httptest.NewRecorder()

	writeAccessMiddleware(map[string]bool{}, testAuthenticator())(newTestContext(recorder, req))

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected middleware to reject unsigned request, got status %d", recorder.Code)
	}
}

func TestStripClientS3AuthPreservesS3OperationQuery(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "http://s3.example.com/bucket/path/file.txt?x-id=PutObject&uploadId=abc&X-Amz-Signature=sig&X-Amz-Date=20260517T163000Z", nil)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 test")
	req.Header.Set("X-Amz-Security-Token", "token")

	stripClientS3Auth(req)

	if req.Header.Get("Authorization") != "" || req.Header.Get("X-Amz-Security-Token") != "" {
		t.Fatal("expected client auth headers to be stripped")
	}
	if req.URL.Query().Get("X-Amz-Signature") != "" || req.URL.Query().Get("X-Amz-Date") != "" {
		t.Fatal("expected presign query parameters to be stripped")
	}
	if req.URL.Query().Get("x-id") != "PutObject" || req.URL.Query().Get("uploadId") != "abc" {
		t.Fatalf("expected S3 operation query parameters to be preserved, got %q", req.URL.RawQuery)
	}
}

func testAuthenticator() *s3SignatureAuthenticator {
	auth := newS3SignatureAuthenticator("proxy-access", "proxy-secret")
	auth.now = func() time.Time { return time.Date(2026, 5, 17, 16, 30, 0, 0, time.UTC) }
	return auth
}

func newSignedRequest(t *testing.T, auth *s3SignatureAuthenticator, method, target, body string) *http.Request {
	t.Helper()

	req := httptest.NewRequest(method, target, bytes.NewBufferString(body))
	req.Host = req.URL.Host
	req.Header.Set("X-Amz-Date", "20260517T163000Z")
	payloadSum := sha256.Sum256([]byte(body))
	payloadHash := hex.EncodeToString(payloadSum[:])
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	scope := "20260517/us-east-1/s3/aws4_request"
	signedHeaders := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	canonicalRequest, err := buildCanonicalRequest(req, signedHeaders, "", payloadHash)
	if err != nil {
		t.Fatal(err)
	}
	signature := auth.signature("20260517T163000Z", scope, canonicalRequest)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=proxy-access/"+scope+", SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature="+signature)
	return req
}

func newPresignedRequest(t *testing.T, auth *s3SignatureAuthenticator, method, target string, expires time.Duration) *http.Request {
	t.Helper()

	req := httptest.NewRequest(method, target, nil)
	req.Host = req.URL.Host
	q := req.URL.Query()
	q.Set("X-Amz-Algorithm", awsSigV4Algorithm)
	q.Set("X-Amz-Credential", "proxy-access/20260517/us-east-1/s3/aws4_request")
	q.Set("X-Amz-Date", "20260517T163000Z")
	q.Set("X-Amz-Expires", strconv.Itoa(int(expires.Seconds())))
	q.Set("X-Amz-SignedHeaders", "host")
	req.URL.RawQuery = q.Encode()

	canonicalRequest, err := buildCanonicalRequest(req, []string{"host"}, "X-Amz-Signature", "UNSIGNED-PAYLOAD")
	if err != nil {
		t.Fatal(err)
	}
	signature := auth.signature("20260517T163000Z", "20260517/us-east-1/s3/aws4_request", canonicalRequest)
	q = req.URL.Query()
	q.Set("X-Amz-Signature", signature)
	req.URL.RawQuery = q.Encode()
	return req
}

func newTestContext(recorder *httptest.ResponseRecorder, req *http.Request) *gin.Context {
	gin.SetMode(gin.TestMode)
	context, _ := gin.CreateTestContext(recorder)
	context.Request = req
	return context
}
