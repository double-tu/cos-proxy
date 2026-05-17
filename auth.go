package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	awsSigV4Algorithm = "AWS4-HMAC-SHA256"
	awsSigV4Request   = "aws4_request"
	defaultAuthSkew   = 15 * time.Minute
	maxPresignExpiry  = 7 * 24 * time.Hour
)

var (
	errMissingSignature = errors.New("missing S3 signature")
	errInvalidSignature = errors.New("invalid S3 signature")
)

type s3SignatureAuthenticator struct {
	accessKey string
	secretKey string
	now       func() time.Time
	maxSkew   time.Duration
}

func newS3SignatureAuthenticator(accessKey, secretKey string) *s3SignatureAuthenticator {
	if accessKey == "" || secretKey == "" {
		return nil
	}

	return &s3SignatureAuthenticator{
		accessKey: accessKey,
		secretKey: secretKey,
		now:       time.Now,
		maxSkew:   defaultAuthSkew,
	}
}

func (a *s3SignatureAuthenticator) Verify(r *http.Request) error {
	if a == nil {
		return errMissingSignature
	}
	if r.URL.Query().Get("X-Amz-Signature") != "" {
		return a.verifyPresignedURL(r)
	}
	return a.verifyAuthorizationHeader(r)
}

func (a *s3SignatureAuthenticator) verifyAuthorizationHeader(r *http.Request) error {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return errMissingSignature
	}

	auth, err := parseAuthorizationHeader(authHeader)
	if err != nil {
		return err
	}
	if auth.accessKey != a.accessKey {
		return errInvalidSignature
	}
	amzDate := r.Header.Get("X-Amz-Date")
	if amzDate == "" {
		amzDate = r.Header.Get("Date")
	}
	if err := validateSignedTime(amzDate, a.now(), a.maxSkew); err != nil {
		return err
	}

	payloadHash := r.Header.Get("X-Amz-Content-Sha256")
	if payloadHash == "" {
		payloadHash = "UNSIGNED-PAYLOAD"
	}

	canonicalRequest, err := buildCanonicalRequest(r, auth.signedHeaders, "", payloadHash)
	if err != nil {
		return err
	}
	expected := a.signature(amzDate, auth.scope, canonicalRequest)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(auth.signature)) != 1 {
		return errInvalidSignature
	}
	return nil
}

func (a *s3SignatureAuthenticator) verifyPresignedURL(r *http.Request) error {
	q := r.URL.Query()
	if q.Get("X-Amz-Algorithm") != awsSigV4Algorithm {
		return errInvalidSignature
	}

	credential, err := parseCredential(q.Get("X-Amz-Credential"))
	if err != nil {
		return err
	}
	if credential.accessKey != a.accessKey {
		return errInvalidSignature
	}

	amzDate := q.Get("X-Amz-Date")
	signedAt, err := parseAmzDate(amzDate)
	if err != nil {
		return err
	}
	expiresSeconds, err := strconv.Atoi(q.Get("X-Amz-Expires"))
	if err != nil || expiresSeconds < 0 {
		return errInvalidSignature
	}
	expires := time.Duration(expiresSeconds) * time.Second
	if expires > maxPresignExpiry {
		return errInvalidSignature
	}
	now := a.now()
	if now.Before(signedAt.Add(-a.maxSkew)) || now.After(signedAt.Add(expires)) {
		return errInvalidSignature
	}

	signedHeaders := strings.Split(q.Get("X-Amz-SignedHeaders"), ";")
	if len(signedHeaders) == 0 || signedHeaders[0] == "" {
		return errInvalidSignature
	}

	payloadHash := q.Get("X-Amz-Content-Sha256")
	if payloadHash == "" {
		payloadHash = "UNSIGNED-PAYLOAD"
	}

	canonicalRequest, err := buildCanonicalRequest(r, signedHeaders, "X-Amz-Signature", payloadHash)
	if err != nil {
		return err
	}
	expected := a.signature(amzDate, credential.scope, canonicalRequest)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(q.Get("X-Amz-Signature"))) != 1 {
		return errInvalidSignature
	}
	return nil
}

func (a *s3SignatureAuthenticator) signature(amzDate, scope, canonicalRequest string) string {
	stringToSign := strings.Join([]string{
		awsSigV4Algorithm,
		amzDate,
		scope,
		hexSHA256(canonicalRequest),
	}, "\n")

	parts := strings.Split(scope, "/")
	if len(parts) != 4 {
		return ""
	}
	date, region, service := parts[0], parts[1], parts[2]
	signingKey := hmacSHA256([]byte("AWS4"+a.secretKey), date)
	signingKey = hmacSHA256(signingKey, region)
	signingKey = hmacSHA256(signingKey, service)
	signingKey = hmacSHA256(signingKey, awsSigV4Request)
	return hex.EncodeToString(hmacSHA256(signingKey, stringToSign))
}

type authorizationData struct {
	accessKey     string
	scope         string
	signedHeaders []string
	signature     string
}

type credentialData struct {
	accessKey string
	scope     string
}

func parseAuthorizationHeader(header string) (*authorizationData, error) {
	if !strings.HasPrefix(header, awsSigV4Algorithm+" ") {
		return nil, errInvalidSignature
	}

	values := map[string]string{}
	for _, part := range strings.Split(strings.TrimPrefix(header, awsSigV4Algorithm+" "), ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return nil, errInvalidSignature
		}
		values[key] = value
	}

	credential, err := parseCredential(values["Credential"])
	if err != nil {
		return nil, err
	}
	signedHeaders := strings.Split(values["SignedHeaders"], ";")
	if len(signedHeaders) == 0 || signedHeaders[0] == "" || values["Signature"] == "" {
		return nil, errInvalidSignature
	}

	return &authorizationData{
		accessKey:     credential.accessKey,
		scope:         credential.scope,
		signedHeaders: signedHeaders,
		signature:     values["Signature"],
	}, nil
}

func parseCredential(value string) (*credentialData, error) {
	parts := strings.Split(value, "/")
	if len(parts) != 5 || parts[4] != awsSigV4Request {
		return nil, errInvalidSignature
	}
	if parts[0] == "" || parts[1] == "" || parts[2] == "" || parts[3] == "" {
		return nil, errInvalidSignature
	}
	return &credentialData{
		accessKey: parts[0],
		scope:     strings.Join(parts[1:], "/"),
	}, nil
}

func validateSignedTime(amzDate string, now time.Time, maxSkew time.Duration) error {
	signedAt, err := parseAmzDate(amzDate)
	if err != nil {
		return err
	}
	if now.Before(signedAt.Add(-maxSkew)) || now.After(signedAt.Add(maxSkew)) {
		return errInvalidSignature
	}
	return nil
}

func parseAmzDate(value string) (time.Time, error) {
	t, err := time.Parse("20060102T150405Z", value)
	if err != nil {
		return time.Time{}, errInvalidSignature
	}
	return t, nil
}

func buildCanonicalRequest(r *http.Request, signedHeaders []string, ignoredQueryKey, payloadHash string) (string, error) {
	normalizedHeaders, canonicalHeaders, signedHeadersValue, err := canonicalizeHeaders(r, signedHeaders)
	if err != nil {
		return "", err
	}
	_ = normalizedHeaders

	return strings.Join([]string{
		r.Method,
		canonicalURI(r.URL),
		canonicalQuery(r.URL.Query(), ignoredQueryKey),
		canonicalHeaders,
		signedHeadersValue,
		payloadHash,
	}, "\n"), nil
}

func canonicalizeHeaders(r *http.Request, signedHeaders []string) (map[string]string, string, string, error) {
	normalized := make(map[string]string, len(signedHeaders))
	ordered := make([]string, 0, len(signedHeaders))
	seenHost := false

	for _, header := range signedHeaders {
		name := strings.ToLower(strings.TrimSpace(header))
		if name == "" {
			return nil, "", "", errInvalidSignature
		}
		if name == "host" {
			seenHost = true
			normalized[name] = strings.ToLower(r.Host)
		} else {
			values, ok := r.Header[http.CanonicalHeaderKey(name)]
			if !ok {
				return nil, "", "", fmt.Errorf("%w: missing signed header %s", errInvalidSignature, name)
			}
			normalized[name] = normalizeHeaderValue(strings.Join(values, ","))
		}
		ordered = append(ordered, name)
	}
	if !seenHost {
		return nil, "", "", errInvalidSignature
	}
	sort.Strings(ordered)

	var canonical strings.Builder
	for _, name := range ordered {
		canonical.WriteString(name)
		canonical.WriteByte(':')
		canonical.WriteString(normalized[name])
		canonical.WriteByte('\n')
	}

	return normalized, canonical.String(), strings.Join(ordered, ";"), nil
}

func normalizeHeaderValue(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func canonicalURI(u *url.URL) string {
	path := u.EscapedPath()
	if path == "" {
		return "/"
	}
	return path
}

func canonicalQuery(values url.Values, ignoredKey string) string {
	type pair struct {
		key   string
		value string
	}
	pairs := []pair{}
	for key, keyValues := range values {
		if strings.EqualFold(key, ignoredKey) {
			continue
		}
		for _, value := range keyValues {
			pairs = append(pairs, pair{key: sigV4Escape(key), value: sigV4Escape(value)})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].key == pairs[j].key {
			return pairs[i].value < pairs[j].value
		}
		return pairs[i].key < pairs[j].key
	})

	parts := make([]string, len(pairs))
	for i, pair := range pairs {
		parts[i] = pair.key + "=" + pair.value
	}
	return strings.Join(parts, "&")
}

func sigV4Escape(value string) string {
	return strings.ReplaceAll(url.QueryEscape(value), "+", "%20")
}

func hexSHA256(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(value))
	return mac.Sum(nil)
}
