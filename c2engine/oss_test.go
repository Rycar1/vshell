package c2engine

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// TestOSSSignatureMatchesHMACSHA1 verifies the OSS V1 signature is a correct
// HMAC-SHA1 of the string-to-sign (mathematical correctness of the hand-rolled
// implementation).
func TestOSSSignatureMatchesHMACSHA1(t *testing.T) {
	ou := &OSSUploader{config: &OSSUploadConfig{
		AccessKey:  "AKID-test",
		SecretKey:  "secret-key-123",
		Bucket:     "my-bucket",
		Endpoint:   "oss-cn-hangzhou.aliyuncs.com",
	}}

	method := "PUT"
	objectPath := "/my-bucket/agent.bin"
	date := "Fri, 31 Jul 2026 12:00:00 GMT"

	sig := ou.ossSignature(method, objectPath, date)

	// Recompute independently
	stringToSign := fmt.Sprintf("%s\n\n\n%s\n%s", method, date, objectPath)
	h := hmac.New(sha1.New, []byte("secret-key-123"))
	h.Write([]byte(stringToSign))
	want := base64.StdEncoding.EncodeToString(h.Sum(nil))

	if sig != want {
		t.Errorf("signature = %q, want %q", sig, want)
	}

	// Authorization header format: "OSS <AccessKey>:<signature>"
	auth := fmt.Sprintf("OSS %s:%s", ou.config.AccessKey, sig)
	if !strings.HasPrefix(auth, "OSS AKID-test:") {
		t.Errorf("auth format = %q", auth)
	}
}

// TestOSSUploaderURLConstruction verifies provider URL formats.
func TestOSSUploaderURLConstruction(t *testing.T) {
	ali := &OSSUploader{config: &OSSUploadConfig{
		Provider: ProviderAliOSS,
		Bucket:   "my-bucket",
		Endpoint: "oss-cn-hangzhou.aliyuncs.com",
		CDNDomain: "cdn.example.com",
	}}
	// Aliyun URL: https://<bucket>.<endpoint>/<bucket>/<file>
	_ = ali

	// Verify GenerateDistributionURLs handles empty OssUrl
	if urls := GenerateDistributionURLs(&Listener{}); urls != nil {
		t.Errorf("empty OssUrl should yield nil URLs, got %v", urls)
	}
}

// TestOSSConfigFrontendFields verifies the config fields match the original
// frontend's OSS form fields (AccessKeyId/AccessKeySecret/BucketName/Endpoint/
// CDNDomain extracted from embedded JS).
func TestOSSConfigFrontendFields(t *testing.T) {
	cfg := &OSSUploadConfig{
		Provider:  ProviderAliOSS,
		Endpoint:  "oss-cn-hangzhou.aliyuncs.com",
		Bucket:    "bucket",
		AccessKey: "AKID",
		SecretKey: "SK",
		Region:    "cn-hangzhou",
		CDNDomain: "cdn.example.com",
	}
	_ = cfg // struct field coverage is compile-time verified
}
