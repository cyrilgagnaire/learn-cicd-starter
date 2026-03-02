package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey_MissingAuthorizationHeader(t *testing.T) {
	headers := http.Header{}

	_, err := GetAPIKey(headers)
	if err != ErrNoAuthHeaderIncluded {
		t.Fatalf("expected ErrNoAuthHeaderIncluded, got %v", err)
	}
}

func TestGetAPIKey_ValidAuthorizationHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey test-api-key")

	apiKey, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if apiKey != "test-api-key" {
		t.Fatalf("expected api key test-api-key, got %s", apiKey)
	}
}

func TestGetAPIKey_MalformedAuthorizationHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer test-api-key")

	_, err := GetAPIKey(headers)
	if err == nil {
		t.Fatal("expected malformed authorization header error, got nil")
	}
	if err.Error() != "malformed authorization header" {
		t.Fatalf("expected malformed authorization header error, got %v", err)
	}
}
