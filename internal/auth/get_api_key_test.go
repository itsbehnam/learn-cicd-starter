package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	// Test case: Missing Authorization header
	headers := http.Header{}
	_, err := GetAPIKey(headers)
	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("expected error %v, got %v", ErrNoAuthHeaderIncluded, err)
	}

	// Test case: Malformed Authorization header
	headers.Set("Authorization", "Bearer abcdef123456")
	_, err = GetAPIKey(headers)
	if err == nil || err.Error() != "malformed authorization header" {
		t.Errorf("expected malformed authorization header error, got %v", err)
	}

	// Test case: Correct Authorization header
	headers.Set("Authorization", "ApiKey abcdef123456")
	apiKey, err := GetAPIKey(headers)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if apiKey != "abcdef123456" {
		t.Errorf("expected apiKey 'abcdef123456', got %v", apiKey)
	}
}
