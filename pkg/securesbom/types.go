package securesbom

import (
	"time"
	"net/http"
)

// Config holds configuration for the Secure SBOM API client
type Config struct {
	BaseURL string
	APIKey string
	HTTPClient HTTPClient
	Timeout time.Duration
	UserAgent string
}

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Key represents a cryptographic key in the system
type Key struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Algorithm string    `json:"algorithm,omitempty"`
}

// KeyListResponse contains the response from listing keys
type KeyListResponse struct {
	Keys []Key `json:"keys"`
}

// SignResult contains the result of a sign operation
/*
type SignResult struct {
	SignedSBOM interface{} `json:"signed_sbom"`
	Signature  string      `json:"signature,omitempty"`
	KeyID      string      `json:"key_id,omitempty"`
	Timestamp  time.Time   `json:"timestamp,omitempty"`
}
*/
type SignResult map[string]interface{}

// VerifyResult contains the result of a verify operation
type VerifyResult struct {
	Valid     bool      `json:"valid"`
	Message   string    `json:"message,omitempty"`
	KeyID     string    `json:"key_id,omitempty"`
	Algorithm string    `json:"algorithm,omitempty"`
	Timestamp time.Time `json:"timestamp,omitempty"`
}

// APIVerifyResponse represents the actual API response structure
type APIVerifyResponse struct {
	Message   string `json:"message"`
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
}
