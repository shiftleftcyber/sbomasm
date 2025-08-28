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

// Keep GeneratedKey as the single key type
type GeneratedKey struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Algorithm string    `json:"algorithm"`
	PublicKey string    `json:"public_key,omitempty"` // Only populated for new keys
}

type KeyListResponse struct {
	Keys []GeneratedKey `json:"keys"` // Changed from []Key to []GeneratedKey
}

// Internal API response types (keep these for parsing)
type apiKeyListItem struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Algorithm string    `json:"algorithm"`
}

type apiGenerateKeyResponse struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

// GenerateKeyResponse represents the response from generating a new key
type GenerateKeyResponse struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

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
