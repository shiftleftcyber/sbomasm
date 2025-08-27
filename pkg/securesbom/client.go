// Package securesbom provides a Go SDK for interacting with the Secure SBOM API.
//
// This SDK is designed to be framework-agnostic and can be used in CLI tools,
// web applications, or any other Go application that needs to sign and verify SBOMs.
//
// Basic usage:
//
//	client := securesbom.NewClient(&securesbom.Config{
//		BaseURL: "https://your-api.googleapis.com",
//		APIKey:  "your-api-key",
//	})
//
//	// Sign an SBOM
//	result, err := client.SignSBOM(ctx, "key-id", sbomData)
//
//	// Verify an SBOM
//	result, err := client.VerifySBOM(ctx, "key-id", signedSBOM)

package securesbom

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"mime/multipart"
)

const (
	DefaultTimeout = 30 * time.Second
	
	UserAgent = "secure-sbom-sdk-go/1.0"
)

// Client provides access to the Secure SBOM API
type Client struct {
	config     *Config
	httpClient HTTPClient
}

type ClientInterface interface {
    HealthCheck(ctx context.Context) error
    ListKeys(ctx context.Context) (*KeyListResponse, error)
    GenerateKey(ctx context.Context) (*Key, error)
    GetPublicKey(ctx context.Context, keyID string) (string, error)
    SignSBOM(ctx context.Context, keyID string, sbom interface{}) (*SignResult, error)
    VerifySBOM(ctx context.Context, keyID string, signedSBOM interface{}) (*VerifyResult, error)
}

func (e *APIError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("secure-sbom API error %d: %s (%s)", e.StatusCode, e.Message, e.Details)
	}
	return fmt.Sprintf("secure-sbom API error %d: %s", e.StatusCode, e.Message)
}

// Temporary returns true if the error is likely temporary and retryable
func (e *APIError) Temporary() bool {
	return e.StatusCode >= 500 || e.StatusCode == 429
}

// NewClient creates a new Secure SBOM API client
func NewClient(config *Config) (*Client, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}
	
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Create a copy to avoid mutation
	cfg := *config
	
	// Set defaults
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = UserAgent
	}
	
	// Create HTTP client if not provided
	var httpClient HTTPClient = cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: cfg.Timeout,
		}
	}

	return &Client{
		config:     &cfg,
		httpClient: httpClient,
	}, nil
}

// validateConfig validates the client configuration
func validateConfig(config *Config) error {
	if config.APIKey == "" {
		return fmt.Errorf("APIKey is required")
	}
	
	if config.BaseURL == "" {
		return fmt.Errorf("BaseURL is required")
	}
	
	// Validate base URL format
	if _, err := url.Parse(config.BaseURL); err != nil {
		return fmt.Errorf("invalid BaseURL: %w", err)
	}
	
	if config.Timeout < 0 {
		return fmt.Errorf("Timeout cannot be negative")
	}
	
	return nil
}

// buildURL constructs a full URL for the given endpoint
func (c *Client) buildURL(endpoint string) string {
	baseURL := strings.TrimSuffix(c.config.BaseURL, "/")
	endpoint = strings.TrimPrefix(endpoint, "/")
	return fmt.Sprintf("%s/%s", baseURL, endpoint)
}

// doRequest performs an HTTP request with proper authentication and error handling
func (c *Client) doRequest(ctx context.Context, method, endpoint string, body interface{}) (*http.Response, error) {
	url := c.buildURL(endpoint)
	
	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set authentication and headers
	req.Header.Set("x-api-key", c.config.APIKey)
	req.Header.Set("User-Agent", c.config.UserAgent)
	req.Header.Set("Accept", "application/json")
	
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	// Handle HTTP error status codes
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		
		apiErr := &APIError{
			StatusCode: resp.StatusCode,
			Message:    http.StatusText(resp.StatusCode),
		}
		
		// Try to parse structured error response
		if bodyBytes, err := io.ReadAll(resp.Body); err == nil && len(bodyBytes) > 0 {
			var errorResp struct {
				Message   string `json:"message"`
				Details   string `json:"details"`
				RequestID string `json:"request_id"`
				Error     string `json:"error"` // Alternative field name
			}
			
			if json.Unmarshal(bodyBytes, &errorResp) == nil {
				if errorResp.Message != "" {
					apiErr.Message = errorResp.Message
				} else if errorResp.Error != "" {
					apiErr.Message = errorResp.Error
				}
				apiErr.Details = errorResp.Details
				apiErr.RequestID = errorResp.RequestID
			}
		}
		
		return nil, apiErr
	}

	return resp, nil
}

// doMultipartRequest performs an HTTP request with multipart content
func (c *Client) doMultipartRequest(ctx context.Context, method, endpoint string, body io.Reader, contentType string) (*http.Response, error) {
	url := c.buildURL(endpoint)

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set authentication and headers
	req.Header.Set("x-api-key", c.config.APIKey)
	req.Header.Set("User-Agent", c.config.UserAgent)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", contentType)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	// Handle HTTP error status codes (same logic as doRequest)
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		
		apiErr := &APIError{
			StatusCode: resp.StatusCode,
			Message:    http.StatusText(resp.StatusCode),
		}
		
		// Try to parse structured error response
		if bodyBytes, err := io.ReadAll(resp.Body); err == nil && len(bodyBytes) > 0 {
			var errorResp struct {
				Message   string `json:"message"`
				Details   string `json:"details"`
				RequestID string `json:"request_id"`
				Error     string `json:"error"` // Alternative field name
			}
			
			if json.Unmarshal(bodyBytes, &errorResp) == nil {
				if errorResp.Message != "" {
					apiErr.Message = errorResp.Message
				} else if errorResp.Error != "" {
					apiErr.Message = errorResp.Error
				}
				apiErr.Details = errorResp.Details
				apiErr.RequestID = errorResp.RequestID
			}
		}
		
		return nil, apiErr
	}

	return resp, nil
}

// HealthCheck verifies that the API is accessible and responding
func (c *Client) HealthCheck(ctx context.Context) error {
	resp, err := c.doRequest(ctx, "GET", "/infra/healthcheck", nil)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()
	
	return nil
}

// ListKeys retrieves all available signing keys
func (c *Client) ListKeys(ctx context.Context) (*KeyListResponse, error) {
	resp, err := c.doRequest(ctx, "GET", "/v0/keys", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}
	defer resp.Body.Close()

	var result KeyListResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// GenerateKey creates a new signing key
func (c *Client) GenerateKey(ctx context.Context) (*Key, error) {
	resp, err := c.doRequest(ctx, "POST", "/v0/keys", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	defer resp.Body.Close()

	var key Key
	if err := json.NewDecoder(resp.Body).Decode(&key); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &key, nil
}

// GetPublicKey retrieves the public key in PEM format for the specified key ID
func (c *Client) GetPublicKey(ctx context.Context, keyID string) (string, error) {
	if keyID == "" {
		return "", fmt.Errorf("keyID is required")
	}

	endpoint := fmt.Sprintf("/v0/keys/%s/public.pem", keyID)
	resp, err := c.doRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("failed to get public key: %w", err)
	}
	defer resp.Body.Close()

	pemBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	return string(pemBytes), nil
}

func (c *Client) SignSBOM(ctx context.Context, keyID string, sbom interface{}) (*SignResult, error) {
	if keyID == "" {
		return nil, fmt.Errorf("keyID is required")
	}
	if sbom == nil {
		return nil, fmt.Errorf("sbom is required")
	}

	endpoint := fmt.Sprintf("/v0/sbom/%s/sign?sigType=simple", keyID)
	
	// Convert SBOM to JSON bytes
	sbomBytes, err := json.Marshal(sbom)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SBOM: %w", err)
	}

	// Create multipart form
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	
	// Create form file field
	part, err := writer.CreateFormFile("sbom", "sbom.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create form file: %w", err)
	}
	
	// Write SBOM data to the form file
	if _, err := part.Write(sbomBytes); err != nil {
		return nil, fmt.Errorf("failed to write SBOM data: %w", err)
	}
	
	// Close the writer to finalize the form
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close form writer: %w", err)
	}

	// Make the request with multipart content
	resp, err := c.doMultipartRequest(ctx, "POST", endpoint, &buf, writer.FormDataContentType())
	if err != nil {
		return nil, fmt.Errorf("failed to sign SBOM: %w", err)
	}
	defer resp.Body.Close()

	var result SignResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// VerifySBOM verifies a signed SBOM using the specified key
func (c *Client) VerifySBOM(ctx context.Context, keyID string, signedSBOM interface{}) (*VerifyResult, error) {
	if keyID == "" {
		return nil, fmt.Errorf("keyID is required")
	}
	if signedSBOM == nil {
		return nil, fmt.Errorf("signedSBOM is required")
	}

	endpoint := fmt.Sprintf("/v0/sbom/%s/verify", keyID)
	
	// Convert signed SBOM to JSON bytes
	signedSBOMBytes, err := json.Marshal(signedSBOM)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signed SBOM: %w", err)
	}

	// Create multipart form
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	
	// Create form file field with the correct field name for verification
	part, err := writer.CreateFormFile("signedSBOM", "signed-sbom.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create form file: %w", err)
	}
	
	// Write signed SBOM data to the form file
	if _, err := part.Write(signedSBOMBytes); err != nil {
		return nil, fmt.Errorf("failed to write signed SBOM data: %w", err)
	}
	
	// Close the writer to finalize the form
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close form writer: %w", err)
	}

	// Make the request with multipart content
	resp, err := c.doMultipartRequest(ctx, "POST", endpoint, &buf, writer.FormDataContentType())
	if err != nil {
		return nil, fmt.Errorf("failed to verify SBOM: %w", err)
	}
	defer resp.Body.Close()

	// Read response body for both success and error cases
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Handle different HTTP status codes
	switch resp.StatusCode {
	case 200:
		// Success case - signature is valid
		var apiResp APIVerifyResponse
		if err := json.Unmarshal(bodyBytes, &apiResp); err != nil {
			return nil, fmt.Errorf("failed to decode success response: %w", err)
		}
		
		return &VerifyResult{
			Valid:     true,
			Message:   apiResp.Message,
			KeyID:     apiResp.KeyID,
			Algorithm: apiResp.Algorithm,
			Timestamp: time.Now(),
		}, nil
		
	case 500:
		// Error case - signature verification failed
		// First try to parse as structured error response
		var apiErr APIErrorResponse
		if err := json.Unmarshal(bodyBytes, &apiErr); err != nil {
			// If JSON parsing fails, treat the response as plain text
			errorMsg := strings.TrimSpace(string(bodyBytes))
			if errorMsg == "" {
				errorMsg = "signature verification failed"
			}
			return &VerifyResult{
				Valid:     false,
				Message:   errorMsg,
				Timestamp: time.Now(),
			}, nil
		}
		
		// Use structured error response
		errorMessage := apiErr.Message
		if errorMessage == "" {
			errorMessage = apiErr.Error
		}
		if errorMessage == "" {
			errorMessage = "signature verification failed"
		}
		
		return &VerifyResult{
			Valid:     false,
			Message:   errorMessage,
			Timestamp: time.Now(),
		}, nil
		
	default:
		// Unexpected HTTP status code
		return nil, fmt.Errorf("unexpected response status %d: %s", resp.StatusCode, string(bodyBytes))
	}
}
