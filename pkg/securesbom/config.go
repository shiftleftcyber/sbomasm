package securesbom

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
	"math"
)

// ConfigBuilder provides a fluent interface for building client configurations
type ConfigBuilder struct {
	config Config
}

// SBOM represents an SBOM document
type SBOM struct {
	data interface{}
}

// RetryConfig configures retry behavior for operations
type RetryConfig struct {
	MaxAttempts int
	InitialWait time.Duration
	MaxWait     time.Duration
	Multiplier  float64
}

// ClientOption represents a configuration option for the client
type ClientOption func(*Config)

// RetryingClient wraps the base client with retry logic
type RetryingClient struct {
	client      *Client
	retryConfig RetryConfig
}

// NewConfigBuilder creates a new configuration builder
func NewConfigBuilder() *ConfigBuilder {
	return &ConfigBuilder{}
}

// WithBaseURL sets the API base URL
func (b *ConfigBuilder) WithBaseURL(baseURL string) *ConfigBuilder {
	b.config.BaseURL = baseURL
	return b
}

// WithAPIKey sets the API key
func (b *ConfigBuilder) WithAPIKey(apiKey string) *ConfigBuilder {
	b.config.APIKey = apiKey
	return b
}

// WithTimeout sets the request timeout
func (b *ConfigBuilder) WithTimeout(timeout time.Duration) *ConfigBuilder {
	b.config.Timeout = timeout
	return b
}

func (b *ConfigBuilder) WithHTTPClient(client HTTPClient) *ConfigBuilder {
	b.config.HTTPClient = client
	return b
}

func (b *ConfigBuilder) WithUserAgent(userAgent string) *ConfigBuilder {
	b.config.UserAgent = userAgent
	return b
}

// FromEnv populates configuration from environment variables
func (b *ConfigBuilder) FromEnv() *ConfigBuilder {
	if apiKey := os.Getenv("SECURE_SBOM_API_KEY"); apiKey != "" {
		b.config.APIKey = apiKey
	}
	if baseURL := os.Getenv("SECURE_SBOM_BASE_URL"); baseURL != "" {
		b.config.BaseURL = baseURL
	}
	return b
}

// Build creates the final configuration
func (b *ConfigBuilder) Build() *Config {
	// Return a copy to prevent external mutation
	config := b.config
	return &config
}

// BuildClient creates a client with the built configuration
func (b *ConfigBuilder) BuildClient() (*Client, error) {
	return NewClient(b.Build())
}

// NewSBOM creates a new SBOM from data
func NewSBOM(data interface{}) *SBOM {
	return &SBOM{data: data}
}

// LoadSBOMFromReader loads an SBOM from an io.Reader
func LoadSBOMFromReader(reader io.Reader) (*SBOM, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read data: %w", err)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("no data provided")
	}

	var sbomData interface{}
	if err := json.Unmarshal(data, &sbomData); err != nil {
		return nil, fmt.Errorf("failed to parse SBOM JSON: %w", err)
	}

	return &SBOM{data: sbomData}, nil
}

// LoadSBOMFromFile loads an SBOM from a file
func LoadSBOMFromFile(filePath string) (*SBOM, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer file.Close()

	return LoadSBOMFromReader(file)
}

// Data returns the raw SBOM data
func (s *SBOM) Data() interface{} {
	return s.data
}

// WriteToWriter writes the SBOM to an io.Writer
func (s *SBOM) WriteToWriter(writer io.Writer) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(s.data)
}

// WriteToFile writes the SBOM to a file
func (s *SBOM) WriteToFile(filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", filePath, err)
	}
	defer file.Close()

	return s.WriteToWriter(file)
}

// String returns a JSON string representation of the SBOM
func (s *SBOM) String() string {
	data, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error marshaling SBOM: %v", err)
	}
	return string(data)
}

// DefaultRetryConfig returns a sensible default retry configuration
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts: 3,
		InitialWait: 1 * time.Second,
		MaxWait:     10 * time.Second,
		Multiplier:  2.0,
	}
}

// WithRetry wraps a function to retry on temporary failures
func WithRetry(ctx context.Context, config RetryConfig, fn func() error) error {
	var lastErr error
	
	for attempt := 0; attempt < config.MaxAttempts; attempt++ {
		if err := fn(); err != nil {
			lastErr = err
			
			// Check if error is retryable
			if apiErr, ok := err.(*APIError); ok && !apiErr.Temporary() {
				return err // Don't retry non-temporary errors
			}
			
			// Don't wait after the last attempt
			if attempt == config.MaxAttempts-1 {
				break
			}
			
			// Calculate wait time with exponential backoff
			waitTime := time.Duration(float64(config.InitialWait) * 
				math.Pow(config.Multiplier, float64(attempt)))
			if waitTime > config.MaxWait {
				waitTime = config.MaxWait
			}
			
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(waitTime):
				// Continue to next attempt
			}
		} else {
			return nil // Success
		}
	}
	
	return fmt.Errorf("operation failed after %d attempts: %w", config.MaxAttempts, lastErr)
}

// WithRetryingClient wraps a client with retry logic
func WithRetryingClient(client *Client, retryConfig RetryConfig) *RetryingClient {
	return &RetryingClient{
		client:      client,
		retryConfig: retryConfig,
	}
}

// HealthCheck performs a health check with retries
func (r *RetryingClient) HealthCheck(ctx context.Context) error {
	return WithRetry(ctx, r.retryConfig, func() error {
		return r.client.HealthCheck(ctx)
	})
}

// Update RetryingClient methods to use GeneratedKey
func (r *RetryingClient) ListKeys(ctx context.Context) (*KeyListResponse, error) {
	var result *KeyListResponse
	err := WithRetry(ctx, r.retryConfig, func() error {
		var err error
		result, err = r.client.ListKeys(ctx)
		return err
	})
	return result, err
}

// Update GenerateKey to return *GeneratedKey (change from *Key)
func (r *RetryingClient) GenerateKey(ctx context.Context) (*GeneratedKey, error) {
	var result *GeneratedKey
	err := WithRetry(ctx, r.retryConfig, func() error {
		var err error
		result, err = r.client.GenerateKey(ctx)
		return err
	})
	return result, err
}

// GetPublicKey gets a public key with retries
func (r *RetryingClient) GetPublicKey(ctx context.Context, keyID string) (string, error) {
	var result string
	err := WithRetry(ctx, r.retryConfig, func() error {
		var err error
		result, err = r.client.GetPublicKey(ctx, keyID)
		return err
	})
	return result, err
}

func (r *RetryingClient) SignSBOM(ctx context.Context, keyID string, sbom interface{}) (*SignResult, error) {
	var result *SignResult
	err := WithRetry(ctx, r.retryConfig, func() error {
		var err error
		result, err = r.client.SignSBOM(ctx, keyID, sbom)
		return err
	})
	return result, err
}

// VerifySBOM verifies an SBOM with retries
func (r *RetryingClient) VerifySBOM(ctx context.Context, keyID string, signedSBOM interface{}) (*VerifyResult, error) {
	var result *VerifyResult
	err := WithRetry(ctx, r.retryConfig, func() error {
		var err error
		result, err = r.client.VerifySBOM(ctx, keyID, signedSBOM)
		return err
	})
	return result, err
}
