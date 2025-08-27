package cmd

import (
	"context"
	"fmt"
	"os"
	"time"
	"encoding/json"

	"github.com/interlynk-io/sbomasm/pkg/securesbom"
	"github.com/spf13/cobra"
)

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a signed SBOM using Secure SBOM API",
	Long: `Verify the authenticity and integrity of a signed SBOM document.

The verify command takes a signed SBOM file, sends it to the Secure SBOM API
for verification, and reports whether the signature is valid. This ensures
the SBOM hasn't been tampered with since it was signed.

Examples:
  # Verify a signed SBOM
  sbomasm verify --sbom signed-sbom.json --key-id my-key-123 --api-key $API_KEY

  # Verify from stdin
  cat signed-sbom.json | sbomasm verify --key-id my-key-123 --api-key $API_KEY

  # Verify with environment variable for API key
  export SECURE_SBOM_API_KEY=your-api-key
  sbomasm verify --sbom signed-sbom.json --key-id my-key-123

  # Verify with custom API endpoint
  sbomasm verify --sbom signed-sbom.json --key-id my-key-123 --base-url https://custom.api.com

  # Verify with JSON output for automation
  sbomasm verify --sbom signed-sbom.json --key-id my-key-123 --output json`,
	RunE: runVerifyCommand,
}

// Verify command flags
var (
	verifySBOMPath   string
	verifyKeyID      string
	verifyAPIKey     string
	verifyBaseURL    string
	verifyOutputFormat string
	verifyTimeout    time.Duration
	verifyRetryCount int
	verifyQuiet      bool
)

// VerificationOutput represents the verification result output
type VerificationOutput struct {
	Valid     bool      `json:"valid"`
	Message   string    `json:"message,omitempty"`
	KeyID     string    `json:"key_id,omitempty"`
	Timestamp time.Time `json:"timestamp,omitempty"`
	Status    string    `json:"status"`
}

func init() {
	// Add verify command to root
	rootCmd.AddCommand(verifyCmd)

	// Required flags
	verifyCmd.Flags().StringVar(&verifySBOMPath, "sbom", "", "Path to signed SBOM file (use '-' for stdin)")
	verifyCmd.Flags().StringVar(&verifyKeyID, "key-id", "", "Key ID used to sign the SBOM")

	// Authentication flags
	verifyCmd.Flags().StringVar(&verifyAPIKey, "api-key", "", "API key for authentication (or set SECURE_SBOM_API_KEY)")
	verifyCmd.Flags().StringVar(&verifyBaseURL, "base-url", "", "Base URL for Secure SBOM API (or set SECURE_SBOM_BASE_URL)")

	// Output flags
	verifyCmd.Flags().StringVar(&verifyOutputFormat, "output", "text", "Output format: text, json")
	verifyCmd.Flags().BoolVar(&verifyQuiet, "quiet", false, "Suppress progress output (only show result)")

	// Advanced flags
	verifyCmd.Flags().DurationVar(&verifyTimeout, "timeout", 30*time.Second, "Request timeout")
	verifyCmd.Flags().IntVar(&verifyRetryCount, "retry", 3, "Number of retry attempts for failed requests")

	// Mark required flags
	verifyCmd.MarkFlagRequired("key-id")

	// Set up flag dependencies and validation
	verifyCmd.PreRunE = validateVerifyFlags
}

func validateVerifyFlags(cmd *cobra.Command, args []string) error {
	// Validate key ID
	if verifyKeyID == "" {
		return fmt.Errorf("--key-id is required")
	}

	// Check for API key in flag or environment
	if verifyAPIKey == "" {
		verifyAPIKey = os.Getenv("SECURE_SBOM_API_KEY")
		if verifyAPIKey == "" {
			return fmt.Errorf("API key is required. Use --api-key flag or set SECURE_SBOM_API_KEY environment variable")
		}
	}

	// Validate output format
	if verifyOutputFormat != "text" && verifyOutputFormat != "json" {
		return fmt.Errorf("--output must be 'text' or 'json'")
	}

	// Validate timeout
	if verifyTimeout <= 0 {
		return fmt.Errorf("--timeout must be positive")
	}

	// Validate retry count
	if verifyRetryCount < 0 {
		return fmt.Errorf("--retry cannot be negative")
	}

	return nil
}

func runVerifyCommand(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), verifyTimeout+10*time.Second)
	defer cancel()

	// Create SDK client using the same interface as signing
	client, err := createVerifyClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	// Load signed SBOM
	if !verifyQuiet {
		fmt.Fprintf(os.Stderr, "Loading signed SBOM...\n")
	}
	
	signedSBOM, err := loadSBOMForVerification()
	if err != nil {
		return fmt.Errorf("failed to load signed SBOM: %w", err)
	}

	// Perform health check
	if !verifyQuiet {
		fmt.Fprintf(os.Stderr, "Connecting to Secure SBOM API...\n")
	}
	
	if err := client.HealthCheck(ctx); err != nil {
		return fmt.Errorf("API health check failed: %w", err)
	}

	// Verify the SBOM
	if !verifyQuiet {
		fmt.Fprintf(os.Stderr, "Verifying SBOM signature with key %s...\n", verifyKeyID)
	}
	
	result, err := client.VerifySBOM(ctx, verifyKeyID, signedSBOM.Data())
	if err != nil {
		return fmt.Errorf("failed to verify SBOM: %w", err)
	}

	// Output the verification result
	if err := outputVerificationResult(result); err != nil {
		return fmt.Errorf("failed to output verification result: %w", err)
	}

	// Set exit code based on verification result
	if !result.Valid {
		os.Exit(1)
	}

	return nil
}

// Updated createVerifyClient to use the same interface as signing
func createVerifyClient() (securesbom.ClientInterface, error) {
	// Build configuration
	config := securesbom.NewConfigBuilder().
		WithAPIKey(verifyAPIKey).
		WithTimeout(verifyTimeout).
		FromEnv()

	if verifyBaseURL != "" {
		config = config.WithBaseURL(verifyBaseURL)
	}

	baseClient, err := config.BuildClient()
	if err != nil {
		return nil, err
	}

	// Wrap with retry logic if requested
	if verifyRetryCount > 0 {
		retryConfig := securesbom.RetryConfig{
			MaxAttempts: verifyRetryCount,
			InitialWait: 1 * time.Second,
			MaxWait:     10 * time.Second,
			Multiplier:  2.0,
		}
		return securesbom.WithRetryingClient(baseClient, retryConfig), nil
	}

	return baseClient, nil
}

func loadSBOMForVerification() (*securesbom.SBOM, error) {
	if verifySBOMPath == "" || verifySBOMPath == "-" {
		// Read from stdin
		return securesbom.LoadSBOMFromReader(os.Stdin)
	}

	// Read from file
	return securesbom.LoadSBOMFromFile(verifySBOMPath)
}

func outputVerificationResult(result *securesbom.VerifyResult) error {
	output := VerificationOutput{
		Valid:     result.Valid,
		Message:   result.Message,
		KeyID:     result.KeyID,
		Timestamp: result.Timestamp,
	}

	if result.Valid {
		output.Status = "VALID"
	} else {
		output.Status = "INVALID"
	}

	switch verifyOutputFormat {
	case "json":
		return outputVerificationJSON(output)
	case "text":
		return outputVerificationText(output)
	default:
		return fmt.Errorf("unsupported output format: %s", verifyOutputFormat)
	}
}

func outputVerificationJSON(output VerificationOutput) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func outputVerificationText(output VerificationOutput) error {
	if output.Valid {
		fmt.Printf("✓ SBOM signature is VALID\n")
	} else {
		fmt.Printf("✗ SBOM signature is INVALID\n")
	}

	if output.Message != "" {
		fmt.Printf("Message: %s\n", output.Message)
	}

	if output.KeyID != "" {
		fmt.Printf("Key ID: %s\n", output.KeyID)
	}

	if !output.Timestamp.IsZero() {
		fmt.Printf("Verified at: %s\n", output.Timestamp.Format(time.RFC3339))
	}

	return nil
}

// VerifyClientInterface allows for easier testing and mocking
//type VerifyClientInterface interface {
//	HealthCheck(ctx context.Context) error
//	VerifySBOM(ctx context.Context, keyID string, signedSBOM interface{}) (*securesbom.VerifyResult, error)
//}

// Ensure our clients implement the interface
//var _ VerifyClientInterface = (*securesbom.Client)(nil)
//var _ VerifyClientInterface = (*securesbom.RetryingClient)(nil)