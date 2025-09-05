package securesbom

import (
	"encoding/json"
)

// GetSignatureValue returns the signature value as a string for convenience
func (sr SignResultAPIResponse) GetSignatureValue() string {
	if sig, ok := sr["signature"].(map[string]interface{}); ok {
		if value, ok := sig["value"].(string); ok {
			return value
		}
	}
	return ""
}

// GetSignatureAlgorithm returns the signature algorithm
func (sr SignResultAPIResponse) GetSignatureAlgorithm() string {
	if sig, ok := sr["signature"].(map[string]interface{}); ok {
		if alg, ok := sig["algorithm"].(string); ok {
			return alg
		}
	}
	return ""
}

// GetSignedSBOMBytes returns the complete signed SBOM as JSON bytes
func (sr SignResultAPIResponse) GetSignedSBOMBytes() ([]byte, error) {
	return json.Marshal(sr)
}

// HasSignature returns true if the SBOM contains a signature
func (sr SignResultAPIResponse) HasSignature() bool {
	_, ok := sr["signature"]
	return ok
}
