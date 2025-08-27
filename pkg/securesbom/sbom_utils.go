package securesbom

import (
	"encoding/json"
)

// GetSignatureValue returns the signature value as a string for convenience
func (sr SignResult) GetSignatureValue() string {
	if sig, ok := sr["signature"].(map[string]interface{}); ok {
		if value, ok := sig["value"].(string); ok {
			return value
		}
	}
	return ""
}

// GetSignatureAlgorithm returns the signature algorithm
func (sr SignResult) GetSignatureAlgorithm() string {
	if sig, ok := sr["signature"].(map[string]interface{}); ok {
		if alg, ok := sig["algorithm"].(string); ok {
			return alg
		}
	}
	return ""
}

// GetSignedSBOMBytes returns the complete signed SBOM as JSON bytes
func (sr SignResult) GetSignedSBOMBytes() ([]byte, error) {
	return json.Marshal(sr)
}

// HasSignature returns true if the SBOM contains a signature
func (sr SignResult) HasSignature() bool {
	_, ok := sr["signature"]
	return ok
}
