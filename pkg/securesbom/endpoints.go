package securesbom

import (
	"net/http"
)

const (
	API_VERSION = "/v0"
	API_ENDPOINT_HEALTHCHECK = "/infra/healthcheck"
	API_ENDPOINT_KEYS = "/keys"
	API_ENDPOINT_SBOM = "/sbom"

	HTTP_METHOD_POST = http.MethodPost
)