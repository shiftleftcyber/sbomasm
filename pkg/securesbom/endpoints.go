package securesbom

import (
	"net/http"
)

const (
	API_VERSION = "/v0"
	API_ENDPOINT_HEALTHCHECK = "/infra/healthcheck"
	API_ENDPOINT_KEYS = "/keys"
	API_ENDPOINT_SBOM = "/sbom"

	DEFAULT_SECURE_SBOM_BASE_URL = "https://secure-sbom-api-prod-gateway-dhncnyq8.uc.gateway.dev"

	HTTP_METHOD_GET = http.MethodGet
	HTTP_METHOD_POST = http.MethodPost
)