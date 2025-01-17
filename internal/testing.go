package internal

import (
	"crypto"
	"encoding/base64"
	"encoding/json"

	"github.com/go-jose/go-jose/v4"
)

var (
	//EC keys were generated on `mkjwk.org`

	ExchangeKey1, ExchangeKey1Thp = KeyFromJson(`{
		"alg": "ECMR",
		"crv": "P-512",
		"kid": "2c739699-f497-46f9-8f8a-66d237c08a29",
		"kty": "EC",
		"use": "exchange",
		"d": "AbvskQAdy2M7MHSKvR45mGJLEgUq1-RAngkY3mEdrm-x6-qQGGDX0hQ89NvoERuVwxwhitskrLzC0VTrZ9mBArMN",
		"x": "AQ9iDNelRXRZZQTTpzR7imHIMGYG1-qQ6uif6Lj6eFpbUMf07gydd6K9Z2HQ_DAfRgf5JiQhrUdXzwB5xCqB53Pc",
		"y": "AIpTGuqfOMSLP0cNl1J8rQfgamnIMuTDcUrk3dSpif8jD2cKWTJaaIhffPG2XLxaJtSNZNGFZXvObhBghb_8X8GQ"
	}`)
	ExchangeKey1ID = "2c739699-f497-46f9-8f8a-66d237c08a29"
)

// Test helpers

func KeyFromJson(jsonData string) (jose.JSONWebKey, string) {
	var result jose.JSONWebKey
	_ = json.Unmarshal([]byte(jsonData), &result)
	thp, _ := result.Thumbprint(crypto.SHA256)
	return result, base64.RawURLEncoding.EncodeToString(thp)
}
