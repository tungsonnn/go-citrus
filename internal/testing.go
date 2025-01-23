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
		"kty": "EC",
		"alg": "ECMR",
		"d": "AbvskQAdy2M7MHSKvR45mGJLEgUq1-RAngkY3mEdrm-x6-qQGGDX0hQ89NvoERuVwxwhitskrLzC0VTrZ9mBArMN",
		"use": "exchange",
		"crv": "P-521",
		"kid": "2c739699-f497-46f9-8f8a-66d237c08a29",
		"x": "AQ9iDNelRXRZZQTTpzR7imHIMGYG1-qQ6uif6Lj6eFpbUMf07gydd6K9Z2HQ_DAfRgf5JiQhrUdXzwB5xCqB53Pc",
		"y": "AIpTGuqfOMSLP0cNl1J8rQfgamnIMuTDcUrk3dSpif8jD2cKWTJaaIhffPG2XLxaJtSNZNGFZXvObhBghb_8X8GQ"
	}`)
	ExchangeKey1Id = "2c739699-f497-46f9-8f8a-66d237c08a29"

	ExchangeKey2, ExchangeKey2Thp = KeyFromJson(`{
		"kty": "EC",
		"alg": "ECMR",
		"d": "AS0rirJe34fIQbrC5qhQbmyU1q2IdOzgXtSLq6dN7D99zMiD0ocmBjIfpZd6fdEFMq5qQIcZlo1KplAktQDwuuVT",
		"use": "exchange",
		"crv": "P-521",
		"kid": "6231775b-7126-4ff4-bee9-f0521d945b95",
		"x": "AYg_DWneLPrwrsZVZw4i8AOnfDCWLskSKP_0ol-3c2q8HMD0cL0KDGaeRx5j4qi95IunNsWlKHPM6W-9IIK_7dfx",
		"y": "AOJxNtG2dkAD4wWwrWlcDzwIwKOhlqMAuwYmLhKfTmgJhJHpiY64QPlxiu6gPltFe5RkDcq6ZBj_ogQ0EwY0-iWQ"
	}`)
	ExchangeKey2Id = "6231775b-7126-4ff4-bee9-f0521d945b95"

	SigningKey1, SigningKey1Thp = KeyFromJson(`{
		"kty": "EC",
		"d": "AcEOnvtRjKPp-QPwSN3yqCDlhsjifuDIAuCse5uv_wV6ENIyADh8lOllF3YsOgmPksjYooD5UV9oBBhArltfQYbb",
		"use": "signECMR",
		"crv": "P-521",
		"x": "AZWyek40TOSPIMTgbPCwVrtFPSLDjoIxOhx8d22rMeMnb3ld9k9sS20EGniNJHOxivovazbpbJE5-GcysqG9JafO",
		"y": "ATGtjipFn2p07AtdY_dWCwjWc4b9a-kHh7Bg3gv44T3Xsp-N2OfPCWprG0GQ4lkhNgR4kAXkJJphy0hY5XKriBkO",
		"alg": "ES512"
	}`)

	SigningKey2, SigningKey2Thp = KeyFromJson(`
	{
		"kty": "EC",
		"d": "AV_OfM9AOtKKADO_u2oukTF2pTzbRyVdlx1e5xLP0olWCikwVkUAZsCvS9Uz_sPc4j03_HZo2CUQOtIS1TrspH6n",
		"use": "sig",
		"crv": "P-521",
		"x": "AVyw73ZRsdos7fEcr_B2OIMF03wFigCzsEDyknfnk488S3E5gdp9xz8RfafFnTx9Q3QI6_HMz5D3JkC6fYtiv8wY",
		"y": "AJ7u-6g5qOEZOBePgJ9jr9qozUXDjJ4W-gVi4485FIy8FJEczyicgPcIREU-M9EwcX_D87nRdgxrzLUmzBWov_NS",
		"alg": "ES512"
	}`)
)

// Test helpers

func KeyFromJson(jsonData string) (jose.JSONWebKey, string) {
	var result jose.JSONWebKey
	_ = json.Unmarshal([]byte(jsonData), &result)
	thp, _ := result.Thumbprint(crypto.SHA256)
	return result, base64.RawURLEncoding.EncodeToString(thp)
}
