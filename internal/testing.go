package internal

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"

	"github.com/go-jose/go-jose/v4"
)

var (
	//EC keys were generated on `mkjwk.org`
	ExchangeKey1, ExchangeKey1Thp = KeyFromJson(`
	{
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

	ExchangeKey2, ExchangeKey2Thp = KeyFromJson(`
	{
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

	ExchangeKey3, ExchangeKey3Thp = KeyFromJson(`
	{
		"kty": "EC",
		"alg": "ECMR",
		"d": "AU71UGL7wRTG6duEf3h_Qg169PGxDjcfJHGxl96oDinzSDyRmtUen6YHPfaGt5zdixyuELuGx8nWg5H_LEIepIN2",
		"use": "exchange",
		"crv": "P-521",
		"x": "AaAtd2e-MGOMDQm1NqbC04r4P-X-6yX7HLRVGaf3295zAqc9u2wLnUp4aN6Twk8TdZreu5T6n1aacWmHEusYWPBy",
		"y": "AY3tZ417yswNFsY7xLw-SpWJNw6qvvEqv3nr_ZC5JdYHkTBHYkSczosfc77xKwMig-6Qt7xILq44DRTRX18D2Sb4"
	}`)

	SigningKey1, SigningKey1Thp = KeyFromJson(`
	{
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
		"use": "signECMR",
		"crv": "P-521",
		"x": "AVyw73ZRsdos7fEcr_B2OIMF03wFigCzsEDyknfnk488S3E5gdp9xz8RfafFnTx9Q3QI6_HMz5D3JkC6fYtiv8wY",
		"y": "AJ7u-6g5qOEZOBePgJ9jr9qozUXDjJ4W-gVi4485FIy8FJEczyicgPcIREU-M9EwcX_D87nRdgxrzLUmzBWov_NS",
		"alg": "ES512"
	}`)

	SigningKey3, SigningKey3Thp = KeyFromJson(`
	{
		"kty": "EC",
		"d": "ABuqXwWbTlKdhsGngx7ANRiCWSd9Tr8pYAaPDZzK0CwEfKf5ijL1ezXXUbncOsm_FU3VYagkPuAfgbWkmpis16RN",
		"use": "signECMR",
		"crv": "P-521",
		"x": "AefOgzykjxJ7pf5oOT2SWujf_v-rADSQb4FMULEfkdcys3nRhFqPjMwT6xDmpdX-eDdaYMkxSSbo3nxzcBkyF2Aj",
		"y": "AZ3Imzm6E0TPzOMvE61nKCXA3BvYUrOJZr36e7OyuNIAK-rW9k_ED2Z26kxJi_p8uxtiUn2PQI8rs2Omg_8ZGtjv",
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

func GenerateRSAKey() (*jose.JSONWebKey, error) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	return &jose.JSONWebKey{Key: k}, nil
}
