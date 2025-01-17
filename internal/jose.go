package internal

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/go-jose/go-jose/v4"
)

const (
	defaultExchangeAlgorithm = "ECMR"
)

// Helper functions related to Javascript Object Signing and Encryption (JOSE) framework

// JSON Web Keys

func generateKey(algorithm string, usage string) (jose.JSONWebKey, error) {
	pk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return jose.JSONWebKey{}, err
	}

	return jose.JSONWebKey{
		Key:       pk,
		Algorithm: algorithm,
		Use:       usage,
	}, nil
}

func isECKey(key jose.JSONWebKey) bool {
	_, pub := key.Key.(*ecdsa.PublicKey)
	_, pri := key.Key.(*ecdsa.PrivateKey)
	return pub || pri
}

// ECMR-specific Keys
func GenerateExchangeKey() (jose.JSONWebKey, error) {
	return generateKey(defaultExchangeAlgorithm, "exchange")
}

func GenerateSigningKey() (jose.JSONWebKey, error) {
	return generateKey(defaultExchangeAlgorithm, "signECMR")
}

func IsECMRKey(key jose.JSONWebKey) bool {
	return isECKey(key) && key.Algorithm == "ECMR"
}

func IsSigningKey(key jose.JSONWebKey) bool {
	return key.Use == "signECMR"
}

func IsExchangeKey(key jose.JSONWebKey) bool {
	return IsECMRKey(key) && key.Use == "exchange"
}

func CreateExchangeKey(key interface{}) jose.JSONWebKey {
	return jose.JSONWebKey{
		Key:       key,
		Algorithm: defaultExchangeAlgorithm,
		Use:       "exchange",
	}
}

// Thumbprint

func Thumbprints(key jose.JSONWebKey, algorithms ...crypto.Hash) ([]string, error) {
	if len(algorithms) == 0 {
		// default support key thumbprint algorithms
		algorithms = []crypto.Hash{
			crypto.SHA1,
			crypto.SHA224,
			crypto.SHA256,
			crypto.SHA384,
			crypto.SHA512,
		}
	}

	var results []string
	for _, hash := range algorithms {
		thp, err := key.Thumbprint(hash)
		if err != nil {
			return nil, err
		}

		results = append(results, string(thp))
	}

	return results, nil
}
