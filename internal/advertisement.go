package internal

import (
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

type Advertisement struct {
	exchangeKeys KeyList
	signingKeys  KeyList
}

func NewAdvertisement(advertised ...jose.JSONWebKey) (*Advertisement, error) {
	var exc KeyList
	var sig KeyList

	for i, key := range advertised {
		if !isECKey(key) {
			return nil, fmt.Errorf("advertised key %d is not an EC public key", i)
		}

		if IsExchangeKey(key) {
			exc = append(exc, key)
		}

		if IsSigningKey(key) {
			sig = append(sig, key)
		}
	}

	if len(sig) == 0 {
		return nil, fmt.Errorf("no signing keys found for advertisement")
	}

	if len(exc) == 0 {
		return nil, fmt.Errorf("no exchange keys found for advertisement")
	}

	return &Advertisement{exc, sig}, nil
}

func (t *Advertisement) ExchangeKeys() KeyList {
	return t.exchangeKeys
}

func (t *Advertisement) SigningKeys() KeyList {
	return t.signingKeys
}

// Returns a signed advertised key set in JSON Web Signature(JWS) format
func (t *Advertisement) Marshall() ([]byte, error) {
	var advertised KeyList
	advertised = append(advertised, t.exchangeKeys...)
	advertised = append(advertised, t.signingKeys...)

	// Collect public keys from the advertised key list
	public := jose.JSONWebKeySet{Keys: advertised.PublicKeys()}
	payload, err := json.Marshal(public)
	if err != nil {
		return nil, err
	}

	// Sign the payload
	var keys []jose.SigningKey
	for _, key := range t.signingKeys {
		keys = append(keys, jose.SigningKey{Algorithm: jose.SignatureAlgorithm(key.Algorithm), Key: key})
	}

	opts := &jose.SignerOptions{}
	signer, err := jose.NewMultiSigner(keys, opts.WithContentType("jwk-set+json"))
	if err != nil {
		return nil, err
	}
	signature, err := signer.Sign(payload)
	if err != nil {
		return nil, err
	}

	return []byte(signature.FullSerialize()), nil
}
