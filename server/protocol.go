package server

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/go-jose/go-jose/v4"

	. "go-citrus/internal"
)

/*
	McCallum-Relyea key exchange protocol, server operations.
	Reference from original implementation: https://github.com/latchset/tang/blob/master/src/keys.c
*/

type Protocol struct {
	advertisements map[string][]byte          // Advertisement lookup map - signing key thumbprint -> client advertisement
	exchange       map[string]jose.JSONWebKey // Recovery lookup map - exchange key thumbprint -> server key map
}

/* ----- Server key advertisement -----
Server possesses different Ecliptic-Curve (EC) key pairs (s, S) and advertise its public portion `s` to client.
NOTE:
	The advertisement thumbprint is in order for the server to find the correct signed server key advertisement to send to client,
	while the exchange thumbprint is generated from the `s` key will be sent from client to find `S`.
*/

func NewProtocol(adv KeyList) (*Protocol, error) {
	p := Protocol{
		advertisements: make(map[string][]byte),
		exchange:       make(map[string]jose.JSONWebKey),
	}

	defaultAdv, err := NewAdvertisement(adv...)
	if err != nil {
		return nil, err
	}
	exchange := defaultAdv.ExchangeKeys()
	signing := defaultAdv.SigningKeys()

	bytes, err := defaultAdv.Marshall()
	if err != nil {
		return nil, err
	}

	// Always return the default advertisement,
	p.advertisements[""] = bytes

	// as well as the signing keys with provided thumbprints.
	for _, key := range signing {
		if err = p.addAdvertisementKey(key, bytes); err != nil {
			return nil, err
		}
	}

	// Add advertised exchange keys.
	for _, key := range exchange {
		if err = p.addExchangeKey(key); err != nil {
			return nil, err
		}
	}

	return &p, nil
}

func (t *Protocol) addAdvertisementKey(key jose.JSONWebKey, advertisement []byte) error {
	thumbs, err := Thumbprints(key)
	if err != nil {
		return err
	}

	for _, thumb := range thumbs {
		t.advertisements[thumb] = advertisement
	}

	return nil
}

func (t *Protocol) GetAdvertisement(thumbprint string) []byte {
	return t.advertisements[thumbprint]
}

func (t *Protocol) addExchangeKey(key jose.JSONWebKey) error {
	thumbs, err := Thumbprints(key)
	if err != nil {
		return err
	}

	for _, thumb := range thumbs {
		t.exchange[thumb] = key
	}

	return nil
}

/*
	Perform the ECMR key recovery using blinded client recovery request key 'x',
	and the server private key 'S', identified using client-provided thumbprint thp(s).
 	Server recovery operation: y = x * S
*/

func (t *Protocol) Recover(thumbprint string, request []byte) ([]byte, error) {
	var jwkX jose.JSONWebKey

	if err := jwkX.UnmarshalJSON(request); err != nil {
		return nil, err
	}

	y, err := t.computeRecoverKey(thumbprint, jwkX)
	if err != nil {
		return nil, err
	}

	return y.MarshalJSON()
}

func (t *Protocol) computeRecoverKey(thumbprint string, jwkX jose.JSONWebKey) (jose.JSONWebKey, error) {
	// Validate request and fetch 'x'
	if !IsECMRKey(jwkX) {
		return jose.JSONWebKey{}, NewInvalidKeyError("client recovery request does not contain a valid ECMR key")
	}

	x, ok := jwkX.Key.(*ecdsa.PublicKey)
	if !ok {
		return jose.JSONWebKey{}, NewInvalidKeyError("failed to fetch public key from client recovery request")
	}

	// Get the server private key 'S'
	jwkS, ok := t.exchange[thumbprint]
	if !ok {
		return jose.JSONWebKey{}, NewKeyNotFoundError("server key (thumbprint='%s') not found", thumbprint)
	}

	S, ok := jwkS.Key.(*ecdsa.PrivateKey)
	if !ok {
		return jose.JSONWebKey{}, NewInvalidKeyError("failed to read private key from server (thumbprint='%s')", thumbprint)
	}

	if !S.Curve.IsOnCurve(x.X, x.Y) {
		return jose.JSONWebKey{}, NewInvalidKeyError("recovery request key is not on the same EC curve point with server private key")
	}

	ec := NewECAlgorithm(S.Curve)

	// Final recovery computation: y = x * S
	y := ec.Multiply(x, S)

	return CreateExchangeKey(y), nil
}

// Server-typed errors

type InvalidKeyError struct {
	msg string
}

func NewInvalidKeyError(format string, a ...interface{}) error {
	return &InvalidKeyError{
		msg: fmt.Sprintf(format, a...),
	}
}

func (e *InvalidKeyError) Error() string {
	return e.msg
}

type KeyNotFoundError struct {
	msg string
}

func NewKeyNotFoundError(format string, a ...interface{}) error {
	return &InvalidKeyError{
		msg: fmt.Sprintf(format, a...),
	}
}

func (e *KeyNotFoundError) Error() string {
	return e.msg
}
