package client

import "github.com/go-jose/go-jose/v4"

/*
Custom recovery handler to perform server key recovery call: POST /rec/{thumbprint} + body{x}
  - thumbprint - server exchange key 's' thumbprint
  - 'x' - client recovery request key
*/

type RecoveryFn func(thumbprint string, x []byte) ([]byte, error)

type Protocol struct {
	recoveryHandler RecoveryFn
}

func NewProtocol(recoveryHandler RecoveryFn) *Protocol {
	return &Protocol{
		recoveryHandler: recoveryHandler,
	}
}

/* ----- Client key generation and data encryption -----
1. Get advertised server key 's'
2. Create a pair of client Ecliptic-Curve (EC) keys (c, C)
	c = g * C
3. Calculate the shared secret K using server's advertised public key 's' and its private key 'C'
	K = s * C = g * S * C
4. Construct symmetric key from K
	symmetric-key = jose.Recipient{Algorithm: ECDH_ES, Key: K.Public(), KeyID: thp(K)}
5. Encrypt the data using an encryption mode (i.e. AES or AES+HMAC), and return cipher as encoded JWE structure.
	cipher = encryptionMode-encrypt(data, symmetric-key)

K and C will be discarded so K cannot be used for decrypting data and client remove itself as primary stakeholder for using C to derive K.
This is where our computing server helps.

Client will keep the cipher to reconstruct the data, with the help of thp(s) and 'c' during recovery operation.
*/

func (t *Protocol) Encrypt(cipher []byte, advServerKey jose.JSONWebKey) ([]byte, error) {
	return nil, nil
}

/* ----- Client key recovery and decryption -----
1. Create a blind ephemeral EC key:
	e = g * E
2. Add 'e' to the preserved 'c', creating client recovery request key 'x', which will be sent to the server via `RecoveryFn`
	x = c + e = (g * C) + (g * E)
3. [Server] Perform "half-ECDH" recovery over x using server's private key S, identified by given thumbprint in `RecoveryFn`
	y = x * S = ((g * C) + (g * E)) * S = g * S * C + g * S * E
4. [Client] Perform "half-ECDH" client-side over the server's advertised public key 's' using 'E'
	z = s * E = g * S * E
5. Recover the original shared secret 'K'
	K = y - z = (g * S * C + g * S * E) - (g * S * E) = g * S * C
6. Derive symmetric key from 'K', and decrypt the cipher
	symmetric-key = go-jose/josecipher.DeriveECDHES(K)
	data = encryptionMode-decrypt(cipher, symmetric-key)
*/

func (t *Protocol) Decrypt(cipher []byte) ([]byte, error) {
	return nil, nil
}
