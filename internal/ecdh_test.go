package internal

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	// Sample x,y coordinator in a NIST P-521 curve encoded in Base64
	b64x = "AQ9iDNelRXRZZQTTpzR7imHIMGYG1-qQ6uif6Lj6eFpbUMf07gydd6K9Z2HQ_DAfRgf5JiQhrUdXzwB5xCqB53Pc"
	b64y = "AIpTGuqfOMSLP0cNl1J8rQfgamnIMuTDcUrk3dSpif8jD2cKWTJaaIhffPG2XLxaJtSNZNGFZXvObhBghb_8X8GQ"
)

func TestECDHKey(t *testing.T) {
	// Create curve, and convert sample base64-encoded x,y-coordinator to big.Int
	sampleAlgo := NewECAlgorithm(elliptic.P521())

	xBytes, _ := base64.URLEncoding.DecodeString(b64x)
	x := new(big.Int)
	x.SetBytes(xBytes)

	yBytes, _ := base64.URLEncoding.DecodeString(b64y)
	y := new(big.Int)
	y.SetBytes(yBytes)

	t.Run("creating a ECDH key", func(t *testing.T) {
		pubECDH := sampleAlgo.key(x, y)
		require.Equal(t, pubECDH.Curve(), ecdh.P521())
	})
}
