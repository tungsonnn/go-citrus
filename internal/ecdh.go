package internal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
)

// Elliptic curve Diffie-Helman computations

type ECAlgorithm struct {
	Curve elliptic.Curve
}

func NewECAlgorithm(curve elliptic.Curve) ECAlgorithm {
	return ECAlgorithm{
		Curve: curve,
	}
}

// Create a ECDH public key with given curve, x and y-axis.
func (t ECAlgorithm) key(x *big.Int, y *big.Int) *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: t.Curve,
		X:     x,
		Y:     y,
	}
}

func (t ECAlgorithm) Multiply(p *ecdsa.PublicKey, P *ecdsa.PrivateKey) *ecdsa.PublicKey {
	X, Y := t.Curve.ScalarMult(p.X, p.Y, P.D.Bytes())
	return t.key(X, Y)
}
