package internal

import (
	"crypto"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
)

func TestGenerateExchangeKey(t *testing.T) {
	t.Run("generate a new exchange key", func(t *testing.T) {
		jwk, err := GenerateExchangeKey()
		require.NoError(t, err)
		require.NotNil(t, jwk)

		require.Equal(t, defaultExchangeAlgorithm, jwk.Algorithm)
		require.False(t, jwk.IsPublic())
	})
}

func TestGenerateSigningKey(t *testing.T) {
	t.Run("generate a new signing key", func(t *testing.T) {
		jwk, err := GenerateExchangeKey()
		require.NoError(t, err)
		require.NotNil(t, jwk)

		require.Equal(t, defaultExchangeAlgorithm, jwk.Algorithm)
		require.False(t, jwk.IsPublic())
	})
}

func TestIsECKey(t *testing.T) {
	t.Run("check validity of a EC key", func(t *testing.T) {
		require.True(t, isECKey(ExchangeKey1))
		p := ExchangeKey1.Public()
		require.True(t, isECKey(p))
	})
}

func TestIsECMRKey(t *testing.T) {
	t.Run("check invalidity of an exchange key", func(t *testing.T) {
		require.True(t, IsECMRKey(ExchangeKey1))
	})
	t.Run("check validity of a signing key", func(t *testing.T) {
		require.False(t, IsECMRKey(SigningKey1))
	})
}

func TestThumbprints(t *testing.T) {
	t.Run("default thumbprint algorithm", func(t *testing.T) {
		actual, err := Thumbprints(ExchangeKey1)
		require.NoError(t, err)
		require.Len(t, actual, len(DefaultThumbprintAlgorithm))
	})
	t.Run("specific thumbprint algorithm", func(t *testing.T) {
		actual, err := Thumbprints(ExchangeKey1, crypto.SHA256, crypto.SHA512)
		require.NoError(t, err)
		require.Equal(t, ExchangeKey1Thp, actual[0])
		require.Len(t, actual, 2)
	})
	t.Run("invalid symmetric key", func(t *testing.T) {
		symmetricKeyJSON := `{
			"kty": "oct",
			"kid": "4c812e39-5108-43a4-98b4-52d73e571575",
			"k": "N1PCdw3M2B1TfJhoaY2mL736p2vCUc47"
		}`

		var sk jose.JSONWebKey
		_ = sk.UnmarshalJSON([]byte(symmetricKeyJSON))

		_, err := Thumbprints(sk)
		require.Error(t, err)
	})
}
