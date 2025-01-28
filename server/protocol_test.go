package server

import (
	"fmt"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"

	. "go-citrus/internal"
)

func TestProtocol_NewServer(t *testing.T) {
	t.Run("building a vanilla server", func(t *testing.T) {
		server, err := NewProtocol(
			KeyList{ExchangeKey1, ExchangeKey2, SigningKey1},
		)
		require.NotNil(t, server)
		require.NoError(t, err)

		advPerSignKey := len(DefaultThumbprintAlgorithm)

		// Exchange keys are advertised + 1 default advertisement
		require.Len(t, server.advertisements, advPerSignKey+1, "Invalid number of advertisements")
	})

	t.Run("building a server with no exchange key", func(t *testing.T) {
		_, err := NewProtocol(
			KeyList{SigningKey1, SigningKey2},
		)

		require.Error(t, err)
	})

	t.Run("building a server with no signing key", func(t *testing.T) {
		_, err := NewProtocol(
			KeyList{ExchangeKey1, ExchangeKey2},
		)

		require.Error(t, err)
	})

	t.Run("building a server with non-ECMR key", func(t *testing.T) {
		rsa, err := GenerateRSAKey()
		require.NoError(t, err)

		_, err = NewProtocol(
			KeyList{*rsa, SigningKey1},
		)
		require.Error(t, fmt.Errorf("advertised key 0 is not an EC public key"), err)
	})
}

func TestProtocol_GetAdvertisement(t *testing.T) {
	server, err := NewProtocol(
		KeyList{ExchangeKey1, ExchangeKey2, SigningKey1},
	)
	require.NotEmpty(t, server)
	require.NoError(t, err)

	t.Run("get default advertisement", func(t *testing.T) {
		// Get and parse default advertisement
		response := server.GetAdvertisement("")
		require.NotEmpty(t, response)

		adv, err := ParseAdvertisement(response, []jose.SignatureAlgorithm{DefaultSignatureAlgorithm})
		require.NoError(t, err)

		require.Len(t, adv.ExchangeKeys(), 2)
		require.Len(t, adv.SigningKeys(), 1)

		ensurePublic(t, adv.ExchangeKeys()...)
		ensurePublic(t, adv.SigningKeys()...)
	})

	t.Run("get advertised keys using thumbprint of signing key", func(t *testing.T) {
		response := server.GetAdvertisement(SigningKey1Thp)
		require.NotEmpty(t, response)

		adv, err := ParseAdvertisement(response, []jose.SignatureAlgorithm{DefaultSignatureAlgorithm})
		require.NoError(t, err)

		require.Len(t, adv.ExchangeKeys(), 2)
		require.Len(t, adv.SigningKeys(), 1)

		ensurePublic(t, adv.ExchangeKeys()...)
		ensurePublic(t, adv.SigningKeys()...)
	})
}

func TestProtocol_Recover(t *testing.T) {
	server, err := NewProtocol(
		KeyList{ExchangeKey1, ExchangeKey2, ExchangeKey3, SigningKey1},
	)
	require.NotEmpty(t, server)
	require.NoError(t, err)

	// generate blinded recovery request from client
	x, _ := GenerateExchangeKey()

	thumbs := []string{ExchangeKey1Thp, ExchangeKey2Thp, ExchangeKey3Thp}
	for _, thumb := range thumbs {
		response, err := server.computeRecoverKey(thumb, x.Public())
		require.NoError(t, err)
		require.NotEmpty(t, response)
		require.True(t, response.IsPublic())
	}
}

func ensurePublic(t *testing.T, keys ...jose.JSONWebKey) {
	for _, key := range keys {
		require.True(t, key.IsPublic())
	}
}
