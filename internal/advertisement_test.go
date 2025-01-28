package internal

import (
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
)

var (
	singleSignatureAdvertisement   = []byte(`{"payload":"eyJrZXlzIjpbeyJ1c2UiOiJleGNoYW5nZSIsImt0eSI6IkVDIiwia2lkIjoiMmM3Mzk2OTktZjQ5Ny00NmY5LThmOGEtNjZkMjM3YzA4YTI5IiwiY3J2IjoiUC01MjEiLCJhbGciOiJFQ01SIiwieCI6IkFROWlETmVsUlhSWlpRVFRwelI3aW1ISU1HWUcxLXFRNnVpZjZMajZlRnBiVU1mMDdneWRkNks5WjJIUV9EQWZSZ2Y1SmlRaHJVZFh6d0I1eENxQjUzUGMiLCJ5IjoiQUlwVEd1cWZPTVNMUDBjTmwxSjhyUWZnYW1uSU11VERjVXJrM2RTcGlmOGpEMmNLV1RKYWFJaGZmUEcyWEx4YUp0U05aTkdGWlh2T2JoQmdoYl84WDhHUSJ9LHsidXNlIjoic2lnbkVDTVIiLCJrdHkiOiJFQyIsImNydiI6IlAtNTIxIiwiYWxnIjoiRVM1MTIiLCJ4IjoiQVpXeWVrNDBUT1NQSU1UZ2JQQ3dWcnRGUFNMRGpvSXhPaHg4ZDIyck1lTW5iM2xkOWs5c1MyMEVHbmlOSkhPeGl2b3ZhemJwYkpFNS1HY3lzcUc5SmFmTyIsInkiOiJBVEd0amlwRm4ycDA3QXRkWV9kV0N3aldjNGI5YS1rSGg3QmczZ3Y0NFQzWHNwLU4yT2ZQQ1dwckcwR1E0bGtoTmdSNGtBWGtKSnBoeTBoWTVYS3JpQmtPIn1dfQ","protected":"eyJhbGciOiJFUzUxMiIsImN0eSI6Imp3ay1zZXQranNvbiJ9","signature":"AHUg2EjvWCBfwahjdRx27tg26dCu994q8dkvtA2ftlbDFPG68SkdsuXP4PZ1A0K1yPqgfFl0VoY77jKeT1pocBmeAO3c5fRRaD618O086z4xDOlaS7QF-57oPCDiDexu1RKNYBANRRSEhaFdAUwegdhN7RSl87EHr4lAOqOzvYL8mZav"}`)
	multipleSignatureAdvertisement = []byte(`{"payload":"eyJrZXlzIjpbeyJ1c2UiOiJleGNoYW5nZSIsImt0eSI6IkVDIiwia2lkIjoiMmM3Mzk2OTktZjQ5Ny00NmY5LThmOGEtNjZkMjM3YzA4YTI5IiwiY3J2IjoiUC01MjEiLCJhbGciOiJFQ01SIiwieCI6IkFROWlETmVsUlhSWlpRVFRwelI3aW1ISU1HWUcxLXFRNnVpZjZMajZlRnBiVU1mMDdneWRkNks5WjJIUV9EQWZSZ2Y1SmlRaHJVZFh6d0I1eENxQjUzUGMiLCJ5IjoiQUlwVEd1cWZPTVNMUDBjTmwxSjhyUWZnYW1uSU11VERjVXJrM2RTcGlmOGpEMmNLV1RKYWFJaGZmUEcyWEx4YUp0U05aTkdGWlh2T2JoQmdoYl84WDhHUSJ9LHsidXNlIjoiZXhjaGFuZ2UiLCJrdHkiOiJFQyIsImtpZCI6IjYyMzE3NzViLTcxMjYtNGZmNC1iZWU5LWYwNTIxZDk0NWI5NSIsImNydiI6IlAtNTIxIiwiYWxnIjoiRUNNUiIsIngiOiJBWWdfRFduZUxQcndyc1pWWnc0aThBT25mRENXTHNrU0tQXzBvbC0zYzJxOEhNRDBjTDBLREdhZVJ4NWo0cWk5NUl1bk5zV2xLSFBNNlctOUlJS183ZGZ4IiwieSI6IkFPSnhOdEcyZGtBRDR3V3dyV2xjRHp3SXdLT2hscU1BdXdZbUxoS2ZUbWdKaEpIcGlZNjRRUGx4aXU2Z1BsdEZlNVJrRGNxNlpCal9vZ1EwRXdZMC1pV1EifSx7InVzZSI6InNpZ25FQ01SIiwia3R5IjoiRUMiLCJjcnYiOiJQLTUyMSIsImFsZyI6IkVTNTEyIiwieCI6IkFaV3llazQwVE9TUElNVGdiUEN3VnJ0RlBTTERqb0l4T2h4OGQyMnJNZU1uYjNsZDlrOXNTMjBFR25pTkpIT3hpdm92YXpicGJKRTUtR2N5c3FHOUphZk8iLCJ5IjoiQVRHdGppcEZuMnAwN0F0ZFlfZFdDd2pXYzRiOWEta0hoN0JnM2d2NDRUM1hzcC1OMk9mUENXcHJHMEdRNGxraE5nUjRrQVhrSkpwaHkwaFk1WEtyaUJrTyJ9XX0","protected":"eyJhbGciOiJFUzUxMiIsImN0eSI6Imp3ay1zZXQranNvbiJ9","signature":"AdN1hYCPAM-esTFI51L-cuVuV1a1VkHcX6OaanyrNNEwe50G6I7OGJf_81x-QMjRkduqoGW0eLtuYUplFlakm7SHAf2NgK1sdrTCaLzNIP_in3UW-dRJtDSzs164-7JzuCmfh7QiAvkWvIctxhg8wTsy88_7-2j8pVbgfb--9Ci6TUjU"}`)
)

func TestNewAdvertisement(t *testing.T) {
	t.Run("testing advertisement happy path", func(t *testing.T) {
		adv, err := NewAdvertisement(ExchangeKey1, SigningKey1)
		require.NotNil(t, adv)
		require.NoError(t, err)

		require.Len(t, adv.ExchangeKeys(), 1)
		require.Len(t, adv.SigningKeys(), 1)
	})

	t.Run("testing advertisement with invalid key error", func(t *testing.T) {
		invalidKey, err := GenerateRSAKey()
		require.NoError(t, err)
		require.NotNil(t, invalidKey)

		_, err = NewAdvertisement(ExchangeKey1, SigningKey1, jose.JSONWebKey{Key: invalidKey})
		require.Error(t, err)
	})

}

func TestAdvertisement_Marshall(t *testing.T) {
	t.Run("marshall one key set", func(t *testing.T) {
		original, err := NewAdvertisement(ExchangeKey1, SigningKey1)
		require.NoError(t, err)
		require.NotNil(t, original)

		payload, err := original.Marshall()
		require.NoError(t, err)
		require.NotEmpty(t, payload)

		restored, err := ParseAdvertisement(payload, []jose.SignatureAlgorithm{DefaultSignatureAlgorithm})
		require.NoError(t, err)
		require.NotNil(t, restored)

		require.Equal(t, len(original.ExchangeKeys()), len(restored.ExchangeKeys()))
		require.Equal(t, len(original.SigningKeys()), len(restored.SigningKeys()))
	})

	t.Run("marshall multiple key sets", func(t *testing.T) {
		original, err := NewAdvertisement(ExchangeKey1, SigningKey1, ExchangeKey2, SigningKey2)
		require.NoError(t, err)
		require.NotNil(t, original)

		payload, err := original.Marshall()
		require.NoError(t, err)
		require.NotEmpty(t, payload)

		restored, err := ParseAdvertisement(payload, []jose.SignatureAlgorithm{DefaultSignatureAlgorithm})
		require.NoError(t, err)
		require.NotNil(t, restored)

		require.Equal(t, len(original.ExchangeKeys()), len(restored.ExchangeKeys()))
		require.Equal(t, len(original.SigningKeys()), len(restored.SigningKeys()))
	})
}

func TestAdvertisement_Parse(t *testing.T) {
	// Use payload from Marshal() tests to test the function.
	t.Run("testing single signature advertisement", func(t *testing.T) {
		_, err := ParseAdvertisement(singleSignatureAdvertisement, []jose.SignatureAlgorithm{DefaultSignatureAlgorithm})
		require.NoError(t, err)
	})

	t.Run("testing multi signatures advertisement", func(t *testing.T) {
		_, err := ParseAdvertisement(multipleSignatureAdvertisement, []jose.SignatureAlgorithm{DefaultSignatureAlgorithm})
		require.NoError(t, err)
	})
}
