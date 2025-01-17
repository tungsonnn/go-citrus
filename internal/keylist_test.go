package internal

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKeyList_PublicKeys(t *testing.T) {
	keys := KeyList{ExchangeKey1}

	actual := keys.PublicKeys()
	require.Len(t, actual, len(keys))
}
