package internal

import "github.com/go-jose/go-jose/v4"

type KeyList []jose.JSONWebKey

func (t KeyList) PublicKeys() KeyList {
	var result KeyList

	for _, key := range t {
		result = append(result, key.Public())
	}
	return result
}
