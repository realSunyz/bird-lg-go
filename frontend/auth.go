package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// signPayload creates a base64-encoded ASN.1 ECDSA signature for the provided payload.
// Returns an empty string when no ECDSA key is configured.
func signPayload(payload string) (string, error) {
	priv := setting.ecdsaPrivate
	if priv == nil {
		return "", nil
	}

	digest := sha256.Sum256([]byte(payload))
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}
