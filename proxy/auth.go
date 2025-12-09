package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
)

// verifySignature checks the base64-encoded ASN.1 ECDSA signature of the provided payload.
// If no public key is configured, it treats verification as optional and succeeds.
func verifySignature(r *http.Request, payload string) error {
	pub := setting.ecdsaPublic
	if pub == nil {
		return nil
	}

	sigB64 := r.URL.Query().Get("sig")
	if sigB64 == "" {
		return errors.New("missing signature")
	}

	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return err
	}

	digest := sha256.Sum256([]byte(payload))
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return errors.New("signature verification failed")
	}

	return nil
}
