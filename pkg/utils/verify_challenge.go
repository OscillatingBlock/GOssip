package utils

import "crypto/ed25519"

func ValidateChallenge(signingPubKey, challenge, signature []byte) (bool, error) {
	ok := ed25519.Verify(signingPubKey, challenge, signature)
	return ok, nil
}
