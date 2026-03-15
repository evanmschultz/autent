package token

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
)

// SecretManager issues and verifies opaque session secrets.
type SecretManager interface {
	NewSecret() (plain string, secretHash []byte, err error)
	HashSecret(secret string) []byte
	VerifySecret(secret string, secretHash []byte) bool
}

// OpaqueSecretManager issues random opaque session secrets and verifies them by hash.
type OpaqueSecretManager struct{}

// Issue issues one random opaque secret and its stored hash.
func (manager OpaqueSecretManager) Issue() (string, []byte, error) {
	return manager.NewSecret()
}

// NewSecret issues one random opaque secret and its stored hash.
func (OpaqueSecretManager) NewSecret() (string, []byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("generate secret: %w", err)
	}
	plain := hex.EncodeToString(raw)
	return plain, hashSecret(plain), nil
}

// HashSecret hashes one plain secret for storage.
func (OpaqueSecretManager) HashSecret(secret string) []byte {
	return hashSecret(secret)
}

// VerifySecret compares one plain secret to one stored hash in constant time.
func (OpaqueSecretManager) VerifySecret(secret string, secretHash []byte) bool {
	if len(secretHash) == 0 {
		return false
	}
	computed := hashSecret(secret)
	return subtle.ConstantTimeCompare(computed, secretHash) == 1
}

// Verify compares one plain secret to one stored hash in constant time.
func (manager OpaqueSecretManager) Verify(secret string, secretHash []byte) bool {
	return manager.VerifySecret(secret, secretHash)
}

// hashSecret returns the SHA-256 digest of one secret string.
func hashSecret(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	out := make([]byte, len(sum))
	copy(out, sum[:])
	return out
}
