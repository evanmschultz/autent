package token

import "testing"

// TestOpaqueSecretManager verifies secret issue, hash, and constant-time verification behavior.
func TestOpaqueSecretManager(t *testing.T) {
	t.Parallel()

	manager := OpaqueSecretManager{}
	plain, secretHash, err := manager.NewSecret()
	if err != nil {
		t.Fatalf("NewSecret() error = %v", err)
	}
	if plain == "" {
		t.Fatal("NewSecret() returned an empty plain secret")
	}
	if len(secretHash) == 0 {
		t.Fatal("NewSecret() returned an empty secret hash")
	}
	if !manager.VerifySecret(plain, secretHash) {
		t.Fatal("VerifySecret() should accept the matching secret")
	}
	if manager.VerifySecret("wrong-secret", secretHash) {
		t.Fatal("VerifySecret() should reject the wrong secret")
	}
}

// TestOpaqueSecretManagerHelpers verifies the Issue, HashSecret, and Verify helpers.
func TestOpaqueSecretManagerHelpers(t *testing.T) {
	t.Parallel()

	manager := OpaqueSecretManager{}
	plain, secretHash, err := manager.Issue()
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if got := manager.HashSecret(plain); len(got) != len(secretHash) {
		t.Fatalf("len(HashSecret()) = %d, want %d", len(got), len(secretHash))
	}
	if !manager.Verify(plain, secretHash) {
		t.Fatal("Verify() = false, want true")
	}
	if manager.Verify(plain, nil) {
		t.Fatal("Verify() with nil hash = true, want false")
	}
}

// TestOpaqueSecretManagerWrappers verifies the convenience wrapper methods.
func TestOpaqueSecretManagerWrappers(t *testing.T) {
	t.Parallel()

	manager := OpaqueSecretManager{}
	plain, secretHash, err := manager.Issue()
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if !manager.Verify(plain, secretHash) {
		t.Fatal("Verify() should accept the matching secret")
	}
	if manager.Verify(plain, nil) {
		t.Fatal("Verify() should reject an empty stored hash")
	}
	if got := manager.HashSecret(plain); len(got) == 0 {
		t.Fatal("HashSecret() returned an empty digest")
	}
}
