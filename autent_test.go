package autent

import (
	"testing"
	"time"

	"github.com/evanmschultz/autent/inmem"
	"github.com/evanmschultz/autent/token"
)

// TestNewService verifies the root package façade constructs the primary service.
func TestNewService(t *testing.T) {
	t.Parallel()

	service, err := NewService(Config{
		Repository: inmem.NewRepository(),
		Secrets:    token.OpaqueSecretManager{},
		Clock: func() time.Time {
			return time.Date(2026, time.March, 17, 12, 0, 0, 0, time.UTC)
		},
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	if service == nil {
		t.Fatal("NewService() = nil, want service")
	}
}
