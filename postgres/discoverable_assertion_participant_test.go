package postgres_test

import (
	"testing"

	webauthn "github.com/faustbrian/go-webauthn"
	webauthnpg "github.com/faustbrian/go-webauthn/postgres"
)

func TestDiscoverableAssertionParticipationInvalidCustody(t *testing.T) {
	var store *webauthnpg.Store
	if p, err := store.DiscoverableAssertionCreation(webauthn.CeremonyCreation{}); err == nil || p != nil {
		t.Fatal("zero discoverable creation accepted")
	}
	if p, err := store.DiscoverableAssertionFinalization(webauthn.AssertionTransition{}); err == nil || p != nil {
		t.Fatal("zero discoverable transition accepted")
	}
}
