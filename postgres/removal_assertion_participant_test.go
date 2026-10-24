package postgres_test

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	webauthn "github.com/faustbrian/go-webauthn"
	webauthnpg "github.com/faustbrian/go-webauthn/postgres"
)

func TestRemovalAssertionRejectsInvalidCustody(t *testing.T) {
	var store *webauthnpg.Store
	if p, err := store.RemovalAssertionCreation(webauthn.CeremonyCreation{}); p != nil || err == nil {
		t.Fatal("zero removal options accepted")
	}
	if p, err := store.RemovalAssertionFinalization(webauthn.AssertionTransition{}, webauthnpg.RemovalRequest{}); p != nil || err == nil {
		t.Fatal("manufactured removal assertion accepted")
	}
	var p webauthnpg.RemovalAssertionFinalization
	if _, err := p.Fields(); err == nil {
		t.Fatal("zero participant supplied command fields")
	}
	if err := p.Validate(identity.Command{}, kernel.CommandPlan{}); err == nil {
		t.Fatal("zero participant validated")
	}
	if err := p.Apply(context.Background(), kernel.Work{}, nil, identity.Command{}); err == nil {
		t.Fatal("zero participant applied")
	}
	if err := p.Check(context.Background(), kernel.Work{}, nil, identity.Command{}); err == nil {
		t.Fatal("zero participant checked")
	}
	if _, err := p.CheckRemainingCredential(context.Background(), kernel.Work{}, nil, identity.Command{}, []byte("remaining")); err == nil {
		t.Fatal("zero participant supplied remaining-key authority")
	}
	if _, err := p.Result(identity.CommandResult{}); err == nil {
		t.Fatal("zero participant issued verification")
	}
	if _, err := store.RecoverRemovalAssertion(context.Background(), kernel.RecoveryWork{}, nil); err == nil {
		t.Fatal("zero recovery accepted")
	}
}
