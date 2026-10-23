package postgres_test

import (
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	webauthn "github.com/faustbrian/go-webauthn"
	webauthnpg "github.com/faustbrian/go-webauthn/postgres"
)

func TestAssertionParticipationInvalidCustody(t *testing.T) {
	var store *webauthnpg.Store
	if p, err := store.AssertionCreation(webauthn.CeremonyCreation{}); err == nil || p != nil {
		t.Fatal("zero store/creation accepted")
	}
	if p, err := store.AssertionFinalization(webauthn.AssertionTransition{}); err == nil || p != nil {
		t.Fatal("zero store/transition accepted")
	}
	if p, err := store.PreauthAssertionCreation(webauthn.CeremonyCreation{}); err == nil || p != nil {
		t.Fatal("zero store/preauth creation accepted")
	}
	if p, err := store.PreauthAssertionFinalization(webauthn.AssertionTransition{}); err == nil || p != nil {
		t.Fatal("zero store/preauth transition accepted")
	}
	var creation webauthnpg.AssertionCreation
	if _, err := creation.Fields(); err == nil {
		t.Fatal("zero creation supplied fields")
	}
	if err := creation.Generate(context.Background(), time.Now()); err == nil {
		t.Fatal("zero creation generated")
	}
	if err := creation.Validate(identity.Command{}, kernel.CommandPlan{}); err == nil {
		t.Fatal("zero creation validated")
	}
	if err := creation.Apply(context.Background(), kernel.Work{}, nil, identity.Command{}); err == nil {
		t.Fatal("zero creation applied")
	}
	if err := creation.Check(context.Background(), kernel.Work{}, nil, identity.Command{}); err == nil {
		t.Fatal("zero creation checked")
	}
	if _, _, err := creation.Result(identity.CommandResult{}); err == nil {
		t.Fatal("zero creation returned options")
	}
	creation.Discard()
	var finalization webauthnpg.AssertionFinalization
	if _, err := finalization.Fields(); err == nil {
		t.Fatal("zero finalization supplied fields")
	}
	if err := finalization.Validate(identity.Command{}, kernel.CommandPlan{}); err == nil {
		t.Fatal("zero finalization validated")
	}
	if err := finalization.Apply(context.Background(), kernel.Work{}, nil, identity.Command{}); err == nil {
		t.Fatal("zero finalization applied")
	}
	if err := finalization.Check(context.Background(), kernel.Work{}, nil, identity.Command{}); err == nil {
		t.Fatal("zero finalization checked")
	}
	if _, err := finalization.Result(identity.CommandResult{}); err == nil {
		t.Fatal("zero finalization returned credential")
	}
	if _, err := store.RecoverAssertion(context.Background(), kernel.RecoveryWork{}, nil); err == nil {
		t.Fatal("zero store recovered")
	}
}
