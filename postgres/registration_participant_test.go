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

func TestRegistrationParticipationInvalidCustody(t *testing.T) {
	var store *webauthnpg.Store
	if p, err := store.RegistrationCreation(webauthn.CeremonyCreation{}); err == nil || p != nil {
		t.Fatal("zero store/creation accepted")
	}
	if p, err := store.RegistrationFinalization(webauthn.RegistrationTransition{}); err == nil || p != nil {
		t.Fatal("zero store/verified transition accepted")
	}
	var creation webauthnpg.RegistrationCreation
	if _, err := creation.Fields(); err == nil {
		t.Fatal("zero creation supplied command fields")
	}
	if err := creation.Generate(context.Background(), time.Now()); err == nil {
		t.Fatal("zero creation generated challenge")
	}
	if err := creation.Apply(context.Background(), kernel.Work{}, nil, identity.Command{}); err == nil {
		t.Fatal("zero creation applied")
	}
	if _, _, err := creation.Result(identity.CommandResult{}); err == nil {
		t.Fatal("zero creation returned revealable output")
	}
	var finalization webauthnpg.RegistrationFinalization
	if _, err := finalization.Fields(); err == nil {
		t.Fatal("zero finalization supplied fields")
	}
	if err := finalization.Apply(context.Background(), kernel.Work{}, nil, identity.Command{}); err == nil {
		t.Fatal("zero finalization applied")
	}
	if _, err := finalization.Result(identity.CommandResult{}); err == nil {
		t.Fatal("zero finalization supplied a credential")
	}
}
