package postgres_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	webauthn "github.com/faustbrian/go-webauthn"
	webauthnpg "github.com/faustbrian/go-webauthn/postgres"
)

func TestEnrollmentParticipantsRejectInvalidCustody(t *testing.T) {
	var store *webauthnpg.Store
	if p, err := store.EnrollmentAssertionCreation(webauthn.CeremonyCreation{}); err == nil || p != nil {
		t.Fatal("zero assertion creation admitted")
	}
	if p, err := store.EnrollmentAuthorization(webauthn.AssertionTransition{}, webauthn.CeremonyCreation{}); err == nil || p != nil {
		t.Fatal("fabricated compound admitted")
	}
	if p, err := store.SessionRegistrationFinalization(webauthn.RegistrationTransition{}); err == nil || p != nil {
		t.Fatal("fabricated registration admitted")
	}
	var a webauthnpg.EnrollmentAssertionCreation
	var b webauthnpg.EnrollmentAuthorization
	var c webauthnpg.SessionRegistrationFinalization
	var nilA *webauthnpg.EnrollmentAssertionCreation
	var nilB *webauthnpg.EnrollmentAuthorization
	var nilC *webauthnpg.SessionRegistrationFinalization
	for _, p := range []interface {
		Fields() ([]identity.FeatureField, error)
		Validate(identity.Command, kernel.CommandPlan) error
		Apply(context.Context, kernel.Work, kernel.FeatureExecutionContributor, identity.Command) error
		Check(context.Context, kernel.Work, kernel.FeatureExecutionContributor, identity.Command) error
	}{&a, &b, &c, nilA, nilB, nilC} {
		if _, err := p.Fields(); err == nil {
			t.Fatal("zero participant supplied fields")
		}
		if err := p.Validate(identity.Command{}, kernel.CommandPlan{}); err == nil {
			t.Fatal("zero participant admitted command")
		}
		if err := p.Apply(context.Background(), kernel.Work{}, nil, identity.Command{}); err == nil {
			t.Fatal("zero participant applied")
		}
		if err := p.Check(context.Background(), kernel.Work{}, nil, identity.Command{}); err == nil {
			t.Fatal("zero participant checked")
		}
		if p == nilA || p == nilB || p == nilC {
			continue
		}
		if _, err := json.Marshal(p); err == nil {
			t.Fatal("participant exported custody")
		}
		if got := fmt.Sprintf("%#v", p); !strings.Contains(got, "redacted") {
			t.Fatal("participant did not redact")
		}
	}
	if err := a.Generate(context.Background(), time.Now()); err == nil {
		t.Fatal("zero assertion generated")
	}
	if err := b.Generate(context.Background(), time.Now()); err == nil {
		t.Fatal("zero compound generated")
	}
	if _, _, err := a.Result(identity.CommandResult{}); err == nil {
		t.Fatal("zero assertion revealed")
	}
	if _, _, _, err := b.Result(identity.CommandResult{}); err == nil {
		t.Fatal("zero compound revealed")
	}
	if _, err := c.Result(identity.CommandResult{}); err == nil {
		t.Fatal("zero registration revealed")
	}
	if !b.AuthorizationExpiresAt().IsZero() {
		t.Fatal("zero compound supplied authority")
	}
	a.Discard()
	b.Discard()
}
