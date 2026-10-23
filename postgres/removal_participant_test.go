package postgres_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	webauthnpg "github.com/faustbrian/go-webauthn/postgres"
)

func TestRemovalRejectsInvalidCustody(t *testing.T) {
	var store *webauthnpg.Store
	if p, err := store.CredentialRemoval(webauthnpg.RemovalRequest{}); err == nil || p != nil {
		t.Fatal("zero store or request accepted")
	}
	var p webauthnpg.CredentialRemoval
	if _, err := p.Fields(); err == nil {
		t.Fatal("zero participant supplied fields")
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
	if _, err := json.Marshal(p); err == nil {
		t.Fatal("participant serialized invocation state")
	}
	if output := fmt.Sprintf("%+v", p); !strings.Contains(output, "redacted") {
		t.Fatal("participant diagnostics are not redacted")
	}
}
