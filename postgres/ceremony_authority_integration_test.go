//go:build integration

package postgres_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	webauthn "github.com/faustbrian/go-webauthn"
)

// Characterize current-account authority independently of protocol validity:
// both challenges are issued while active, then the actual subject is suspended
// before either valid browser response reaches the genuine native finalizer.
func TestSuspendedSubjectCannotFinalizeCeremoniesPostgres(t *testing.T) {
	ctx, pool, _, store := nativeFixture(t)
	digestKey, e := webauthn.NewChallengeDigestKey(bytes.Repeat([]byte{41}, 32))
	if e != nil {
		t.Fatal(e)
	}
	svc, e := webauthn.New(webauthn.Config{TenantID: "tenant-a", RelyingParty: webauthn.RelyingParty{ID: "example.com", Name: "Authority fixture", Origins: []string{"https://login.example.com"}, Version: 1}, ChallengeKey: digestKey, MaximumDuration: 10 * time.Second, Extensions: webauthn.ExtensionRequestSet{CredentialProperties: true, CredentialProtection: 3, EnforceCredentialProtection: true}}, webauthn.Dependencies{Store: store})
	if e != nil {
		t.Fatal(e)
	}
	fresh := func() webauthn.CeremonyContext {
		id, e := identity.NewCommandID()
		if e != nil {
			t.Fatal(e)
		}
		return webauthn.CeremonyContext{CommandID: id, TenantID: "tenant-a", UserID: "user-a", ActorID: "actor-a", CorrelationID: "authority-test"}
	}
	handle := bytes.Repeat([]byte{42}, 32)
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	id := bytes.Repeat([]byte{43}, 32)
	registrationOptions, e := svc.BeginRegistration(ctx, webauthn.BeginRegistrationRequest{Context: fresh(), UserHandle: handle, Origin: "https://login.example.com"})
	if e != nil {
		t.Fatal(e)
	}
	registrationCeremony, _ := registrationOptions.Ceremony()
	registrationChallenge := optionChallenge(t, ctx, registrationOptions.TransferJSON)
	registered, e := svc.VerifyRegistration(ctx, webauthn.VerifyRegistrationRequest{Context: fresh(), CeremonyID: registrationCeremony.ID, Origin: "https://login.example.com", ExpectedVersion: 1, Response: registrationResponse(t, key, id, registrationChallenge, 0x45, 0)})
	if e != nil {
		t.Fatal("active subject could not enroll the fixture credential", e)
	}
	credential, ok := registered.Credential()
	if !ok || credential.Version != 1 || credential.Counter != 0 {
		t.Fatal("active enrollment did not finalize the expected credential")
	}
	// Exercise the same response builder and native verifier while authority is
	// present, so a generic denial below cannot hide malformed assertion input.
	activeOptions, e := svc.BeginAssertion(ctx, webauthn.BeginAssertionRequest{Context: fresh(), UserHandle: handle, Origin: "https://login.example.com", AllowedCredentials: [][]byte{id}})
	if e != nil {
		t.Fatal(e)
	}
	activeCeremony, _ := activeOptions.Ceremony()
	activeChallenge := optionChallenge(t, ctx, activeOptions.TransferJSON)
	active, e := svc.VerifyAssertion(ctx, webauthn.VerifyAssertionRequest{Context: fresh(), CeremonyID: activeCeremony.ID, Origin: "https://login.example.com", ExpectedVersion: 1, ExpectedCredentialVersion: credential.Version, Response: assertionResponse(t, key, id, handle, activeChallenge, 0x05, 1)})
	if e != nil {
		t.Fatal("active subject could not finalize the signed assertion", e)
	}
	credential, ok = active.Credential()
	if !ok || credential.Version != 2 || credential.Counter != 1 {
		t.Fatal("active assertion did not finalize the expected credential")
	}
	assertionOptions, e := svc.BeginAssertion(ctx, webauthn.BeginAssertionRequest{Context: fresh(), UserHandle: handle, Origin: "https://login.example.com", AllowedCredentials: [][]byte{id}})
	if e != nil {
		t.Fatal(e)
	}
	assertionCeremony, _ := assertionOptions.Ceremony()
	assertionChallenge := optionChallenge(t, ctx, assertionOptions.TransferJSON)
	assertion := webauthn.VerifyAssertionRequest{Context: fresh(), CeremonyID: assertionCeremony.ID, Origin: "https://login.example.com", ExpectedVersion: 1, ExpectedCredentialVersion: credential.Version, Response: assertionResponse(t, key, id, handle, assertionChallenge, 0x05, 2)}
	pendingOptions, e := svc.BeginRegistration(ctx, webauthn.BeginRegistrationRequest{Context: fresh(), UserHandle: handle, Origin: "https://login.example.com"})
	if e != nil {
		t.Fatal(e)
	}
	pendingCeremony, _ := pendingOptions.Ceremony()
	pendingChallenge := optionChallenge(t, ctx, pendingOptions.TransferJSON)
	pendingRegistration := webauthn.VerifyRegistrationRequest{Context: fresh(), CeremonyID: pendingCeremony.ID, Origin: "https://login.example.com", ExpectedVersion: 1, Response: registrationResponse(t, key, bytes.Repeat([]byte{44}, 32), pendingChallenge, 0x45, 0)}

	// Compare the complete persisted credential row, including its numeric
	// version and all record metadata, so counter/backup/usage changes cannot
	// hide behind a missing Verified result. Failure/no-change audits are allowed;
	// successful audits, native effects and lifecycle/outbox effects are not.
	var beforeCredential string
	if e = pool.Raw().QueryRow(ctx, `SELECT row_to_json(c)::text FROM webauthn.credentials c WHERE rp_id='example.com' AND credential_id=$1`, id).Scan(&beforeCredential); e != nil {
		t.Fatal(e)
	}
	var before [4]int
	if e = pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM webauthn.credentials),(SELECT count(*) FROM webauthn.effects),(SELECT count(*) FROM audit.records WHERE outcome=$1),(SELECT count(*) FROM public.outbox_messages)`, int(audit.OutcomeSucceeded)).Scan(&before[0], &before[1], &before[2], &before[3]); e != nil {
		t.Fatal(e)
	}
	// The fixture changes the authority owner's real row; it does not claim an
	// administrator-workflow implementation or replace any coordinator decision.
	changed, e := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='suspended',version=version+1 WHERE tenant_id='tenant-a' AND user_id='user-a' AND status='active'`)
	if e != nil || changed.RowsAffected() != 1 {
		t.Fatal("fixture did not suspend the actual active subject", e)
	}
	assertUnchanged := func(t *testing.T) {
		t.Helper()
		var afterCredential string
		if e := pool.Raw().QueryRow(ctx, `SELECT row_to_json(c)::text FROM webauthn.credentials c WHERE rp_id='example.com' AND credential_id=$1`, id).Scan(&afterCredential); e != nil || afterCredential != beforeCredential {
			t.Fatal("suspended subject changed credential counter/version/metadata", e)
		}
		var after [4]int
		if e := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM webauthn.credentials),(SELECT count(*) FROM webauthn.effects),(SELECT count(*) FROM audit.records WHERE outcome=$1),(SELECT count(*) FROM public.outbox_messages)`, int(audit.OutcomeSucceeded)).Scan(&after[0], &after[1], &after[2], &after[3]); e != nil || after != before {
			t.Fatal("suspended subject retained a credential or successful effect", e)
		}
		var unconsumed int
		if e := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM webauthn.ceremonies WHERE ceremony_id=ANY($1::text[]) AND consumed_by IS NULL`, []string{assertionCeremony.ID, pendingCeremony.ID}).Scan(&unconsumed); e != nil || unconsumed != 2 {
			t.Fatal("suspended subject consumed an issued ceremony", e)
		}
	}
	t.Run("assertion", func(t *testing.T) {
		verified, e := svc.VerifyAssertion(ctx, assertion)
		var denied webauthn.Denied
		if !errors.As(e, &denied) {
			t.Fatal("suspended subject's valid signed assertion was not denied", e)
		}
		if _, ok := verified.Credential(); ok {
			t.Fatal("suspended assertion returned verified credential evidence")
		}
		if _, ok := verified.Context(); ok {
			t.Fatal("suspended assertion returned verified ceremony context")
		}
		assertUnchanged(t)
	})
	t.Run("registration", func(t *testing.T) {
		verified, e := svc.VerifyRegistration(ctx, pendingRegistration)
		var denied webauthn.Denied
		if !errors.As(e, &denied) {
			t.Fatal("suspended subject's valid registration was not denied", e)
		}
		if _, ok := verified.Credential(); ok {
			t.Fatal("suspended registration returned verified credential evidence")
		}
		if _, ok := verified.Context(); ok {
			t.Fatal("suspended registration returned verified ceremony context")
		}
		assertUnchanged(t)
	})
}
