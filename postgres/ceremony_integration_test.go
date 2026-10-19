//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	outboxpg "github.com/faustbrian/go-transactional-outbox/v2/postgres"
	webauthn "github.com/faustbrian/go-webauthn"
	webauthnpg "github.com/faustbrian/go-webauthn/postgres"
	"github.com/jackc/pgx/v5"
)

type allowCeremony struct{}

// A faulty adapter cannot retarget a verifier by projecting a different stored
// scope/version. The embedded real Store still owns every durable operation.
type projectedStore struct {
	webauthn.Store
	project func(*webauthn.CeremonyRecord)
}

func (s projectedStore) LoadCeremony(ctx context.Context, q webauthn.Lookup) (webauthn.CeremonyRecord, error) {
	r, e := s.Store.LoadCeremony(ctx, q)
	if e == nil {
		s.project(&r)
	}
	return r, e
}

// Pause only after the public verifier has captured the original credential
// version, then let the genuine native Store exercise its optimistic CAS.
type pausedAssertionStore struct {
	webauthn.Store
	ready  chan<- struct{}
	resume <-chan struct{}
}

func (s pausedAssertionStore) FinalizeAssertion(ctx context.Context, transition webauthn.AssertionTransition) (webauthn.Credential, identity.CommitOutcome, error) {
	close(s.ready)
	select {
	case <-ctx.Done():
		return webauthn.Credential{}, identity.CommitOutcomeNotCommitted, webauthn.Unavailable{}
	case <-s.resume:
		return s.Store.FinalizeAssertion(ctx, transition)
	}
}

func (allowCeremony) Decide(_ context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	return authorization.Decision{Outcome: authorization.Allow, Revision: c.PolicyRevision}, nil
}

func nativeFixture(t *testing.T) (context.Context, *database.Pool, kernel.CoordinatorConfig, *webauthnpg.Store) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	dsn := os.Getenv("WEBAUTHN_TEST_DSN")
	if dsn == "" {
		t.Fatal("WEBAUTHN_TEST_DSN must identify an empty task-owned loopback PostgreSQL database")
	}
	pool, e := database.New(ctx, database.Config{DSN: dsn, MaxConns: 8, SessionInit: func(ctx context.Context, c *pgx.Conn) error { _, e := c.Exec(ctx, `SET search_path=public`); return e }})
	if e != nil {
		t.Fatal("task PostgreSQL connection", e)
	}
	t.Cleanup(func() { _ = pool.Close(context.Background()) })
	history, e := (kernel.MigrationSource{}).Load(ctx)
	if e != nil {
		t.Fatal(e)
	}
	for _, m := range history {
		if _, e = pool.Raw().Exec(ctx, m.UpSQL()); e != nil {
			t.Fatal("kernel migration", e)
		}
	}
	history, e = (webauthnpg.MigrationSource{}).Load(ctx)
	if e != nil {
		t.Fatal(e)
	}
	for _, m := range history {
		if _, e = pool.Raw().Exec(ctx, m.UpSQL()); e != nil {
			t.Fatal("ceremony migration", e)
		}
	}
	if _, e = pool.Raw().Exec(ctx, auditpg.FreshInstallPreflightSQL()); e != nil {
		t.Fatal(e)
	}
	for _, source := range []fs.FS{auditpg.Migrations(), outboxpg.Migrations(), lifecyclepg.Migrations()} {
		files, e := fs.ReadDir(source, ".")
		if e != nil {
			t.Fatal(e)
		}
		for _, file := range files {
			wire, e := fs.ReadFile(source, file.Name())
			if e != nil {
				t.Fatal(e)
			}
			if _, e = pool.Raw().Exec(ctx, strings.Split(string(wire), "-- +migrations Down")[0]); e != nil {
				t.Fatal("native effect migration", e)
			}
		}
	}
	if _, e = pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('tenant-a','user-a','active',1)`); e != nil {
		t.Fatal(e)
	}
	coordinator := kernel.CoordinatorConfig{MaximumDuration: 5 * time.Second, LeaseDuration: 30 * time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: &kernel.CommandQueryPolicy{Clock: clock.System{}, Authorization: allowCeremony{}, PolicyVersion: 1}}
	store, e := webauthnpg.New(pool, webauthnpg.Config{Coordinator: coordinator, PolicyID: "webauthn-test", PolicyVersion: 1})
	if e != nil {
		t.Fatal(e)
	}
	return ctx, pool, coordinator, store
}

func TestRegistrationAssertionPostgres(t *testing.T) {
	ctx, pool, coordinator, store := nativeFixture(t)
	digestKey, e := webauthn.NewChallengeDigestKey(bytes.Repeat([]byte{2}, 32))
	if e != nil {
		t.Fatal(e)
	}
	config := webauthn.Config{TenantID: "tenant-a", RelyingParty: webauthn.RelyingParty{ID: "example.com", Name: "Example", Origins: []string{"https://login.example.com"}, Version: 1}, ChallengeKey: digestKey, MaximumDuration: 10 * time.Second, Extensions: webauthn.ExtensionRequestSet{CredentialProperties: true, CredentialProtection: 3, EnforceCredentialProtection: true}}
	svc, e := webauthn.New(config, webauthn.Dependencies{Store: store})
	if e != nil {
		t.Fatal(e)
	}
	fresh := func() webauthn.CeremonyContext {
		id, e := identity.NewCommandID()
		if e != nil {
			t.Fatal(e)
		}
		return webauthn.CeremonyContext{CommandID: id, TenantID: "tenant-a", UserID: "user-a", ActorID: "actor-a", CorrelationID: "ceremony-test"}
	}
	begin := webauthn.BeginRegistrationRequest{Context: fresh(), UserHandle: bytes.Repeat([]byte{7}, 32), Origin: "https://login.example.com"}
	options, e := svc.BeginRegistration(ctx, begin)
	if e != nil {
		t.Fatal("create durable registration", e)
	}
	record, ok := options.Ceremony()
	if !ok || record.ID != string(begin.Context.CommandID) {
		t.Fatal("original ceremony identity")
	}
	challenge := optionChallenge(t, ctx, options.TransferJSON)
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	id := bytes.Repeat([]byte{8}, 32)
	registration := webauthn.VerifyRegistrationRequest{Context: fresh(), CeremonyID: record.ID, Origin: begin.Origin, Response: registrationResponse(t, key, id, challenge, 0x45, 0), ExpectedVersion: 1}
	registered, e := svc.VerifyRegistration(ctx, registration)
	if e != nil {
		t.Fatal("finalized public registration", e)
	}
	credential, ok := registered.Credential()
	if !ok || credential.Version != 1 || !bytes.Equal(credential.ID, id) {
		t.Fatal("finalized credential")
	}
	// Same original command after service restart must replay its original result,
	// not create another credential, challenge consumption, audit or lifecycle row.
	store, e = webauthnpg.New(pool, webauthnpg.Config{Coordinator: coordinator, PolicyID: "webauthn-test", PolicyVersion: 1})
	if e != nil {
		t.Fatal(e)
	}
	svc, e = webauthn.New(config, webauthn.Dependencies{Store: store})
	if e != nil {
		t.Fatal(e)
	}
	var replay webauthn.Replay
	if result, e := svc.VerifyRegistration(ctx, registration); !errors.As(e, &replay) {
		t.Fatal("original registration replay must withhold verification", e)
	} else if _, ok := result.Credential(); ok {
		t.Fatal("replay reissued verification")
	}
	if outcome, e := svc.Recover(ctx, webauthn.RecoveryRequest{Context: registration.Context, Operation: webauthn.RegistrationOperation, CredentialID: id}); e != nil || outcome != identity.CommitOutcomeCommitted {
		t.Fatal("original registration outcome recovery", e)
	}
	if retry, e := svc.BeginRegistration(ctx, begin); e != nil {
		t.Fatal("creation replay", e)
	} else if e = retry.TransferJSON(ctx, func(context.Context, []byte) error { t.Fatal("replayed challenge revealed"); return nil }); e == nil {
		t.Fatal("replay must withhold challenge")
	}
	assertionBegin := webauthn.BeginAssertionRequest{Context: fresh(), UserHandle: begin.UserHandle, Origin: begin.Origin, AllowedCredentials: [][]byte{id}}
	assertOptions, e := svc.BeginAssertion(ctx, assertionBegin)
	if e != nil {
		t.Fatal("create assertion", e)
	}
	assertCeremony, _ := assertOptions.Ceremony()
	assertChallenge := optionChallenge(t, ctx, assertOptions.TransferJSON)
	assertion := webauthn.VerifyAssertionRequest{Context: fresh(), CeremonyID: assertCeremony.ID, Origin: begin.Origin, Response: assertionResponse(t, key, id, begin.UserHandle, assertChallenge, 0x05, 1), ExpectedVersion: 1, ExpectedCredentialVersion: 1}
	verified, e := svc.VerifyAssertion(ctx, assertion)
	if e != nil {
		t.Fatal("finalized signed assertion", e)
	}
	updated, ok := verified.Credential()
	if !ok || updated.Counter != 1 || updated.Version != 2 || verified.CounterRisk() {
		t.Fatal("counter transition")
	}
	if result, e := svc.VerifyAssertion(ctx, assertion); !errors.As(e, &replay) {
		t.Fatal("original assertion replay must withhold verification", e)
	} else if _, ok := result.Credential(); ok {
		t.Fatal("assertion replay reissued verification")
	}
	if outcome, e := svc.Recover(ctx, webauthn.RecoveryRequest{Context: assertion.Context, Operation: webauthn.AssertionOperation, CredentialID: id}); e != nil || outcome != identity.CommitOutcomeCommitted {
		t.Fatal("original assertion outcome recovery", e)
	}
	assertion.Context = fresh()
	if v, e := svc.VerifyAssertion(ctx, assertion); e == nil {
		t.Fatal("consumed ceremony authenticated again", v)
	}
	var credentials, audits, effects int
	if e = pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM webauthn.credentials),(SELECT count(*) FROM audit.identity_command_bindings),(SELECT count(*) FROM webauthn.effects)`).Scan(&credentials, &audits, &effects); e != nil {
		t.Fatal(e)
	}
	if credentials != 1 || effects != 4 || audits != 4 {
		t.Fatalf("native atomic counts: credentials=%d effects=%d audits=%d", credentials, effects, audits)
	}
	if verifiedContext, ok := verified.Context(); !ok || verifiedContext.Command.CommandID == "" || verifiedContext.CeremonyID != assertCeremony.ID || verifiedContext.RPID != "example.com" || verifiedContext.RPVersion != 1 || verifiedContext.Origin != begin.Origin || !verifiedContext.ExpiresAt.Equal(assertCeremony.ExpiresAt) || !verifiedContext.UserPresent || !verifiedContext.UserVerified {
		t.Fatal("verified result lost original finalized context")
	}

	newRegistered := func(t *testing.T, count uint32, flags byte) (*ecdsa.PrivateKey, []byte, webauthn.Credential) {
		t.Helper()
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		id := make([]byte, 32)
		if _, e = rand.Read(id); e != nil {
			t.Fatal(e)
		}
		options, e := svc.BeginRegistration(ctx, webauthn.BeginRegistrationRequest{Context: fresh(), UserHandle: begin.UserHandle, Origin: begin.Origin})
		if e != nil {
			t.Fatal(e)
		}
		ceremony, _ := options.Ceremony()
		challenge := optionChallenge(t, ctx, options.TransferJSON)
		result, e := svc.VerifyRegistration(ctx, webauthn.VerifyRegistrationRequest{Context: fresh(), CeremonyID: ceremony.ID, Origin: begin.Origin, Response: registrationResponse(t, key, id, challenge, flags, count), ExpectedVersion: 1})
		if e != nil {
			t.Fatal("case registration", e)
		}
		credential, ok := result.Credential()
		if !ok {
			t.Fatal("no registered credential")
		}
		return key, id, credential
	}
	newAssertion := func(t *testing.T, key *ecdsa.PrivateKey, id []byte, c webauthn.Credential, flags byte, count uint32) webauthn.VerifyAssertionRequest {
		t.Helper()
		options, e := svc.BeginAssertion(ctx, webauthn.BeginAssertionRequest{Context: fresh(), UserHandle: begin.UserHandle, Origin: begin.Origin, AllowedCredentials: [][]byte{id}})
		if e != nil {
			t.Fatal(e)
		}
		ceremony, _ := options.Ceremony()
		challenge := optionChallenge(t, ctx, options.TransferJSON)
		return webauthn.VerifyAssertionRequest{Context: fresh(), CeremonyID: ceremony.ID, Origin: begin.Origin, Response: assertionResponse(t, key, id, begin.UserHandle, challenge, flags, count), ExpectedVersion: 1, ExpectedCredentialVersion: c.Version}
	}
	// A command reservation may remain for original-command recovery, but no
	// domain, success-audit or lifecycle effect may escape a denied/rolled-back
	// command. The kernel deliberately persists separate no-change failure audits.
	durableCounts := func(t *testing.T) [5]int {
		t.Helper()
		var n [5]int
		if e := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM webauthn.credentials),(SELECT count(*) FROM webauthn.effects),(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE r.outcome=$1),(SELECT count(*) FROM public.outbox_messages),(SELECT count(*) FROM webauthn.ceremonies WHERE consumed_by IS NOT NULL)`, int(audit.OutcomeSucceeded)).Scan(&n[0], &n[1], &n[2], &n[3], &n[4]); e != nil {
			t.Fatal(e)
		}
		return n
	}
	assertFailureAudit := func(t *testing.T, command identity.CommandID, outcome audit.Outcome) {
		t.Helper()
		id, e := base64.RawURLEncoding.DecodeString(string(command))
		if e != nil {
			t.Fatal(e)
		}
		var wire []byte
		if e = pool.Raw().QueryRow(ctx, `SELECT r.canonical_record FROM audit.records r JOIN audit.identity_command_bindings b ON b.event_id=r.record_id WHERE b.command_id=$1`, id).Scan(&wire); e != nil {
			t.Fatal("missing original failure audit", e)
		}
		record, e := audit.ParseCanonicalJSON(wire, audit.DefaultLimits())
		if e != nil || record.Outcome() != outcome || !record.Changes().NoChange() || record.Attributes()["aggregate.before_version"] != record.Attributes()["aggregate.after_version"] {
			t.Fatal("failure audit claimed a partial credential change", e)
		}
	}
	t.Run("foreign Store projection cannot verify", func(t *testing.T) {
		options, e := svc.BeginRegistration(ctx, webauthn.BeginRegistrationRequest{Context: fresh(), UserHandle: begin.UserHandle, Origin: begin.Origin})
		if e != nil {
			t.Fatal(e)
		}
		ceremony, _ := options.Ceremony()
		challenge := optionChallenge(t, ctx, options.TransferJSON)
		id := bytes.Repeat([]byte{31}, 32)
		request := webauthn.VerifyRegistrationRequest{Context: fresh(), CeremonyID: ceremony.ID, Origin: begin.Origin, ExpectedVersion: 1, Response: registrationResponse(t, key, id, challenge, 0x45, 0)}
		for _, tc := range []struct {
			name    string
			project func(*webauthn.CeremonyRecord)
		}{
			{"tenant", func(r *webauthn.CeremonyRecord) { r.Intent.Context.TenantID = "tenant-b" }},
			{"subject", func(r *webauthn.CeremonyRecord) { r.Intent.Context.UserID = "user-b" }},
			{"actor", func(r *webauthn.CeremonyRecord) { r.Intent.Context.ActorID = "actor-b" }},
			{"RP", func(r *webauthn.CeremonyRecord) { r.Intent.RPID = "other.example.com" }},
			{"RP policy version", func(r *webauthn.CeremonyRecord) { r.Intent.RPVersion++ }},
			{"ceremony version", func(r *webauthn.CeremonyRecord) { r.Version++ }},
			{"origin", func(r *webauthn.CeremonyRecord) { r.Intent.Origin = "https://other.example.com" }},
		} {
			t.Run(tc.name, func(t *testing.T) {
				wrapped, e := webauthn.New(config, webauthn.Dependencies{Store: projectedStore{Store: store, project: tc.project}})
				if e != nil {
					t.Fatal(e)
				}
				before := durableCounts(t)
				verified, e := wrapped.VerifyRegistration(ctx, request)
				if e == nil {
					t.Fatal("foreign Store projection verified")
				}
				if _, ok := verified.Credential(); ok || durableCounts(t) != before {
					t.Fatal("foreign Store projection leaked verification or durable effects")
				}
			})
		}
		if _, e = svc.VerifyRegistration(ctx, request); e != nil {
			t.Fatal("projection denial consumed original ceremony", e)
		}
	})
	t.Run("hostile registration does not consume ceremony", func(t *testing.T) {
		options, e := svc.BeginRegistration(ctx, webauthn.BeginRegistrationRequest{Context: fresh(), UserHandle: begin.UserHandle, Origin: begin.Origin})
		if e != nil {
			t.Fatal(e)
		}
		ceremony, _ := options.Ceremony()
		challenge := optionChallenge(t, ctx, options.TransferJSON)
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		id := make([]byte, 32)
		if _, e = rand.Read(id); e != nil {
			t.Fatal(e)
		}
		base := webauthn.VerifyRegistrationRequest{Context: fresh(), CeremonyID: ceremony.ID, Origin: begin.Origin, ExpectedVersion: 1, Response: registrationResponse(t, key, id, challenge, 0x45, 0)}
		for _, name := range []string{"tenant", "subject", "actor", "origin", "version", "client origin", "challenge", "ceremony type", "cross origin", "top origin", "missing UP", "missing UV", "BS without BE", "duplicate JSON", "oversized JSON", "unknown algorithm"} {
			t.Run(name, func(t *testing.T) {
				r := base
				r.Context = fresh()
				r.Response = bytes.Clone(base.Response)
				switch name {
				case "tenant":
					r.Context.TenantID = "tenant-b"
				case "subject":
					r.Context.UserID = "other-user"
				case "actor":
					r.Context.ActorID = "other-actor"
				case "origin":
					r.Origin = "https://evil.example.com"
				case "version":
					r.ExpectedVersion = 2
				case "missing UP":
					r.Response = registrationResponse(t, key, id, challenge, 0x44, 0)
				case "missing UV":
					r.Response = registrationResponse(t, key, id, challenge, 0x41, 0)
				case "BS without BE":
					r.Response = registrationResponse(t, key, id, challenge, 0x55, 0)
				case "duplicate JSON":
					r.Response = append([]byte(`{"type":"public-key",`), base.Response[1:]...)
				case "oversized JSON":
					r.Response = bytes.Repeat([]byte{'x'}, (128<<10)+1)
				case "unknown algorithm":
					r.Response = mutateAttestation(t, r.Response, func(b []byte) []byte { return bytes.Replace(b, []byte{0x03, 0x26, 0x20}, []byte{0x03, 0x27, 0x20}, 1) })
				default:
					r.Response = mutateClient(t, r.Response, func(v map[string]any) {
						switch name {
						case "client origin":
							v["origin"] = "https://evil.example.com"
						case "challenge":
							v["challenge"] = b64(make([]byte, 32))
						case "ceremony type":
							v["type"] = "webauthn.get"
						case "cross origin":
							v["crossOrigin"] = true
						case "top origin":
							v["topOrigin"] = nil
						}
					})
				}
				before := durableCounts(t)
				result, e := svc.VerifyRegistration(ctx, r)
				if e == nil {
					t.Fatal("hostile ceremony accepted")
				}
				if _, ok := result.Credential(); ok {
					t.Fatal("hostile ceremony returned verification")
				}
				if durableCounts(t) != before {
					t.Fatal("hostile registration retained partial durable effects")
				}
			})
		}
		if _, e = svc.VerifyRegistration(ctx, base); e != nil {
			t.Fatal("denied input consumed challenge", e)
		}
	})
	t.Run("backup and counter policy", func(t *testing.T) {
		for _, tc := range []struct {
			name                              string
			stored, received                  uint32
			registrationFlags, assertionFlags byte
			deny, risk                        bool
			counter                           uint32
		}{
			{"nonbackup unsupported zero", 0, 0, 0x45, 0x05, false, false, 0},
			{"nonbackup advance", 0, 2, 0x45, 0x05, false, false, 2},
			{"nonbackup positive advance", 5, 6, 0x45, 0x05, false, false, 6},
			{"nonbackup equal", 5, 5, 0x45, 0x05, true, false, 5},
			{"nonbackup decreased", 5, 4, 0x45, 0x05, true, false, 5},
			{"nonbackup reset", 5, 0, 0x45, 0x05, true, false, 5},
			{"backup zero", 5, 0, 0x4d, 0x1d, false, true, 5},
			{"backup equal", 5, 5, 0x4d, 0x1d, false, true, 5},
			{"backup decreased", 5, 4, 0x4d, 0x0d, false, true, 5},
			{"backup positive", 5, 6, 0x4d, 0x1d, false, false, 6},
			{"eligibility cannot change", 0, 1, 0x45, 0x0d, true, false, 0},
		} {
			t.Run(tc.name, func(t *testing.T) {
				key, id, c := newRegistered(t, tc.stored, tc.registrationFlags)
				r := newAssertion(t, key, id, c, tc.assertionFlags, tc.received)
				before := durableCounts(t)
				v, e := svc.VerifyAssertion(ctx, r)
				if tc.deny {
					if e == nil {
						t.Fatal("counter/backup denial accepted")
					}
					if _, ok := v.Credential(); ok {
						t.Fatal("denial returned verification")
					}
					stored, e := store.LoadCredential(ctx, webauthn.Lookup{Context: r.Context, RPID: "example.com", CeremonyID: r.CeremonyID}, id)
					if e != nil || stored.Counter != c.Counter || stored.Version != c.Version || stored.BackupState != c.BackupState || durableCounts(t) != before {
						t.Fatal("counter denial retained partial durable effects", e)
					}
					return
				}
				if e != nil {
					t.Fatal(e)
				}
				updated, ok := v.Credential()
				if !ok || updated.Counter != tc.counter || updated.Version != 2 || updated.BackupState != (tc.assertionFlags&16 != 0) || v.CounterRisk() != tc.risk {
					t.Fatal("counter/backup transition changed")
				}
			})
		}
	})
	t.Run("otherwise valid assertions require exact signed bytes and key", func(t *testing.T) {
		key, id, c := newRegistered(t, 0, 0x45)
		request := newAssertion(t, key, id, c, 0x05, 1)
		wrongKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		for _, name := range []string{"wrong signing key", "changed authenticator bytes", "changed client data bytes"} {
			t.Run(name, func(t *testing.T) {
				r := request
				r.Context = fresh()
				switch name {
				case "wrong signing key":
					r.Response = resignAssertionResponse(t, request.Response, wrongKey)
				case "changed authenticator bytes":
					r.Response = mutateAssertionMember(t, request.Response, "authenticatorData", func(b []byte) []byte { b[36] = 2; return b })
				case "changed client data bytes":
					// Whitespace preserves parsed challenge/origin/type. Only
					// signature verification of exact received bytes can deny it.
					r.Response = mutateAssertionMember(t, request.Response, "clientDataJSON", func(b []byte) []byte { return append([]byte{' '}, b...) })
				}
				before := durableCounts(t)
				verified, e := svc.VerifyAssertion(ctx, r)
				var denied webauthn.Denied
				if !errors.As(e, &denied) {
					t.Fatal("otherwise valid forged assertion was not denied", e)
				}
				if _, ok := verified.Credential(); ok || durableCounts(t) != before {
					t.Fatal("signature denial retained verification or success effects")
				}
				stored, e := store.LoadCredential(ctx, webauthn.Lookup{Context: r.Context, RPID: "example.com", CeremonyID: r.CeremonyID}, id)
				if e != nil || stored.Counter != c.Counter || stored.Version != c.Version || stored.BackupState != c.BackupState {
					t.Fatal("signature denial changed credential", e)
				}
				var unconsumed int
				if e = pool.Raw().QueryRow(ctx, `SELECT count(*) FROM webauthn.ceremonies WHERE ceremony_id=$1 AND consumed_by IS NULL`, r.CeremonyID).Scan(&unconsumed); e != nil || unconsumed != 1 {
					t.Fatal("signature denial consumed original ceremony", e)
				}
			})
		}
		verified, e := svc.VerifyAssertion(ctx, request)
		if e != nil {
			t.Fatal("signature denials prevented original valid assertion", e)
		}
		updated, ok := verified.Credential()
		if !ok || updated.Extensions.CredentialProtection == nil || c.Extensions.CredentialProtection == nil || *updated.Extensions.CredentialProtection != *c.Extensions.CredentialProtection || updated.Extensions.CredentialProperties == nil || c.Extensions.CredentialProperties == nil || *updated.Extensions.CredentialProperties != *c.Extensions.CredentialProperties {
			t.Fatal("valid assertion refreshed or lost retained enrollment metadata")
		}
	})
	t.Run("distinct ceremonies cannot rebase a stale credential version", func(t *testing.T) {
		key, id, c := newRegistered(t, 0, 0x45)
		first := newAssertion(t, key, id, c, 0x05, 1)
		second := newAssertion(t, key, id, c, 0x05, 2)
		if first.CeremonyID == second.CeremonyID {
			t.Fatal("fixture reused a ceremony")
		}
		ready, resume := make(chan struct{}), make(chan struct{})
		paused, e := webauthn.New(config, webauthn.Dependencies{Store: pausedAssertionStore{Store: store, ready: ready, resume: resume}})
		if e != nil {
			t.Fatal(e)
		}
		secondCtx, cancel := context.WithCancel(ctx)
		var wg sync.WaitGroup
		defer func() { cancel(); wg.Wait() }()
		result := make(chan struct {
			verified bool
			err      error
		}, 1)
		wg.Go(func() {
			v, e := paused.VerifyAssertion(secondCtx, second)
			_, ok := v.Credential()
			result <- struct {
				verified bool
				err      error
			}{ok, e}
			close(result)
		})
		select {
		case <-ready:
		case got := <-result:
			t.Fatal("second assertion failed before native boundary", got.err)
		case <-ctx.Done():
			t.Fatal("second assertion never reached native boundary")
		}
		if _, e = svc.VerifyAssertion(ctx, first); e != nil {
			t.Fatal("first distinct ceremony did not finalize", e)
		}
		before := durableCounts(t)
		close(resume)
		select {
		case got := <-result:
			var conflict webauthn.Conflict
			if got.verified || !errors.As(got.err, &conflict) {
				t.Fatal("stale distinct ceremony was rebased or not conflicted", got.err)
			}
		case <-ctx.Done():
			t.Fatal("stale native finalization did not terminate")
		}
		if durableCounts(t) != before {
			t.Fatal("stale distinct ceremony retained success effects")
		}
		stored, e := store.LoadCredential(ctx, webauthn.Lookup{Context: second.Context, RPID: "example.com", CeremonyID: second.CeremonyID}, id)
		if e != nil || stored.Counter != 1 || stored.Version != 2 {
			t.Fatal("stale distinct ceremony changed current credential", e)
		}
		var unconsumed int
		if e = pool.Raw().QueryRow(ctx, `SELECT count(*) FROM webauthn.ceremonies WHERE ceremony_id=$1 AND consumed_by IS NULL`, second.CeremonyID).Scan(&unconsumed); e != nil || unconsumed != 1 {
			t.Fatal("stale credential conflict consumed second ceremony", e)
		}
	})
	t.Run("distinct competing commands have one winner", func(t *testing.T) {
		key, id, c := newRegistered(t, 0, 0x45)
		r := newAssertion(t, key, id, c, 0x05, 1)
		other := r
		other.Context = fresh()
		var wg sync.WaitGroup
		var outcomes [2]bool
		for index, request := range []webauthn.VerifyAssertionRequest{r, other} {
			wg.Go(func() {
				v, e := svc.VerifyAssertion(ctx, request)
				_, ok := v.Credential()
				outcomes[index] = e == nil && ok
			})
		}
		wg.Wait()
		if outcomes[0] == outcomes[1] {
			t.Fatal("contention did not produce one winner")
		}
	})
	t.Run("primary expiry and canceled work cannot finalize", func(t *testing.T) {
		key, id, c := newRegistered(t, 0, 0x45)
		r := newAssertion(t, key, id, c, 0x05, 1)
		before := durableCounts(t)
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if result, e := svc.VerifyAssertion(canceled, r); e == nil {
			t.Fatal("canceled assertion finalized")
		} else if _, ok := result.Credential(); ok || durableCounts(t) != before {
			t.Fatal("canceled assertion retained partial effects")
		}
		// Shorten the primary-authority deadline while leaving its original
		// digest-bound public projection intact: the adapter must independently
		// enforce its current SQL deadline, not trust previously read metadata.
		if _, e := pool.Raw().Exec(ctx, `UPDATE webauthn.ceremonies SET expires_at=clock_timestamp()-interval '1 second' WHERE ceremony_id=$1`, r.CeremonyID); e != nil {
			t.Fatal(e)
		}
		if result, e := svc.VerifyAssertion(ctx, r); e == nil {
			t.Fatal("primary-expired assertion finalized")
		} else if _, ok := result.Credential(); ok || durableCounts(t) != before {
			t.Fatal("expired assertion retained partial effects")
		}
		assertFailureAudit(t, r.Context.CommandID, audit.OutcomeDenied)
		stored, e := store.LoadCredential(ctx, webauthn.Lookup{Context: r.Context, RPID: "example.com", CeremonyID: r.CeremonyID}, id)
		if e != nil || stored.Counter != 0 || stored.Version != 1 {
			t.Fatal("expiry/cancellation changed credential", e)
		}
	})
	t.Run("outbox failure rolls back consumption and credential", func(t *testing.T) {
		key, id, c := newRegistered(t, 0, 0x45)
		r := newAssertion(t, key, id, c, 0x05, 1)
		before := durableCounts(t)
		if _, e := pool.Raw().Exec(ctx, `CREATE FUNCTION public.webauthn_fail_outbox() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test outbox failure'; END $$; CREATE TRIGGER webauthn_fail_outbox BEFORE INSERT ON public.outbox_messages FOR EACH ROW EXECUTE FUNCTION public.webauthn_fail_outbox();`); e != nil {
			t.Fatal(e)
		}
		v, e := svc.VerifyAssertion(ctx, r)
		if _, drop := pool.Raw().Exec(ctx, `DROP TRIGGER webauthn_fail_outbox ON public.outbox_messages; DROP FUNCTION public.webauthn_fail_outbox();`); drop != nil {
			t.Fatal(drop)
		}
		if e == nil {
			t.Fatal("outbox failure authenticated")
		}
		if _, ok := v.Credential(); ok {
			t.Fatal("rollback returned verification")
		}
		if durableCounts(t) != before {
			t.Fatal("outbox failure retained consumption/audit/lifecycle partial effects")
		}
		assertFailureAudit(t, r.Context.CommandID, audit.OutcomeFailed)
		stored, e := store.LoadCredential(ctx, webauthn.Lookup{Context: r.Context, RPID: "example.com", CeremonyID: r.CeremonyID}, id)
		if e != nil || stored.Counter != 0 || stored.Version != 1 {
			t.Fatal("outbox failure retained mutation", e)
		}
		r.Context = fresh()
		if _, e = svc.VerifyAssertion(ctx, r); e != nil {
			t.Fatal("rollback consumed original challenge", e)
		}
	})
	t.Run("commit ambiguity recovers original noncommit", func(t *testing.T) {
		key, id, c := newRegistered(t, 0, 0x45)
		r := newAssertion(t, key, id, c, 0x05, 1)
		before := durableCounts(t)
		if _, e := pool.Raw().Exec(ctx, `CREATE FUNCTION public.webauthn_commit_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'deferred test commit failure'; END $$; CREATE CONSTRAINT TRIGGER webauthn_commit_fail AFTER INSERT ON webauthn.effects DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.webauthn_commit_fail();`); e != nil {
			t.Fatal(e)
		}
		v, e := svc.VerifyAssertion(ctx, r)
		if _, drop := pool.Raw().Exec(ctx, `DROP TRIGGER webauthn_commit_fail ON webauthn.effects; DROP FUNCTION public.webauthn_commit_fail();`); drop != nil {
			t.Fatal(drop)
		}
		var unknown webauthn.UnknownCommit
		if !errors.As(e, &unknown) || unknown.CommandID != r.Context.CommandID {
			t.Fatal("commit ambiguity lost original identity", e)
		}
		if _, ok := v.Credential(); ok {
			t.Fatal("ambiguous commit returned verification")
		}
		if durableCounts(t) != before {
			t.Fatal("rolled-back ambiguous commit retained partial durable effects")
		}
		commandID, e := base64.RawURLEncoding.DecodeString(string(r.Context.CommandID))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, commandID); e != nil {
			t.Fatal(e)
		}
		outcome, _ := svc.Recover(ctx, webauthn.RecoveryRequest{Context: r.Context, Operation: webauthn.AssertionOperation, CredentialID: id})
		if outcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("original noncommit not recovered", outcome)
		}
		stored, e := store.LoadCredential(ctx, webauthn.Lookup{Context: r.Context, RPID: "example.com", CeremonyID: r.CeremonyID}, id)
		if e != nil || stored.Counter != 0 || stored.Version != 1 {
			t.Fatal("unknown rollback changed credential", e)
		}
	})
}

func mutateAssertionMember(t *testing.T, wire []byte, member string, mutate func([]byte) []byte) []byte {
	t.Helper()
	var outer map[string]any
	if e := json.Unmarshal(wire, &outer); e != nil {
		t.Fatal(e)
	}
	response := outer["response"].(map[string]any)
	b, e := base64.RawURLEncoding.DecodeString(response[member].(string))
	if e != nil {
		t.Fatal(e)
	}
	response[member] = b64(mutate(b))
	result, e := json.Marshal(outer)
	if e != nil {
		t.Fatal(e)
	}
	return result
}

func resignAssertionResponse(t *testing.T, wire []byte, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	var outer map[string]any
	if e := json.Unmarshal(wire, &outer); e != nil {
		t.Fatal(e)
	}
	response := outer["response"].(map[string]any)
	auth, e := base64.RawURLEncoding.DecodeString(response["authenticatorData"].(string))
	if e != nil {
		t.Fatal(e)
	}
	client, e := base64.RawURLEncoding.DecodeString(response["clientDataJSON"].(string))
	if e != nil {
		t.Fatal(e)
	}
	hash := sha256.Sum256(client)
	digest := sha256.Sum256(append(auth, hash[:]...))
	signature, e := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if e != nil {
		t.Fatal(e)
	}
	response["signature"] = b64(signature)
	result, e := json.Marshal(outer)
	if e != nil {
		t.Fatal(e)
	}
	return result
}

func mutateClient(t *testing.T, wire []byte, mutate func(map[string]any)) []byte {
	t.Helper()
	var r map[string]any
	if e := json.Unmarshal(wire, &r); e != nil {
		t.Fatal(e)
	}
	response := r["response"].(map[string]any)
	client, e := base64.RawURLEncoding.DecodeString(response["clientDataJSON"].(string))
	if e != nil {
		t.Fatal(e)
	}
	var value map[string]any
	if e = json.Unmarshal(client, &value); e != nil {
		t.Fatal(e)
	}
	mutate(value)
	client, e = json.Marshal(value)
	if e != nil {
		t.Fatal(e)
	}
	response["clientDataJSON"] = b64(client)
	out, e := json.Marshal(r)
	if e != nil {
		t.Fatal(e)
	}
	return out
}
func mutateAttestation(t *testing.T, wire []byte, mutate func([]byte) []byte) []byte {
	t.Helper()
	var r map[string]any
	if e := json.Unmarshal(wire, &r); e != nil {
		t.Fatal(e)
	}
	response := r["response"].(map[string]any)
	att, e := base64.RawURLEncoding.DecodeString(response["attestationObject"].(string))
	if e != nil {
		t.Fatal(e)
	}
	response["attestationObject"] = b64(mutate(att))
	out, e := json.Marshal(r)
	if e != nil {
		t.Fatal(e)
	}
	return out
}

func optionChallenge(t *testing.T, ctx context.Context, transfer func(context.Context, func(context.Context, []byte) error) error) string {
	t.Helper()
	var out string
	if e := transfer(ctx, func(_ context.Context, b []byte) error {
		var wire struct {
			PublicKey struct {
				Challenge string `json:"challenge"`
			} `json:"publicKey"`
		}
		if e := json.Unmarshal(b, &wire); e != nil {
			return e
		}
		out = wire.PublicKey.Challenge
		return nil
	}); e != nil || out == "" {
		t.Fatal("challenge delivery", e)
	}
	return out
}
func b64(b []byte) string       { return base64.RawURLEncoding.EncodeToString(b) }
func cborText(s string) []byte  { return append(cborHead(3, len(s)), []byte(s)...) }
func cborBytes(b []byte) []byte { return append(cborHead(2, len(b)), b...) }
func cborHead(major byte, n int) []byte {
	if n < 24 {
		return []byte{major<<5 | byte(n)}
	}
	if n < 256 {
		return []byte{major<<5 | 24, byte(n)}
	}
	return binary.BigEndian.AppendUint16([]byte{major<<5 | 25}, uint16(n))
}
func authData(flags byte, count uint32) []byte {
	rp := sha256.Sum256([]byte("example.com"))
	out := append([]byte{}, rp[:]...)
	out = append(out, flags)
	return binary.BigEndian.AppendUint32(out, count)
}
func clientJSON(kind, challenge string) []byte {
	wire, _ := json.Marshal(map[string]any{"type": "webauthn." + kind, "challenge": challenge, "origin": "https://login.example.com", "crossOrigin": false})
	return wire
}
func registrationResponse(t *testing.T, key *ecdsa.PrivateKey, id []byte, challenge string, flags byte, count uint32) []byte {
	t.Helper()
	cose := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21}
	cose = append(cose, cborBytes(key.X.FillBytes(make([]byte, 32)))...)
	cose = append(cose, 0x22)
	cose = append(cose, cborBytes(key.Y.FillBytes(make([]byte, 32)))...)
	auth := authData(flags|0xc0, count)
	auth = append(auth, make([]byte, 16)...)
	auth = binary.BigEndian.AppendUint16(auth, uint16(len(id)))
	auth = append(auth, id...)
	auth = append(auth, cose...)
	auth = append(auth, 0xa1)
	auth = append(auth, cborText("credProtect")...)
	auth = append(auth, 0x03)
	att := []byte{0xa3}
	att = append(att, cborText("fmt")...)
	att = append(att, cborText("none")...)
	att = append(att, cborText("attStmt")...)
	att = append(att, 0xa0)
	att = append(att, cborText("authData")...)
	att = append(att, cborBytes(auth)...)
	wire, e := json.Marshal(map[string]any{"id": b64(id), "rawId": b64(id), "type": "public-key", "response": map[string]string{"clientDataJSON": b64(clientJSON("create", challenge)), "attestationObject": b64(att)}, "clientExtensionResults": map[string]any{"credProps": map[string]bool{"rk": false}, "ignored": map[string]string{"never": "retained"}}})
	if e != nil {
		t.Fatal(e)
	}
	return wire
}
func assertionResponse(t *testing.T, key *ecdsa.PrivateKey, id, handle []byte, challenge string, flags byte, count uint32) []byte {
	t.Helper()
	client := clientJSON("get", challenge)
	auth := authData(flags, count)
	h := sha256.Sum256(client)
	signed := append(bytes.Clone(auth), h[:]...)
	digest := sha256.Sum256(signed)
	sig, e := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if e != nil {
		t.Fatal(e)
	}
	wire, e := json.Marshal(map[string]any{"id": b64(id), "rawId": b64(id), "type": "public-key", "response": map[string]string{"clientDataJSON": b64(client), "authenticatorData": b64(auth), "signature": b64(sig), "userHandle": b64(handle)}})
	if e != nil {
		t.Fatal(e)
	}
	return wire
}
