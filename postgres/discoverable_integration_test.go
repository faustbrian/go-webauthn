//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	webauthn "github.com/faustbrian/go-webauthn"
)

type pausedDiscoverableStore struct {
	webauthn.DiscoverableStore
	ready  chan<- struct{}
	resume <-chan struct{}
}

func (s pausedDiscoverableStore) FinalizeAssertion(ctx context.Context, t webauthn.AssertionTransition) (webauthn.Credential, identity.CommitOutcome, error) {
	s.ready <- struct{}{}
	select {
	case <-ctx.Done():
		return webauthn.Credential{}, identity.CommitOutcomeNotCommitted, webauthn.Unavailable{}
	case <-s.resume:
		return s.DiscoverableStore.FinalizeAssertion(ctx, t)
	}
}

func TestDiscoverableAssertionPostgres(t *testing.T) {
	ctx, pool, _, store := nativeFixture(t)
	key, _ := webauthn.NewChallengeDigestKey(bytes.Repeat([]byte{25}, 32))
	config := webauthn.Config{TenantID: "tenant-a", RelyingParty: webauthn.RelyingParty{ID: "example.com", Name: "Example", Origins: []string{"https://login.example.com"}, Version: 1}, ChallengeKey: key, MaximumDuration: 10 * time.Second}
	svc, err := webauthn.NewDiscoverable(config, webauthn.Dependencies{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	fresh := func(anonymous bool) webauthn.CeremonyContext {
		id, e := identity.NewCommandID()
		if e != nil {
			t.Fatal(e)
		}
		c := webauthn.CeremonyContext{CommandID: id, TenantID: "tenant-a", UserID: "user-a", ActorID: "actor-a", CorrelationID: "discoverable-test"}
		if anonymous {
			c.UserID = ""
			c.AnonymousFlowID = "pre-auth-flow"
		}
		return c
	}
	handle, credentialID := bytes.Repeat([]byte{26}, 32), bytes.Repeat([]byte{27}, 32)
	private, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registration, err := svc.BeginRegistration(ctx, webauthn.BeginRegistrationRequest{Context: fresh(false), UserHandle: handle, Origin: config.RelyingParty.Origins[0], ResidentKeyRequired: true})
	if err != nil {
		t.Fatal(err)
	}
	r, _ := registration.Ceremony()
	challenge := optionChallenge(t, ctx, registration.TransferJSON)
	if _, err = svc.VerifyRegistration(ctx, webauthn.VerifyRegistrationRequest{Context: fresh(false), CeremonyID: r.ID, Origin: r.Intent.Origin, Response: registrationResponse(t, private, credentialID, challenge, 0x4d, 3), ExpectedVersion: 1}); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"foreign-tenant", "foreign-rp"} {
		q := webauthn.Lookup{Context: fresh(true), RPID: "example.com", CeremonyID: r.ID}
		if scope == "foreign-tenant" {
			q.Context.TenantID = "tenant-b"
		} else {
			q.RPID = "other.example.com"
		}
		if _, e := store.LoadDiscoverableCredential(ctx, q, credentialID, handle); e == nil {
			t.Fatal("RP-wide lookup crossed scope", scope)
		}
	}
	for _, scenario := range []string{"missing-handle", "wrong-handle", "oversized-handle", "unknown-credential", "wrong-tenant", "wrong-flow", "wrong-actor", "withdrawn", "signature", "rollback", "mapping-withdrawal", "success"} {
		t.Run(scenario, func(t *testing.T) {
			options, e := svc.BeginDiscoverableAssertion(ctx, webauthn.BeginDiscoverableAssertionRequest{Context: fresh(true), Origin: r.Intent.Origin})
			if e != nil {
				t.Fatal(e)
			}
			ceremony, _ := options.Ceremony()
			challenge := optionChallenge(t, ctx, options.TransferJSON)
			wire := assertionResponse(t, private, credentialID, handle, challenge, 0x1d, 2)
			var body map[string]any
			_ = json.Unmarshal(wire, &body)
			response := body["response"].(map[string]any)
			request := webauthn.VerifyDiscoverableAssertionRequest{Context: fresh(true), CeremonyID: ceremony.ID, Origin: r.Intent.Origin, Response: wire, ExpectedVersion: 1}
			var beforeEffects, beforeAudits, beforeOutbox int
			if e = pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM webauthn.effects),(SELECT count(*) FROM audit.records WHERE outcome=$1),(SELECT count(*) FROM public.outbox_messages)`, int(audit.OutcomeSucceeded)).Scan(&beforeEffects, &beforeAudits, &beforeOutbox); e != nil {
				t.Fatal(e)
			}
			switch scenario {
			case "missing-handle":
				delete(response, "userHandle")
			case "wrong-handle":
				response["userHandle"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			case "oversized-handle":
				response["userHandle"] = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{28}, 65))
			case "unknown-credential":
				body["id"] = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{29}, 32))
				body["rawId"] = body["id"]
			case "wrong-tenant":
				request.Context.TenantID = "tenant-b"
			case "wrong-flow":
				request.Context.AnonymousFlowID = "other-flow"
			case "wrong-actor":
				request.Context.ActorID = "foreign-actor"
			case "withdrawn":
				if _, e = pool.Raw().Exec(ctx, `UPDATE identity.users SET status='suspended' WHERE tenant_id='tenant-a' AND user_id='user-a'`); e != nil {
					t.Fatal(e)
				}
			case "signature":
				response["signature"] = "AA"
			case "rollback":
				if _, e = pool.Raw().Exec(ctx, `CREATE FUNCTION public.discoverable_commit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'discoverable rollback fixture'; END $$; CREATE CONSTRAINT TRIGGER discoverable_commit_failure AFTER INSERT ON webauthn.effects DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.discoverable_commit_failure();`); e != nil {
					t.Fatal(e)
				}
			case "mapping-withdrawal":
				// Change authority after the credential CAS but before the final
				// commit fence, rather than testing only a stale pre-load mapping.
				if _, e = pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('tenant-a','user-b','active',1); CREATE FUNCTION public.discoverable_mapping_change() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN UPDATE webauthn.user_handles SET user_id='user-b' WHERE rp_id=NEW.rp_id AND user_handle=NEW.user_handle; RETURN NEW; END $$; CREATE TRIGGER discoverable_mapping_change AFTER UPDATE ON webauthn.credentials FOR EACH ROW EXECUTE FUNCTION public.discoverable_mapping_change();`); e != nil {
					t.Fatal(e)
				}
			}
			request.Response, _ = json.Marshal(body)
			verified, e := svc.VerifyDiscoverableAssertion(ctx, request)
			if scenario != "success" {
				if e == nil {
					t.Fatal("invalid assertion authenticated")
				}
				if _, ok := verified.Credential(); ok {
					t.Fatal("denial returned credential authority")
				}
				var consumed bool
				var version string
				if e = pool.Raw().QueryRow(ctx, `SELECT consumed_by IS NOT NULL FROM webauthn.ceremonies WHERE ceremony_id=$1`, ceremony.ID).Scan(&consumed); e != nil || consumed {
					t.Fatal("denial consumed ceremony", e)
				}
				if e = pool.Raw().QueryRow(ctx, `SELECT version::text FROM webauthn.credentials WHERE rp_id='example.com' AND credential_id=$1`, credentialID).Scan(&version); e != nil || version != "1" {
					t.Fatal("denial updated credential", e)
				}
				var effects, audits, outbox int
				if e = pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM webauthn.effects),(SELECT count(*) FROM audit.records WHERE outcome=$1),(SELECT count(*) FROM public.outbox_messages)`, int(audit.OutcomeSucceeded)).Scan(&effects, &audits, &outbox); e != nil || effects != beforeEffects || audits != beforeAudits || outbox != beforeOutbox {
					t.Fatal("denial/rollback retained success effects", e)
				}
				if scenario == "rollback" {
					if _, e = pool.Raw().Exec(ctx, `DROP TRIGGER discoverable_commit_failure ON webauthn.effects; DROP FUNCTION public.discoverable_commit_failure()`); e != nil {
						t.Fatal(e)
					}
				}
				if scenario == "mapping-withdrawal" {
					if _, e = pool.Raw().Exec(ctx, `DROP TRIGGER discoverable_mapping_change ON webauthn.credentials; DROP FUNCTION public.discoverable_mapping_change(); DELETE FROM identity.users WHERE tenant_id='tenant-a' AND user_id='user-b'`); e != nil {
						t.Fatal(e)
					}
					var owner string
					if e = pool.Raw().QueryRow(ctx, `SELECT user_id FROM webauthn.user_handles WHERE rp_id='example.com' AND user_handle=$1`, handle).Scan(&owner); e != nil || owner != "user-a" {
						t.Fatal("mapping withdrawal did not roll back", e)
					}
				}
				if scenario == "withdrawn" {
					if _, e = pool.Raw().Exec(ctx, `UPDATE identity.users SET status='active' WHERE tenant_id='tenant-a' AND user_id='user-a'`); e != nil {
						t.Fatal(e)
					}
				}
				return
			}
			if e != nil {
				t.Fatal("usernameless signature denied", e)
			}
			credential, ok := verified.Credential()
			if !ok || credential.UserID != "user-a" || credential.Counter != 3 || !credential.BackupState || credential.Version != 2 || !verified.CounterRisk() {
				t.Fatal("resolved credential/counter/backup transition missing")
			}
			var replay webauthn.Replay
			if again, e := svc.VerifyDiscoverableAssertion(ctx, request); !errors.As(e, &replay) {
				t.Fatal("original completion not replay", e)
			} else if _, ok := again.Credential(); ok {
				t.Fatal("replay authenticated")
			}
			if outcome, e := svc.Recover(ctx, webauthn.RecoveryRequest{Context: request.Context, Operation: webauthn.DiscoverableAssertionOperation, CredentialID: credentialID}); e != nil || outcome != identity.CommitOutcomeCommitted {
				t.Fatal("original anonymous recovery", e)
			}
			if _, e = pool.Raw().Exec(ctx, `UPDATE identity.users SET status='suspended' WHERE tenant_id='tenant-a' AND user_id='user-a'`); e != nil {
				t.Fatal(e)
			}
			if historical, e := svc.VerifyDiscoverableAssertion(ctx, request); !errors.As(e, &replay) {
				t.Fatal("committed retry after suspension lost historical replay", e)
			} else if _, ok := historical.Credential(); ok {
				t.Fatal("historical retry after suspension authenticated")
			}
			if _, e = pool.Raw().Exec(ctx, `UPDATE identity.users SET status='active' WHERE tenant_id='tenant-a' AND user_id='user-a'`); e != nil {
				t.Fatal(e)
			}
			request.Context = fresh(true)
			if _, e := svc.VerifyDiscoverableAssertion(ctx, request); e == nil {
				t.Fatal("consumed challenge replay accepted")
			}
		})
	}
	if t.Failed() {
		return
	}
	// Both cryptographically verified assertions observe version 2 before either
	// finalizer runs. Exactly one CAS/consumption may commit, not a silent rebase.
	t.Run("contention", func(t *testing.T) {
		ready, resume := make(chan struct{}, 2), make(chan struct{})
		concurrent, e := webauthn.NewDiscoverable(config, webauthn.Dependencies{Store: pausedDiscoverableStore{DiscoverableStore: store, ready: ready, resume: resume}})
		if e != nil {
			t.Fatal(e)
		}
		requests := make([]webauthn.VerifyDiscoverableAssertionRequest, 2)
		for i := range requests {
			o, e := svc.BeginDiscoverableAssertion(ctx, webauthn.BeginDiscoverableAssertionRequest{Context: fresh(true), Origin: r.Intent.Origin})
			if e != nil {
				t.Fatal(e)
			}
			c, _ := o.Ceremony()
			challenge := optionChallenge(t, ctx, o.TransferJSON)
			requests[i] = webauthn.VerifyDiscoverableAssertionRequest{Context: fresh(true), CeremonyID: c.ID, Origin: r.Intent.Origin, ExpectedVersion: 1, Response: assertionResponse(t, private, credentialID, handle, challenge, 0x1d, 4)}
		}
		results := make(chan error, 2)
		for _, request := range requests {
			go func() { _, e := concurrent.VerifyDiscoverableAssertion(ctx, request); results <- e }()
		}
		for range 2 {
			select {
			case <-ready:
			case <-ctx.Done():
				t.Fatal("concurrent verification deadline")
			}
		}
		close(resume)
		winners := 0
		for range 2 {
			if e := <-results; e == nil {
				winners++
			} else {
				var conflict webauthn.Conflict
				if !errors.As(e, &conflict) {
					t.Fatal("unexpected contention result", e)
				}
			}
		}
		var consumed int
		var version string
		if e = pool.Raw().QueryRow(ctx, `SELECT count(*) FROM webauthn.ceremonies WHERE ceremony_id IN($1,$2) AND consumed_by IS NOT NULL`, requests[0].CeremonyID, requests[1].CeremonyID).Scan(&consumed); e != nil || consumed != 1 || winners != 1 {
			t.Fatal("contention did not produce exactly one atomic winner", e)
		}
		if e = pool.Raw().QueryRow(ctx, `SELECT version::text FROM webauthn.credentials WHERE rp_id='example.com' AND credential_id=$1`, credentialID).Scan(&version); e != nil || version != "3" {
			t.Fatal("contention changed credential more than once", e)
		}
	})
}
