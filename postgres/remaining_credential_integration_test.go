//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	webauthn "github.com/faustbrian/go-webauthn"
	webauthnpg "github.com/faustbrian/go-webauthn/postgres"
)

// Native and signup histories are produced by the genuine public participants,
// not by relabeling standalone registration effects. Identity signup/session and
// last-key policy remain outside this protocol-only consumer fixture.
func TestRemovalRemainingNativeProvenancePostgres(t *testing.T) {
	testRemovalRemainingNativeProvenancePostgres(t, participantProfile{})
}

func testRemovalRemainingNativeProvenancePostgres(t *testing.T, selected participantProfile) {
	registrationResponse, assertionResponse := selected.registration, selected.assertion
	ctx, pool, config, native := nativeFixture(t)
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE participation_metadata(command_id text PRIMARY KEY); CREATE TABLE assertion_participation_metadata(command_id text PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	digest, _ := webauthn.NewChallengeDigestKey(bytes.Repeat([]byte{121}, 32))
	serviceConfig := webauthn.Config{TenantID: "tenant-a", RelyingParty: webauthn.RelyingParty{ID: "example.com", Name: "Remaining Native Provenance", Origins: []string{"https://login.example.com"}, Version: 1}, ChallengeKey: digest, MaximumDuration: 10 * time.Second}
	serviceConfig.Algorithms = selected.algorithms
	fresh := func(user identity.UserID, actor identity.ActorID) webauthn.CeremonyContext {
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		return webauthn.CeremonyContext{CommandID: id, TenantID: "tenant-a", UserID: user, ActorID: actor, CorrelationID: "remaining-native-provenance"}
	}
	register := func(t *testing.T, store *registrationStore, user identity.UserID, actor identity.ActorID, handle []byte) (webauthn.Credential, crypto.Signer, identity.CommandID) {
		t.Helper()
		svc, err := webauthn.New(serviceConfig, webauthn.Dependencies{Store: store})
		if err != nil {
			t.Fatal(err)
		}
		key := selected.key(t)
		id := make([]byte, 32)
		if _, err := rand.Read(id); err != nil {
			t.Fatal(err)
		}
		opts, err := svc.BeginRegistration(ctx, webauthn.BeginRegistrationRequest{Context: fresh(user, actor), UserHandle: handle, Origin: "https://login.example.com", ResidentKeyRequired: true})
		if err != nil {
			t.Fatal("genuine native registration options", err)
		}
		ceremony, _ := opts.Ceremony()
		challenge := optionChallenge(t, ctx, opts.TransferJSON)
		finish := fresh(user, actor)
		v, err := svc.VerifyRegistration(ctx, webauthn.VerifyRegistrationRequest{Context: finish, CeremonyID: ceremony.ID, Origin: "https://login.example.com", ExpectedVersion: 1, Response: registrationResponse(t, key, id, challenge, 0x45, 0)})
		if err != nil {
			t.Fatal("genuine native registration verification", err)
		}
		credential, ok := v.Credential()
		if !ok {
			t.Fatal("registration did not finalize")
		}
		return credential, key, finish.CommandID
	}
	for _, profile := range []string{"native", "signup"} {
		for _, state := range []string{"success", "final-provenance-withdrawal"} {
			t.Run(profile+"/"+state, func(t *testing.T) {
				user, actor := identity.UserID("user-a"), identity.ActorID("user-a")
				handle := bytes.Repeat([]byte{122}, 32)
				registration := &registrationStore{Store: native, pool: pool, config: config}
				flow := ""
				if profile == "signup" {
					user = identity.UserID("remaining-signup-" + state)
					actor = "signup-service"
					handle = make([]byte, 32)
					if _, err := rand.Read(handle); err != nil {
						t.Fatal(err)
					}
					flow = "remaining-original-flow-" + state
					registration.signupFlow = flow
				}
				remaining, _, original := register(t, registration, user, actor, handle)
				var nativeScope, signupScope bool
				if err := pool.Raw().QueryRow(ctx, `SELECT e.purpose='identity.passkey.register-verify' AND e.user_id=$2 AND e.actor_id=$2 AND e.anonymous_flow_id IS NULL AND r.signup_flow_id IS NULL,e.purpose='identity.passkey.register-verify' AND e.user_id IS NULL AND e.actor_id='signup-service' AND e.anonymous_flow_id=$3 AND r.signup_flow_id=$3 AND r.signup_user_id IS NULL AND r.user_id=$2 AND r.consumed_by=e.command_id FROM webauthn.effects e JOIN webauthn.ceremonies r ON r.ceremony_id=e.ceremony_id WHERE e.command_id=$1`, string(original), string(user), flow).Scan(&nativeScope, &signupScope); err != nil || profile == "native" && !nativeScope || profile == "signup" && !signupScope {
					t.Fatal("actual participant provenance namespace mismatch", nativeScope, signupScope, err)
				}
				// A real self-user native enrollment supplies the authenticating key
				// to remove; the surviving key retains its native/signup history.
				source, key, _ := register(t, &registrationStore{Store: native, pool: pool, config: config}, user, identity.ActorID(user), handle)
				store := &assertionStore{Store: native, pool: pool, config: config, removal: true, remainingID: remaining.ID, removalTarget: webauthnpg.RemovalRequest{RPID: source.RPID, CredentialID: source.ID, Version: source.Version}}
				svc, err := webauthn.New(serviceConfig, webauthn.Dependencies{Store: store})
				if err != nil {
					t.Fatal(err)
				}
				opts, err := svc.BeginAssertion(ctx, webauthn.BeginAssertionRequest{Context: fresh(user, identity.ActorID(user)), UserHandle: handle, Origin: "https://login.example.com", AllowedCredentials: [][]byte{source.ID}})
				if err != nil {
					t.Fatal(err)
				}
				ceremony, _ := opts.Ceremony()
				challenge := optionChallenge(t, ctx, opts.TransferJSON)
				request := webauthn.VerifyAssertionRequest{Context: fresh(user, identity.ActorID(user)), CeremonyID: ceremony.ID, Origin: "https://login.example.com", ExpectedVersion: 1, ExpectedCredentialVersion: source.Version, Response: assertionResponse(t, key, source.ID, handle, challenge, 0x05, 1)}
				counts := func() [4]int {
					var got [4]int
					if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM webauthn.effects WHERE command_id=$1),(SELECT count(*) FROM assertion_participation_metadata WHERE command_id=$1),(SELECT count(*) FROM audit.records WHERE outcome=$2),(SELECT count(*) FROM public.outbox_messages)`, string(request.Context.CommandID), int(audit.OutcomeSucceeded)).Scan(&got[0], &got[1], &got[2], &got[3]); err != nil {
						t.Fatal(err)
					}
					return got
				}
				before := counts()
				if state == "final-provenance-withdrawal" {
					store.afterApply = func(ctx context.Context, w kernel.Work, _ identity.Command) error {
						n, err := w.Exec(ctx, `DELETE FROM webauthn.effects WHERE command_id=$1`, string(original))
						if err == nil && n != 1 {
							t.Fatal("withdrawal did not reach locked original registration effect")
						}
						return err
					}
				}
				v, err := svc.VerifyAssertion(ctx, request)
				var sourceWire []byte
				if scanErr := pool.Raw().QueryRow(ctx, `SELECT record FROM webauthn.credentials WHERE rp_id='example.com' AND credential_id=$1`, source.ID).Scan(&sourceWire); scanErr != nil {
					t.Fatal(scanErr)
				}
				var current webauthn.Credential
				if err := json.Unmarshal(sourceWire, &current); err != nil {
					t.Fatal(err)
				}
				var retained bool
				if scanErr := pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM webauthn.effects WHERE command_id=$1 AND after_credential->>'ID'=$2)`, string(original), base64.StdEncoding.EncodeToString(remaining.ID)).Scan(&retained); scanErr != nil || !retained {
					t.Fatal("original provenance not retained/restored", scanErr)
				}
				if state == "success" {
					verified, ok := v.Credential()
					if err != nil || !ok || verified.Version != source.Version+1 || current.Version != source.Version+2 || len(current.PublicKey) != 0 || counts() != [4]int{before[0] + 1, before[1] + 1, before[2] + 1, before[3] + 1} {
						t.Fatal("genuine native/signup remaining-key removal did not commit atomically", err)
					}
				} else {
					if _, ok := v.Credential(); err == nil || ok || current.Version != source.Version || current.Counter != source.Counter || len(current.PublicKey) == 0 || counts() != before {
						t.Fatal("final provenance withdrawal failed complete rollback", err)
					}
					var consumed bool
					if scanErr := pool.Raw().QueryRow(ctx, `SELECT consumed_by IS NOT NULL FROM webauthn.ceremonies WHERE ceremony_id=$1`, request.CeremonyID).Scan(&consumed); scanErr != nil || consumed {
						t.Fatal("withdrawal consumed original removal ceremony", scanErr)
					}
				}
			})
		}
	}
}
