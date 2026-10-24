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
	"math"
	"net"
	"os"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	webauthn "github.com/faustbrian/go-webauthn"
	webauthnpg "github.com/faustbrian/go-webauthn/postgres"
)

func removalAssertionOperation(finish bool) identity.FeatureOperation {
	schema := "identity.passkey.delete.options-v1"
	if finish {
		schema = "identity.passkey.delete.assertion-v1"
	}
	return identity.FeatureOperation{Owner: "passkey", OperationID: "identity.passkey.delete", SchemaID: schema, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// This is protocol composition proof, not native session, last-key/recovery,
// mapping, credential-reference or policy admission proof.
func TestRemovalAssertionParticipationPostgres(t *testing.T) {
	ctx, pool, config, native := nativeFixture(t)
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE assertion_participation_metadata(command_id text PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	digest, _ := webauthn.NewChallengeDigestKey(bytes.Repeat([]byte{101}, 32))
	serviceConfig := webauthn.Config{TenantID: "tenant-a", RelyingParty: webauthn.RelyingParty{ID: "example.com", Name: "Removal Participant", Origins: []string{"https://login.example.com"}, Version: 1}, ChallengeKey: digest, MaximumDuration: 10 * time.Second}
	registration, err := webauthn.New(serviceConfig, webauthn.Dependencies{Store: native})
	if err != nil {
		t.Fatal(err)
	}
	fresh := func() webauthn.CeremonyContext {
		id, _ := identity.NewCommandID()
		return webauthn.CeremonyContext{CommandID: id, TenantID: "tenant-a", UserID: "user-a", ActorID: "user-a", CorrelationID: "removal-assertion-test"}
	}
	handle := bytes.Repeat([]byte{102}, 32)
	register := func(t *testing.T) (webauthn.Credential, *ecdsa.PrivateKey) {
		t.Helper()
		private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		id := make([]byte, 32)
		if _, err := rand.Read(id); err != nil {
			t.Fatal(err)
		}
		opts, err := registration.BeginRegistration(ctx, webauthn.BeginRegistrationRequest{Context: fresh(), UserHandle: handle, Origin: "https://login.example.com", ResidentKeyRequired: true})
		if err != nil {
			t.Fatal(err)
		}
		ceremony, _ := opts.Ceremony()
		challenge := optionChallenge(t, ctx, opts.TransferJSON)
		verified, err := registration.VerifyRegistration(ctx, webauthn.VerifyRegistrationRequest{Context: fresh(), CeremonyID: ceremony.ID, Origin: "https://login.example.com", ExpectedVersion: 1, Response: registrationResponse(t, private, id, challenge, 0x45, 0)})
		if err != nil {
			t.Fatal(err)
		}
		credential, ok := verified.Credential()
		if !ok {
			t.Fatal("registration has no credential")
		}
		return credential, private
	}
	load := func(t *testing.T, id []byte) webauthn.Credential {
		t.Helper()
		var wire []byte
		if err := pool.Raw().QueryRow(ctx, `SELECT record FROM webauthn.credentials WHERE rp_id='example.com' AND credential_id=$1`, id).Scan(&wire); err != nil {
			t.Fatal(err)
		}
		var c webauthn.Credential
		if err := json.Unmarshal(wire, &c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	setup := func(t *testing.T, same bool, offset time.Duration) (*assertionStore, webauthn.Service, webauthn.VerifyAssertionRequest, webauthn.Credential, webauthn.Credential) {
		t.Helper()
		source, key := register(t)
		target := source
		if !same {
			target, _ = register(t)
		}
		store := &assertionStore{Store: native, pool: pool, config: config, removal: true, generationOffset: offset, removalTarget: webauthnpg.RemovalRequest{RPID: target.RPID, CredentialID: target.ID, Version: target.Version}}
		svc, err := webauthn.New(serviceConfig, webauthn.Dependencies{Store: store})
		if err != nil {
			t.Fatal(err)
		}
		opts, err := svc.BeginAssertion(ctx, webauthn.BeginAssertionRequest{Context: fresh(), UserHandle: handle, Origin: "https://login.example.com", AllowedCredentials: [][]byte{source.ID}})
		if err != nil {
			t.Fatal(err)
		}
		ceremony, _ := opts.Ceremony()
		challenge := optionChallenge(t, ctx, opts.TransferJSON)
		request := webauthn.VerifyAssertionRequest{Context: fresh(), CeremonyID: ceremony.ID, Origin: "https://login.example.com", ExpectedVersion: 1, ExpectedCredentialVersion: source.Version, Response: assertionResponse(t, key, source.ID, handle, challenge, 0x05, 1)}
		return store, svc, request, source, target
	}
	counts := func(t *testing.T, command identity.CommandID) [4]int {
		t.Helper()
		var c [4]int
		if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM webauthn.effects WHERE command_id=$1),(SELECT count(*) FROM assertion_participation_metadata WHERE command_id=$1),(SELECT count(*) FROM audit.records WHERE outcome=$2),(SELECT count(*) FROM public.outbox_messages)`, string(command), int(audit.OutcomeSucceeded)).Scan(&c[0], &c[1], &c[2], &c[3]); err != nil {
			t.Fatal(err)
		}
		return c
	}
	for _, same := range []bool{true, false} {
		name := "distinct-target"
		if same {
			name = "same-target"
		}
		t.Run(name, func(t *testing.T) {
			store, svc, request, source, target := setup(t, same, 0)
			store.observeRemoval = func(p *webauthnpg.RemovalAssertionFinalization, r identity.CommandResult) {
				alias := *p
				if _, err := alias.Result(r); err == nil {
					t.Fatal("copy reissued verification")
				}
			}
			v, err := svc.VerifyAssertion(ctx, request)
			if err != nil {
				t.Fatal("genuine compound assertion/removal", err)
			}
			verified, ok := v.Credential()
			if !ok || verified.Version != source.Version+1 || verified.Counter != 1 || len(verified.PublicKey) == 0 {
				t.Fatal("root must receive exact verifier After, not terminal credential")
			}
			terminal := load(t, target.ID)
			version := target.Version + 1
			if same {
				version++
			}
			if terminal.Version != version || len(terminal.PublicKey) != 0 || !bytes.Equal(terminal.UserHandle, handle) {
				t.Fatal("missing exact reserved terminal successor")
			}
			if !same && load(t, source.ID).Version != source.Version+1 {
				t.Fatal("distinct source did not retain verified live successor")
			}
			var consumed, snapshots bool
			if err := pool.Raw().QueryRow(ctx, `SELECT c.consumed_by=$1,e.before_credential IS NOT NULL AND e.after_credential IS NOT NULL AND e.removal_before_credential IS NOT NULL AND e.removal_after_credential IS NOT NULL FROM webauthn.ceremonies c JOIN webauthn.effects e ON e.command_id=$1 WHERE c.ceremony_id=$2`, string(request.Context.CommandID), request.CeremonyID).Scan(&consumed, &snapshots); err != nil || !consumed || !snapshots {
				t.Fatal("one original effect did not retain both transitions", err)
			}
			if got := counts(t, request.Context.CommandID); got[0] != 1 || got[1] != 1 {
				t.Fatal("parent and protocol effects did not commit once", got)
			}
			if _, err := native.LoadCredential(ctx, webauthn.Lookup{Context: request.Context, RPID: target.RPID, CeremonyID: request.CeremonyID}, target.ID); err == nil {
				t.Fatal("removed key resurrected from historical effect")
			}
			if again, err := svc.VerifyAssertion(ctx, request); err == nil {
				t.Fatal("replay reauthenticated")
			} else if _, ok := again.Credential(); ok {
				t.Fatal("replay released verification")
			}
			if out, err := svc.Recover(ctx, webauthn.RecoveryRequest{Context: request.Context, Operation: webauthn.AssertionOperation, CredentialID: source.ID}); err != nil || out != identity.CommitOutcomeCommitted {
				t.Fatal("original committed command not recoverable", err)
			}
		})
	}
	for _, mode := range []string{"sibling", "verified-source", "historical-expiry", "target", "missing", "erased", "overflow", "counter-overflow", "nonresident", "unretained", "foreign-rp", "withdraw-key", "withdraw-provenance"} {
		t.Run("remaining-credential-"+mode, func(t *testing.T) {
			store, svc, request, source, target := setup(t, mode != "verified-source", 0)
			remaining, _ := register(t)
			if mode == "verified-source" {
				remaining = source
			}
			store.remainingID = remaining.ID
			switch mode {
			case "target":
				store.remainingID = target.ID
			case "missing":
				store.remainingID = []byte("absent-credential")
			case "erased":
				if _, err := pool.Raw().Exec(ctx, `UPDATE webauthn.credentials SET record=jsonb_set(record,'{PublicKey}','null'::jsonb) WHERE rp_id='example.com' AND credential_id=$1`, remaining.ID); err != nil {
					t.Fatal(err)
				}
			case "overflow":
				remaining.Version = math.MaxUint64
				wire, _ := json.Marshal(remaining)
				if _, err := pool.Raw().Exec(ctx, `UPDATE webauthn.credentials SET version=18446744073709551615,record=$1::jsonb WHERE rp_id='example.com' AND credential_id=$2`, string(wire), remaining.ID); err != nil {
					t.Fatal(err)
				}
			case "counter-overflow":
				if _, err := pool.Raw().Exec(ctx, `UPDATE webauthn.credentials SET record=jsonb_set(record,'{Counter}','4294967295'::jsonb) WHERE rp_id='example.com' AND credential_id=$1`, remaining.ID); err != nil {
					t.Fatal(err)
				}
			case "historical-expiry":
				var ceremonyWire []byte
				if err := pool.Raw().QueryRow(ctx, `SELECT ceremony FROM webauthn.effects WHERE purpose='webauthn.register' AND after_credential->>'ID'=$1`, base64.StdEncoding.EncodeToString(remaining.ID)).Scan(&ceremonyWire); err != nil {
					t.Fatal(err)
				}
				var ceremony webauthn.CeremonyRecord
				if err := json.Unmarshal(ceremonyWire, &ceremony); err != nil {
					t.Fatal(err)
				}
				// Equivalent retained history after time passes: current credential
				// lifetime is not the completed registration ceremony's TTL.
				ceremony.ExpiresAt = time.Now().UTC().Add(-time.Hour)
				ceremonyWire, _ = json.Marshal(ceremony)
				if _, err := pool.Raw().Exec(ctx, `UPDATE webauthn.ceremonies SET expires_at=$1,record=$2::jsonb WHERE ceremony_id=$3`, ceremony.ExpiresAt, string(ceremonyWire), ceremony.ID); err != nil {
					t.Fatal(err)
				}
				if _, err := pool.Raw().Exec(ctx, `UPDATE webauthn.effects SET ceremony=$1::jsonb WHERE ceremony_id=$2`, string(ceremonyWire), ceremony.ID); err != nil {
					t.Fatal(err)
				}
			case "nonresident":
				wire, _ := json.Marshal(remaining)
				if _, err := pool.Raw().Exec(ctx, `UPDATE webauthn.effects SET ceremony=jsonb_set(ceremony,'{Intent,ResidentKeyRequired}','false'::jsonb) WHERE purpose='webauthn.register' AND after_credential=$1::jsonb`, string(wire)); err != nil {
					t.Fatal(err)
				}
			case "unretained":
				wire, _ := json.Marshal(remaining)
				if _, err := pool.Raw().Exec(ctx, `DELETE FROM webauthn.effects WHERE purpose='webauthn.register' AND after_credential=$1::jsonb`, string(wire)); err != nil {
					t.Fatal(err)
				}
			case "foreign-rp":
				if _, err := pool.Raw().Exec(ctx, `UPDATE webauthn.effects SET ceremony=jsonb_set(ceremony,'{Intent,RPID}','"other.example.com"'::jsonb) WHERE purpose='webauthn.register' AND after_credential->>'ID'=$1`, base64.StdEncoding.EncodeToString(remaining.ID)); err != nil {
					t.Fatal(err)
				}
			case "withdraw-key":
				store.afterApply = func(ctx context.Context, w kernel.Work, _ identity.Command) error {
					_, err := w.Exec(ctx, `UPDATE webauthn.credentials SET record=jsonb_set(record,'{PublicKey}','null'::jsonb) WHERE rp_id='example.com' AND credential_id=$1`, remaining.ID)
					return err
				}
			case "withdraw-provenance":
				store.afterApply = func(ctx context.Context, w kernel.Work, _ identity.Command) error {
					_, err := w.Exec(ctx, `DELETE FROM webauthn.effects WHERE purpose='webauthn.register' AND after_credential->>'ID'=$1`, base64.StdEncoding.EncodeToString(remaining.ID))
					return err
				}
			}
			before := counts(t, request.Context.CommandID)
			v, err := svc.VerifyAssertion(ctx, request)
			if mode == "sibling" || mode == "verified-source" || mode == "historical-expiry" {
				if _, ok := v.Credential(); err != nil || !ok {
					t.Fatal("genuine live resident remaining key denied", err)
				}
			} else {
				if err == nil {
					t.Fatal("unusable remaining credential admitted")
				}
				if _, ok := v.Credential(); ok {
					t.Fatal("remaining-key denial exposed verification")
				}
				if got := load(t, target.ID); got.Version != target.Version || len(got.PublicKey) == 0 || counts(t, request.Context.CommandID) != before {
					t.Fatal("remaining-key denial retained removal")
				}
			}
		})
	}
	t.Run("genuine-transition-original-target-custody", func(t *testing.T) {
		store, svc, request, _, _ := setup(t, true, 0)
		store.observeTransition = func(transition webauthn.AssertionTransition) {
			m, err := transition.Mutation()
			if err != nil {
				t.Fatal(err)
			}
			for _, mismatch := range []string{"command", "tenant", "user", "actor", "correlation", "rp", "version", "overflow", "id"} {
				r := store.removalTarget
				r.Context = m.Context
				switch mismatch {
				case "command":
					r.Context.CommandID, _ = identity.NewCommandID()
				case "tenant":
					r.Context.TenantID = "other-tenant"
				case "user":
					r.Context.UserID, r.Context.ActorID = "other-user", "other-user"
				case "actor":
					r.Context.ActorID = "other-user"
				case "correlation":
					r.Context.CorrelationID = "other-correlation"
				case "rp":
					r.RPID = "other.example.com"
				case "version":
					r.Version++
				case "overflow":
					r.Version = math.MaxUint64
				case "id":
					r.CredentialID = nil
				}
				if p, err := native.RemovalAssertionFinalization(transition, r); err == nil || p != nil {
					t.Fatal("foreign original target accepted", mismatch)
				}
			}
			wire, _ := json.Marshal(m)
			var fabricated webauthn.AssertionTransition
			if err := json.Unmarshal(wire, &fabricated); err != nil {
				t.Fatal(err)
			}
			r := store.removalTarget
			r.Context = m.Context
			if p, err := native.RemovalAssertionFinalization(fabricated, r); err == nil || p != nil {
				t.Fatal("projection fabricated verifier custody")
			}
		}
		if _, err := svc.VerifyAssertion(ctx, request); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("same-target-successor-overflow", func(t *testing.T) {
		store, svc, request, source, _ := setup(t, true, 0)
		source.Version = math.MaxUint64 - 1
		wire, _ := json.Marshal(source)
		if _, err := pool.Raw().Exec(ctx, `UPDATE webauthn.credentials SET version=18446744073709551614,record=$1::jsonb WHERE rp_id='example.com' AND credential_id=$2`, string(wire), source.ID); err != nil {
			t.Fatal(err)
		}
		store.removalTarget.Version, request.ExpectedCredentialVersion = source.Version, source.Version
		before := counts(t, request.Context.CommandID)
		if v, err := svc.VerifyAssertion(ctx, request); err == nil {
			t.Fatal("same-target terminal successor overflow accepted")
		} else if _, ok := v.Credential(); ok {
			t.Fatal("overflow returned verification")
		}
		if got := load(t, source.ID); got.Version != source.Version || len(got.PublicKey) == 0 || counts(t, request.Context.CommandID) != before {
			t.Fatal("overflow retained mutation")
		}
	})
	for _, failure := range []string{"foreign", "apply", "commit", "withdraw", "scope", "tenant", "user", "actor", "kind", "intent", "profile", "source-profile", "effect-collision", "lifecycle-zero", "lifecycle-event", "lifecycle-jump", "lifecycle-index", "stale-target", "terminal-tamper", "source-tamper", "effect-tamper", "cancel", "expiry"} {
		t.Run("rollback-"+failure, func(t *testing.T) {
			offset := time.Duration(0)
			if failure == "expiry" {
				offset = -5*time.Minute + 500*time.Millisecond
			}
			store, svc, request, source, target := setup(t, failure != "source-tamper" && failure != "stale-target", offset)
			before := counts(t, request.Context.CommandID)
			callCtx := ctx
			store.foreign, store.failApply, store.failCommit, store.withdraw = failure == "foreign", failure == "apply", failure == "commit", failure == "withdraw"
			switch failure {
			case "source-profile":
				if _, err := pool.Raw().Exec(ctx, `UPDATE webauthn.effects SET purpose='identity.passkey.update' WHERE command_id=$1`, request.CeremonyID); err != nil {
					t.Fatal(err)
				}
			case "effect-collision":
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO webauthn.effects(command_id,tenant_id,user_id,actor_id,purpose,record_id,fingerprint,ceremony_id,ceremony) SELECT $1,tenant_id,user_id,actor_id,purpose,record_id,fingerprint,ceremony_id,ceremony FROM webauthn.effects WHERE command_id=$2`, string(request.Context.CommandID), request.CeremonyID); err != nil {
					t.Fatal(err)
				}
				before = counts(t, request.Context.CommandID)
			case "scope", "tenant", "user", "actor", "kind", "intent", "profile", "lifecycle-zero", "lifecycle-event", "lifecycle-jump", "lifecycle-index":
				store.invalidParent = failure
			case "stale-target":
				store.removalTarget.Version++
			case "terminal-tamper", "source-tamper":
				id := target.ID
				if failure == "source-tamper" {
					id = source.ID
				}
				store.afterApply = func(ctx context.Context, w kernel.Work, _ identity.Command) error {
					_, err := w.Exec(ctx, `UPDATE webauthn.credentials SET version=version+1 WHERE rp_id='example.com' AND credential_id=$1`, id)
					return err
				}
			case "effect-tamper":
				store.afterApply = func(ctx context.Context, w kernel.Work, _ identity.Command) error {
					_, err := w.Exec(ctx, `UPDATE webauthn.effects SET fingerprint=$1 WHERE command_id=$2`, bytes.Repeat([]byte{22}, 32), string(request.Context.CommandID))
					return err
				}
			case "expiry":
				store.afterApply = func(ctx context.Context, w kernel.Work, _ identity.Command) error {
					rows, err := w.Query(ctx, `SELECT pg_sleep(0.6)`)
					if err == nil {
						for rows.Next() {
						}
						rows.Close()
					}
					return err
				}
			case "cancel":
				var cancel context.CancelFunc
				callCtx, cancel = context.WithCancel(ctx)
				store.afterApply = func(context.Context, kernel.Work, identity.Command) error { cancel(); return nil }
				defer cancel()
			}
			v, err := svc.VerifyAssertion(callCtx, request)
			if err == nil {
				t.Fatal("failed parent released assertion")
			}
			if _, ok := v.Credential(); ok {
				t.Fatal("uncommitted verification escaped")
			}
			if got := load(t, target.ID); got.Version != target.Version || len(got.PublicKey) == 0 {
				t.Fatal("failed parent retained terminal target")
			}
			if got := load(t, source.ID); got.Version != source.Version || got.Counter != source.Counter {
				t.Fatal("failed parent retained assertion successor")
			}
			if got := counts(t, request.Context.CommandID); got != before {
				t.Fatal("failed parent retained effects", got)
			}
			var consumed bool
			if err := pool.Raw().QueryRow(ctx, `SELECT consumed_by IS NOT NULL FROM webauthn.ceremonies WHERE ceremony_id=$1`, request.CeremonyID).Scan(&consumed); err != nil || consumed {
				t.Fatal("failed parent consumed original ceremony", err)
			}
		})
	}
	t.Run("concurrent-single-consumption", func(t *testing.T) {
		store, svc, request, source, target := setup(t, true, 0)
		ready, proceed := make(chan struct{}, 2), make(chan struct{})
		store.observeTransition = func(webauthn.AssertionTransition) { ready <- struct{}{}; <-proceed }
		results := make(chan bool, 2)
		for range 2 {
			r := request
			r.Context = fresh()
			go func() { v, err := svc.VerifyAssertion(ctx, r); _, ok := v.Credential(); results <- err == nil && ok }()
		}
		for range 2 {
			select {
			case <-ready:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}
		close(proceed)
		wins := 0
		for range 2 {
			if <-results {
				wins++
			}
		}
		if wins != 1 || load(t, target.ID).Version != source.Version+2 {
			t.Fatal("compound single-consumption winners", wins)
		}
	})
	t.Run("lost-final-commit-recovery", func(t *testing.T) {
		recoveryStore, svc, request, source, target := setup(t, true, 0)
		cut := &commitCut{}
		cutPool, err := database.New(ctx, database.Config{DSN: os.Getenv("WEBAUTHN_TEST_DSN"), MaxConns: 2, Configure: func(c *database.PoolConfig) error {
			dial := c.ConnConfig.DialFunc
			c.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
				conn, err := dial(ctx, network, address)
				if err != nil {
					return nil, err
				}
				return &commitCutConn{Conn: conn, cut: cut}, nil
			}
			return nil
		}})
		if err != nil {
			t.Fatal(err)
		}
		defer cutPool.Close(context.Background())
		cutNative, err := webauthnpg.New(cutPool, webauthnpg.Config{Coordinator: config, PolicyID: "removal-assertion-test", PolicyVersion: 1})
		if err != nil {
			t.Fatal(err)
		}
		cutStore := &assertionStore{Store: cutNative, pool: cutPool, config: config, removal: true, removalTarget: webauthnpg.RemovalRequest{RPID: target.RPID, CredentialID: target.ID, Version: target.Version}}
		cutSvc, err := webauthn.New(serviceConfig, webauthn.Dependencies{Store: cutStore})
		if err != nil {
			t.Fatal(err)
		}
		cut.remaining.Store(2)
		v, err := cutSvc.VerifyAssertion(ctx, request)
		var unknown webauthn.UnknownCommit
		if !errors.As(err, &unknown) || !cut.cut.Load() {
			t.Fatal("lost final COMMIT not unknown", err)
		}
		if _, ok := v.Credential(); ok {
			t.Fatal("unknown commit released verification")
		}
		if got := load(t, target.ID); got.Version != source.Version+2 || len(got.PublicKey) != 0 {
			t.Fatal("server did not commit compound removal")
		}
		if out, err := svc.Recover(ctx, webauthn.RecoveryRequest{Context: request.Context, Operation: webauthn.AssertionOperation, CredentialID: source.ID}); err != nil || out != identity.CommitOutcomeCommitted {
			t.Fatal("lost final commit did not reconcile", err)
		}
		if again, err := svc.VerifyAssertion(ctx, request); err == nil {
			t.Fatal("recovered removal reauthenticated")
		} else if _, ok := again.Credential(); ok {
			t.Fatal("recovered verification escaped")
		}
		for _, marker := range []bool{false, true} {
			_, _, pending, before, target := setup(t, true, 0)
			cutStore.removalTarget = webauthnpg.RemovalRequest{RPID: target.RPID, CredentialID: target.ID, Version: target.Version}
			cut.cut.Store(false)
			cut.remaining.Store(1) // Reservation commits; domain Work never opens.
			if v, err := cutSvc.VerifyAssertion(ctx, pending); !errors.As(err, &unknown) {
				t.Fatal("lost reservation not unknown", err)
			} else if _, ok := v.Credential(); ok {
				t.Fatal("pending command released verification")
			}
			commandID, err := base64.RawURLEncoding.DecodeString(string(pending.Context.CommandID))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET created_at=clock_timestamp()-interval '3 seconds',heartbeat_at=clock_timestamp()-interval '2 seconds',updated_at=clock_timestamp()-interval '2 seconds',lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1 AND state='pending'`, commandID); err != nil {
				t.Fatal(err)
			}
			if marker {
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO webauthn.effects(command_id,tenant_id,user_id,actor_id,purpose,record_id,fingerprint,ceremony_id,ceremony,before_credential,after_credential,removal_before_credential,removal_after_credential) SELECT $1,tenant_id,user_id,actor_id,purpose,record_id,fingerprint,ceremony_id,ceremony,before_credential,after_credential,removal_before_credential,removal_after_credential FROM webauthn.effects WHERE command_id=$2`, string(pending.Context.CommandID), string(request.Context.CommandID)); err != nil {
					t.Fatal(err)
				}
			}
			out, err := svc.Recover(ctx, webauthn.RecoveryRequest{Context: pending.Context, Operation: webauthn.AssertionOperation, CredentialID: before.ID})
			var unavailable identity.UnavailableError
			if marker {
				if out == identity.CommitOutcomeCommitted || recoveryStore.recoveredProtocol != kernel.RecoveryUnknown || !errors.As(err, &unavailable) {
					t.Fatal("pending journal with protocol effect reconstructed success", out, err)
				}
			} else {
				if out != identity.CommitOutcomeNotCommitted || recoveryStore.recoveredProtocol != kernel.RecoveryNotCommitted || !errors.As(err, &unavailable) {
					t.Fatal("pending command without effect did not prove noncommit", out, err)
				}
			}
			if got := load(t, target.ID); got.Version != before.Version || len(got.PublicKey) == 0 {
				t.Fatal("recovery replayed protocol mutation")
			}
		}
	})
}
