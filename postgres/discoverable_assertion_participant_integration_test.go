//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	webauthn "github.com/faustbrian/go-webauthn"
	webauthnpg "github.com/faustbrian/go-webauthn/postgres"
	"github.com/jackc/pgx/v5"
)

// This fixture owns only protocol participation, not passkey account admission,
// identifier matching, risk or sessions. Its target is the genuinely registered
// credential's user, obtained only from the root opaque assertion transition.
type discoverableAssertionStore struct {
	*assertionStore
	create       func(webauthn.CeremonyCreation) (*webauthnpg.AssertionCreation, error)
	finalize     func(webauthn.AssertionTransition) (*webauthnpg.AssertionFinalization, error)
	lastOriginal webauthn.CeremonyContext
	lastTarget   identity.UserID
}

func (s *discoverableAssertionStore) CreateCeremony(ctx context.Context, input webauthn.CeremonyCreation) (webauthn.CeremonyRecord, webauthn.Challenge, identity.CommitOutcome, error) {
	p, err := s.create(input)
	if err != nil {
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, identity.CommitOutcomeInvalid, err
	}
	defer p.Discard()
	i, _ := input.Intent()
	fields, _ := p.Fields()
	result, runErr := s.execute(ctx, &assertionOwner{creation: p}, i.Context, fields)
	record, challenge, err := p.Result(result)
	if runErr != nil {
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, result.Outcome, runErr
	}
	return record, challenge, result.Outcome, err
}

func (s *discoverableAssertionStore) FinalizeAssertion(ctx context.Context, input webauthn.AssertionTransition) (webauthn.Credential, identity.CommitOutcome, error) {
	if s.observeTransition != nil {
		s.observeTransition(input)
	}
	p, err := s.finalize(input)
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	m, _ := input.Mutation()
	s.lastOriginal, s.lastTarget = m.Context, m.Before.UserID
	parent := m.Context
	parent.UserID, parent.AnonymousFlowID = m.Before.UserID, ""
	fields, _ := p.Fields()
	result, runErr := s.execute(ctx, &assertionOwner{finalization: p}, parent, fields)
	credential, err := p.Result(result)
	if runErr != nil {
		return webauthn.Credential{}, result.Outcome, runErr
	}
	return credential, result.Outcome, err
}

func (s *discoverableAssertionStore) Recover(ctx context.Context, r webauthn.RecoveryRequest) (identity.CommitOutcome, error) {
	if r.Operation != webauthn.BeginDiscoverableAssertionOperation && r.Operation != webauthn.DiscoverableAssertionOperation {
		return identity.CommitOutcomeInvalid, webauthn.Invalid{Field: "test_recovery"}
	}
	finish := r.Operation == webauthn.DiscoverableAssertionOperation
	owner := &assertionOwner{store: s.Store, discoverable: true}
	coordinator, _, err := s.coordinator(owner)
	if err != nil {
		return identity.CommitOutcomeUnknown, err
	}
	op := assertionOperation(finish)
	q := identity.RecoveryQuery{CommandID: r.Context.CommandID, TenantID: r.Context.TenantID, UserID: r.Context.UserID, AnonymousFlowID: r.Context.AnonymousFlowID, ActorID: r.Context.ActorID, ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID, RecordID: string(r.Context.CommandID)}
	resourceType, subject := "identity.anonymous-flow", q.AnonymousFlowID
	if finish {
		if r.Context != s.lastOriginal || s.lastTarget == "" {
			return identity.CommitOutcomeInvalid, webauthn.Denied{}
		}
		q.UserID, q.ActorID, q.ActorKind, q.AnonymousFlowID = s.lastTarget, identity.ActorID(s.lastTarget), authorization.SubjectUser, ""
		resourceType, subject = "identity.user", string(q.UserID)
	}
	caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(q.ActorID), Kind: q.ActorKind}, Tenant: authorization.TenantID(q.TenantID), Action: authorization.Action(q.OperationID), Resource: authorization.Resource{Type: authorization.ResourceType(resourceType), ID: authorization.ResourceID(subject)}}}
	result, err := coordinator.RecoverCommand(ctx, q, caller)
	return result.Outcome, err
}

func TestDiscoverableAssertionParticipationPostgres(t *testing.T) {
	testDiscoverableAssertionParticipationPostgres(t, participantProfile{})
}

func testDiscoverableAssertionParticipationPostgres(t *testing.T, profile participantProfile) {
	registrationResponse, assertionResponse := profile.registration, profile.assertion
	ctx, pool, config, native := nativeFixture(t)
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE assertion_participation_metadata(command_id text PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	store := &discoverableAssertionStore{assertionStore: &assertionStore{Store: native, pool: pool, config: config, preauth: true, discoverable: true}, create: native.DiscoverableAssertionCreation, finalize: native.DiscoverableAssertionFinalization}
	key, _ := webauthn.NewChallengeDigestKey(bytes.Repeat([]byte{71}, 32))
	serviceConfig := webauthn.Config{TenantID: "tenant-a", RelyingParty: webauthn.RelyingParty{ID: "example.com", Name: "Discoverable Participant", Origins: []string{"https://login.example.com"}, Version: 1}, ChallengeKey: key, MaximumDuration: 10 * time.Second}
	serviceConfig.Algorithms = profile.algorithms
	svc, err := webauthn.NewDiscoverable(serviceConfig, webauthn.Dependencies{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	registration, err := webauthn.New(serviceConfig, webauthn.Dependencies{Store: native})
	if err != nil {
		t.Fatal(err)
	}
	fresh := func(anonymous bool) webauthn.CeremonyContext {
		id, _ := identity.NewCommandID()
		c := webauthn.CeremonyContext{CommandID: id, TenantID: "tenant-a", UserID: "user-a", ActorID: "ingress-service", CorrelationID: "discoverable-participation"}
		if anonymous {
			c.UserID, c.AnonymousFlowID = "", "genuine-preauth-session-flow"
		}
		return c
	}
	handle, id := bytes.Repeat([]byte{72}, 32), bytes.Repeat([]byte{73}, 32)
	private := profile.key(t)
	opts, err := registration.BeginRegistration(ctx, webauthn.BeginRegistrationRequest{Context: fresh(false), UserHandle: handle, Origin: serviceConfig.RelyingParty.Origins[0], ResidentKeyRequired: true})
	if err != nil {
		t.Fatal(err)
	}
	ceremony, _ := opts.Ceremony()
	challenge := optionChallenge(t, ctx, opts.TransferJSON)
	if _, err := registration.VerifyRegistration(ctx, webauthn.VerifyRegistrationRequest{Context: fresh(false), CeremonyID: ceremony.ID, Origin: serviceConfig.RelyingParty.Origins[0], ExpectedVersion: 1, Response: registrationResponse(t, private, id, challenge, 0x45, 0)}); err != nil {
		t.Fatal(err)
	}
	counts := func() [4]int {
		var n [4]int
		if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM webauthn.ceremonies),(SELECT count(*) FROM webauthn.effects),(SELECT count(*) FROM assertion_participation_metadata),(SELECT count(*) FROM public.outbox_messages)`).Scan(&n[0], &n[1], &n[2], &n[3]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	current := func() webauthn.Credential {
		c, err := native.LoadCredential(ctx, webauthn.Lookup{Context: fresh(false), RPID: "example.com"}, id)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	begin := func() (webauthn.AssertionOptions, error) {
		return svc.BeginDiscoverableAssertion(ctx, webauthn.BeginDiscoverableAssertionRequest{Context: fresh(true), Origin: serviceConfig.RelyingParty.Origins[0]})
	}
	request := func(t *testing.T) webauthn.VerifyDiscoverableAssertionRequest {
		t.Helper()
		options, err := begin()
		if err != nil {
			t.Fatal(err)
		}
		r, _ := options.Ceremony()
		ch := optionChallenge(t, ctx, options.TransferJSON)
		return webauthn.VerifyDiscoverableAssertionRequest{Context: fresh(true), CeremonyID: r.ID, Origin: r.Intent.Origin, ExpectedVersion: 1, Response: assertionResponse(t, private, id, handle, ch, 0x05, current().Counter+1)}
	}
	t.Run("anonymous-options", func(t *testing.T) {
		// No account status, handle or allowlist participates in options. The
		// passkey owner separately retains private admission for finalization.
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='suspended' WHERE tenant_id='tenant-a' AND user_id='user-a'`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='active' WHERE tenant_id='tenant-a' AND user_id='user-a'`); err != nil {
				t.Fatal(err)
			}
		}()
		options, err := begin()
		if err != nil {
			t.Fatal(err)
		}
		r, ok := options.Ceremony()
		if !ok || r.Intent.Context.UserID != "" || r.Intent.Context.AnonymousFlowID != "genuine-preauth-session-flow" || len(r.Intent.UserHandle) != 0 || len(r.Intent.AllowedCredentials) != 0 {
			t.Fatal("options exposed account-bound protocol intent")
		}
		if err := options.TransferJSON(ctx, func(_ context.Context, wire []byte) error {
			var body map[string]json.RawMessage
			if err := json.Unmarshal(wire, &body); err != nil {
				return err
			}
			if raw, ok := body["allowCredentials"]; ok && string(raw) != "[]" {
				t.Fatal("anonymous wire exposed credential allowlist")
			}
			if _, ok := body["user"]; ok {
				t.Fatal("anonymous assertion options exposed user")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
	for _, failure := range []string{"actor", "kind", "flow", "tenant", "intent", "apply", "commit"} {
		t.Run("creation-"+failure, func(t *testing.T) {
			before := counts()
			store.invalidParent, store.failApply, store.failCommit = failure, failure == "apply", failure == "commit"
			defer func() { store.invalidParent, store.failApply, store.failCommit = "", false, false }()
			if options, err := begin(); err == nil {
				t.Fatal("invalid anonymous parent returned options")
			} else if _, ok := options.Ceremony(); ok {
				t.Fatal("failed parent revealed ceremony")
			}
			if counts() != before {
				t.Fatal("failed anonymous parent retained effects")
			}
		})
	}
	t.Run("opaque-verifier-custody", func(t *testing.T) {
		r := request(t)
		store.observeTransition = func(transition webauthn.AssertionTransition) {
			m, err := transition.Mutation()
			if err != nil || m.Before.UserID != "user-a" || m.Context.UserID != "" || m.Context.AnonymousFlowID != r.Context.AnonymousFlowID || m.Context.ActorID != r.Context.ActorID {
				t.Fatal("root verifier lost original anonymous scope", err)
			}
			if p, err := native.AssertionFinalization(transition); err == nil || p != nil {
				t.Fatal("legacy self-user constructor accepted discovery")
			}
			if p, err := native.PreauthAssertionFinalization(transition); err == nil || p != nil {
				t.Fatal("identified preauth constructor accepted discovery")
			}
			wire, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			var reconstructed webauthn.AssertionTransition
			if err := json.Unmarshal(wire, &reconstructed); err != nil {
				t.Fatal(err)
			}
			if p, err := native.DiscoverableAssertionFinalization(reconstructed); err == nil || p != nil {
				t.Fatal("decoded projection reconstructed verifier custody")
			}
		}
		defer func() { store.observeTransition = nil }()
		if _, err := svc.VerifyDiscoverableAssertion(ctx, r); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("mapping-withdrawal-final-fence", func(t *testing.T) {
		r := request(t)
		before, c := counts(), current()
		if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('tenant-a','user-b','active',1); CREATE FUNCTION public.native_discovery_mapping_change() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN UPDATE webauthn.user_handles SET user_id='user-b' WHERE rp_id=NEW.rp_id AND user_handle=NEW.user_handle; RETURN NEW; END $$; CREATE TRIGGER native_discovery_mapping_change AFTER UPDATE ON webauthn.credentials FOR EACH ROW EXECUTE FUNCTION public.native_discovery_mapping_change();`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER native_discovery_mapping_change ON webauthn.credentials; DROP FUNCTION public.native_discovery_mapping_change(); DELETE FROM identity.users WHERE tenant_id='tenant-a' AND user_id='user-b'`); err != nil {
				t.Fatal(err)
			}
		}()
		if v, err := svc.VerifyDiscoverableAssertion(ctx, r); err == nil {
			t.Fatal("post-CAS mapping withdrawal authenticated")
		} else if _, ok := v.Credential(); ok {
			t.Fatal("withdrawn mapping exposed verification")
		}
		if counts() != before || current().Version != c.Version {
			t.Fatal("mapping withdrawal retained protected effects")
		}
	})
	t.Run("absolute-expiry-final-precommit", func(t *testing.T) {
		// Root creation has a fixed five-minute lifetime. Use a genuinely older
		// initial Generate sample to obtain a near-term absolute deadline, then
		// wait only after the real root signature and native CAS have succeeded.
		// Never rewrite a stored ceremony or its verifier-issued transition.
		store.generationOffset = -5*time.Minute + 2*time.Second
		r := request(t)
		store.generationOffset = 0
		record, err := native.LoadCeremony(ctx, webauthn.Lookup{Context: r.Context, RPID: "example.com", CeremonyID: r.CeremonyID})
		if err != nil {
			t.Fatal(err)
		}
		before, credential := counts(), current()
		var beforeAudits, afterAudits int
		// Unsuccessful attempt audits deliberately survive protected rollback;
		// only successful mutation effects must roll back with the assertion.
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM audit.records WHERE outcome=$1`, audit.OutcomeSucceeded).Scan(&beforeAudits); err != nil {
			t.Fatal(err)
		}
		staged := false
		store.afterApply = func(ctx context.Context, w kernel.Work, c identity.Command) error {
			staged = true
			// This is a later parent effect inside the genuine shared Work. Its
			// bounded wait crosses the original deadline before final precommit.
			_, err := w.Exec(ctx, `SELECT pg_sleep(GREATEST(0,EXTRACT(epoch FROM ($1::timestamptz-clock_timestamp())))+0.025)`, record.ExpiresAt)
			return err
		}
		defer func() { store.afterApply = nil; store.generationOffset = 0 }()
		verified, err := svc.VerifyDiscoverableAssertion(ctx, r)
		if !staged {
			t.Fatal("expiry test did not reach genuine verified protocol and parent staging", err)
		}
		if err == nil {
			t.Fatal("expired final precommit authenticated")
		}
		if _, ok := verified.Credential(); ok {
			t.Fatal("expired final precommit exposed verification")
		}
		if counts() != before || current().Counter != credential.Counter || current().Version != credential.Version {
			t.Fatal("absolute-expiry failure retained counter or parent effects")
		}
		var consumed bool
		if err := pool.Raw().QueryRow(ctx, `SELECT consumed_by IS NOT NULL FROM webauthn.ceremonies WHERE ceremony_id=$1`, r.CeremonyID).Scan(&consumed); err != nil || consumed {
			t.Fatal("absolute-expiry failure consumed ceremony", err)
		}
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM audit.records WHERE outcome=$1`, audit.OutcomeSucceeded).Scan(&afterAudits); err != nil || afterAudits != beforeAudits {
			t.Fatal("absolute-expiry failure retained audit effects", err)
		}
	})
	for _, failure := range []string{"actor", "kind", "flow", "tenant", "user", "intent", "apply", "commit", "withdraw", "success"} {
		t.Run("finalization-"+failure, func(t *testing.T) {
			r := request(t)
			before, c := counts(), current()
			store.invalidParent, store.failApply, store.failCommit, store.withdraw = failure, failure == "apply", failure == "commit", failure == "withdraw"
			defer func() {
				store.invalidParent, store.failApply, store.failCommit, store.withdraw = "", false, false, false
			}()
			v, err := svc.VerifyDiscoverableAssertion(ctx, r)
			if failure != "success" {
				if err == nil {
					t.Fatal("invalid final parent verified assertion")
				}
				if _, ok := v.Credential(); ok {
					t.Fatal("invalid final parent exposed verification")
				}
				if counts() != before || current().Version != c.Version {
					t.Fatal("final failure retained protocol or parent effects")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, ok := v.Credential()
			if !ok || got.UserID != "user-a" || got.Version != c.Version+1 {
				t.Fatal("genuine discovery did not finalize verified target")
			}
			var actor, protocolActor, flow string
			if err := pool.Raw().QueryRow(ctx, `SELECT actor_id,ceremony->'Intent'->'Context'->>'ActorID',ceremony->'Intent'->'Context'->>'AnonymousFlowID' FROM webauthn.effects WHERE command_id=$1`, string(r.Context.CommandID)).Scan(&actor, &protocolActor, &flow); err != nil || actor != "user-a" || protocolActor != "ingress-service" || flow != r.Context.AnonymousFlowID {
				t.Fatal("final parent rewrote anonymous protocol attribution", err)
			}
			lookup := webauthn.Lookup{Context: r.Context, RPID: "example.com", CeremonyID: r.CeremonyID}
			if snapshot, err := native.LoadDiscoverableCredential(ctx, lookup, id, handle); err != nil || snapshot.Version != c.Version {
				t.Fatal("exact discovery retry lost original snapshot", err)
			}
			for _, defect := range []string{"actor", "flow", "command", "tenant"} {
				foreign := lookup
				switch defect {
				case "actor":
					foreign.Context.ActorID = "foreign-service"
				case "flow":
					foreign.Context.AnonymousFlowID = "foreign-flow"
				case "command":
					foreign.Context.CommandID, _ = identity.NewCommandID()
				case "tenant":
					foreign.Context.TenantID = "foreign-tenant"
				}
				if snapshot, err := native.LoadDiscoverableCredential(ctx, foreign, id, handle); err == nil && snapshot.Version == c.Version {
					t.Fatal("foreign scope selected historical snapshot", defect)
				}
			}
			var original []byte
			if err := pool.Raw().QueryRow(ctx, `SELECT ceremony FROM webauthn.effects WHERE command_id=$1`, string(r.Context.CommandID)).Scan(&original); err != nil {
				t.Fatal(err)
			}
			for _, defect := range []string{"kind", "target", "tenant", "rp", "flow", "actor"} {
				t.Run("retained-"+defect, func(t *testing.T) {
					var retained webauthn.CeremonyRecord
					if err := json.Unmarshal(original, &retained); err != nil {
						t.Fatal(err)
					}
					switch defect {
					case "kind":
						retained.Intent.Kind = "get"
					case "target":
						retained.Intent.Context.UserID = "user-a"
					case "tenant":
						retained.Intent.Context.TenantID = "other-tenant"
					case "rp":
						retained.Intent.RPID = "other.example.com"
					case "flow":
						retained.Intent.Context.AnonymousFlowID = "other-flow"
					case "actor":
						retained.Intent.Context.ActorID = "other-service"
					}
					wire, err := json.Marshal(retained)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := pool.Raw().Exec(ctx, `UPDATE webauthn.effects SET ceremony=$1::jsonb WHERE command_id=$2`, string(wire), string(r.Context.CommandID)); err != nil {
						t.Fatal(err)
					}
					defer func() {
						if _, err := pool.Raw().Exec(ctx, `UPDATE webauthn.effects SET ceremony=$1::jsonb WHERE command_id=$2`, string(original), string(r.Context.CommandID)); err != nil {
							t.Fatal(err)
						}
					}()
					if snapshot, err := native.LoadDiscoverableCredential(ctx, lookup, id, handle); err == nil && snapshot.Version == c.Version {
						t.Fatal("invalid retained ceremony selected historical snapshot")
					}
				})
			}
			var replay webauthn.Replay
			if again, err := svc.VerifyDiscoverableAssertion(ctx, r); !errors.As(err, &replay) {
				t.Fatal("original discoverable completion not replay", err)
			} else if _, ok := again.Credential(); ok {
				t.Fatal("replay authenticated")
			}
			if outcome, err := svc.Recover(ctx, webauthn.RecoveryRequest{Context: r.Context, Operation: webauthn.DiscoverableAssertionOperation, CredentialID: id}); err != nil || outcome != identity.CommitOutcomeCommitted {
				t.Fatal("original final parent not recovered", err)
			}
		})
	}
	t.Run("protocol-actor-flow-and-signature", func(t *testing.T) {
		for _, defect := range []string{"actor", "flow", "signature", "handle"} {
			r := request(t)
			before := counts()
			switch defect {
			case "actor":
				r.Context.ActorID = "foreign-service"
			case "flow":
				r.Context.AnonymousFlowID = "foreign-flow"
			case "signature", "handle":
				var body map[string]any
				_ = json.Unmarshal(r.Response, &body)
				name := "signature"
				if defect == "handle" {
					name = "userHandle"
				}
				body["response"].(map[string]any)[name] = "AA"
				r.Response, _ = json.Marshal(body)
			}
			if v, err := svc.VerifyDiscoverableAssertion(ctx, r); err == nil {
				t.Fatal("invalid anonymous protocol scope/signature accepted", defect)
			} else if _, ok := v.Credential(); ok {
				t.Fatal("invalid protocol exposed verification")
			}
			if counts() != before {
				t.Fatal("invalid anonymous protocol retained effects")
			}
		}
	})
	t.Run("lost-commit-original-recovery", func(t *testing.T) {
		cut := &commitCut{}
		cutPool, err := database.New(ctx, database.Config{DSN: os.Getenv("WEBAUTHN_TEST_DSN"), MaxConns: 2, SessionInit: func(ctx context.Context, c *pgx.Conn) error {
			_, err := c.Exec(ctx, `SET search_path=public`)
			return err
		}, Configure: func(c *database.PoolConfig) error {
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
		cutNative, err := webauthnpg.New(cutPool, webauthnpg.Config{Coordinator: config, PolicyID: "assertion-participation-test", PolicyVersion: 1})
		if err != nil {
			t.Fatal(err)
		}
		cutStore := &discoverableAssertionStore{assertionStore: &assertionStore{Store: cutNative, pool: cutPool, config: config, preauth: true, discoverable: true}, create: cutNative.DiscoverableAssertionCreation, finalize: cutNative.DiscoverableAssertionFinalization}
		cutService, err := webauthn.NewDiscoverable(serviceConfig, webauthn.Dependencies{Store: cutStore})
		if err != nil {
			t.Fatal(err)
		}
		original := fresh(true)
		before := counts()
		cut.remaining.Store(2)
		var unknown webauthn.UnknownCommit
		if options, err := cutService.BeginDiscoverableAssertion(ctx, webauthn.BeginDiscoverableAssertionRequest{Context: original, Origin: serviceConfig.RelyingParty.Origins[0]}); !errors.As(err, &unknown) || !cut.cut.Load() {
			t.Fatal("lost anonymous creation commit not unknown", err)
		} else if _, ok := options.Ceremony(); ok {
			t.Fatal("unknown anonymous creation exposed ceremony")
		}
		if counts() != [4]int{before[0] + 1, before[1] + 1, before[2] + 1, before[3] + 1} {
			t.Fatal("lost anonymous COMMIT did not commit parent and protocol together")
		}
		if outcome, err := cutService.Recover(ctx, webauthn.RecoveryRequest{Context: original, Operation: webauthn.BeginDiscoverableAssertionOperation}); err != nil || outcome != identity.CommitOutcomeCommitted {
			t.Fatal("original anonymous creation not recovered", err)
		}
		r := request(t)
		before, c := counts(), current()
		cut.cut.Store(false)
		cut.remaining.Store(2)
		if v, err := cutService.VerifyDiscoverableAssertion(ctx, r); !errors.As(err, &unknown) || !cut.cut.Load() {
			t.Fatal("lost discovery final COMMIT not unknown", err)
		} else if _, ok := v.Credential(); ok {
			t.Fatal("unknown final COMMIT authenticated")
		}
		if counts() != [4]int{before[0], before[1] + 1, before[2] + 1, before[3] + 1} || current().Version != c.Version+1 {
			t.Fatal("lost final COMMIT did not atomically persist protocol and parent")
		}
		before = counts()
		if outcome, err := cutService.Recover(ctx, webauthn.RecoveryRequest{Context: r.Context, Operation: webauthn.DiscoverableAssertionOperation, CredentialID: id}); err != nil || outcome != identity.CommitOutcomeCommitted {
			t.Fatal("original self-human final parent not recovered", err)
		}
		var replay webauthn.Replay
		if v, err := cutService.VerifyDiscoverableAssertion(ctx, r); !errors.As(err, &replay) {
			t.Fatal("recovered discovery not replay", err)
		} else if _, ok := v.Credential(); ok {
			t.Fatal("recovered discovery authenticated")
		}
		if counts() != before {
			t.Fatal("recovery or retry repeated effects")
		}
		for _, finish := range []bool{false, true} {
			original = fresh(true)
			var req webauthn.VerifyDiscoverableAssertionRequest
			if finish {
				req = request(t)
				original = req.Context
			}
			before = counts()
			cut.cut.Store(false)
			cut.remaining.Store(1)
			if finish {
				if _, err := cutService.VerifyDiscoverableAssertion(ctx, req); !errors.As(err, &unknown) {
					t.Fatal("lost final reservation not unknown", err)
				}
			} else {
				if _, err := cutService.BeginDiscoverableAssertion(ctx, webauthn.BeginDiscoverableAssertionRequest{Context: original, Origin: serviceConfig.RelyingParty.Origins[0]}); !errors.As(err, &unknown) {
					t.Fatal("lost anonymous reservation not unknown", err)
				}
			}
			commandID, _ := base64.RawURLEncoding.DecodeString(string(original.CommandID))
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET created_at=clock_timestamp()-interval '3 seconds',heartbeat_at=clock_timestamp()-interval '2 seconds',updated_at=clock_timestamp()-interval '2 seconds',lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, commandID); err != nil {
				t.Fatal(err)
			}
			op := webauthn.BeginDiscoverableAssertionOperation
			var credentialID []byte
			if finish {
				op = webauthn.DiscoverableAssertionOperation
				credentialID = id
			}
			var unavailable identity.UnavailableError
			if outcome, err := cutService.Recover(ctx, webauthn.RecoveryRequest{Context: original, Operation: op, CredentialID: credentialID}); !errors.As(err, &unavailable) || outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("pending original did not reconcile absence", finish, err)
			}
			if counts() != before {
				t.Fatal("noncommit recovery retained effects")
			}
		}
	})
	t.Run("one-consumption-concurrent", func(t *testing.T) {
		r := request(t)
		before, c := counts(), current()
		ready, resume := make(chan struct{}, 2), make(chan struct{})
		results := make(chan bool, 2)
		for range 2 {
			base := *store.assertionStore
			invocation := &discoverableAssertionStore{assertionStore: &base, create: native.DiscoverableAssertionCreation, finalize: native.DiscoverableAssertionFinalization}
			concurrent, err := webauthn.NewDiscoverable(serviceConfig, webauthn.Dependencies{Store: pausedDiscoverableStore{DiscoverableStore: invocation, ready: ready, resume: resume}})
			if err != nil {
				t.Fatal(err)
			}
			input := r
			input.Context = fresh(true)
			go func() {
				v, err := concurrent.VerifyDiscoverableAssertion(ctx, input)
				_, ok := v.Credential()
				results <- err == nil && ok
			}()
		}
		for range 2 {
			select {
			case <-ready:
			case <-ctx.Done():
				t.Fatal("concurrent opaque verification deadline")
			}
		}
		close(resume)
		winners := 0
		for range 2 {
			if <-results {
				winners++
			}
		}
		if winners != 1 || current().Version != c.Version+1 || counts() != [4]int{before[0], before[1] + 1, before[2] + 1, before[3] + 1} {
			t.Fatal("concurrent discovery did not have one atomic winner", winners)
		}
	})
}
