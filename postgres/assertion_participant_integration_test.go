//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	webauthn "github.com/faustbrian/go-webauthn"
	webauthnpg "github.com/faustbrian/go-webauthn/postgres"
	"github.com/jackc/pgx/v5"
)

// Protocol composition fixture only: the actual identity authentication,
// preauth/risk admission, passkey metadata and session owners are not replaced.
type assertionOwner struct {
	command                                  identity.Command
	creation                                 *webauthnpg.AssertionCreation
	finalization                             *webauthnpg.AssertionFinalization
	store                                    *webauthnpg.Store
	failApply, failCommit, foreign, withdraw bool
}

func (*assertionOwner) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}
}
func (*assertionOwner) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{assertionOperation(false), assertionOperation(true)}
}
func assertionOperation(finish bool) identity.FeatureOperation {
	id := "identity.passkey.signin-options"
	if finish {
		id = "identity.passkey.signin-verify"
	}
	return identity.FeatureOperation{Owner: "passkey", OperationID: id, SchemaID: id + ".native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}
func (p *assertionOwner) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if c != p.command {
		return identity.InvalidInputError{Field: "test_command"}
	}
	if p.creation != nil {
		return p.creation.Validate(c, plan)
	}
	if p.finalization != nil {
		return p.finalization.Validate(c, plan)
	}
	return identity.InvalidInputError{Field: "test_transition"}
}
func (p *assertionOwner) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	owner := p
	if p.foreign {
		owner = &assertionOwner{}
	}
	var err error
	if p.creation != nil {
		err = p.creation.Apply(ctx, w, owner, c)
	} else {
		err = p.finalization.Apply(ctx, w, owner, c)
	}
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	b, _, _, err := w.FeatureScope(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if _, err = w.Exec(ctx, `INSERT INTO assertion_participation_metadata(command_id) VALUES($1)`, string(b.CommandID)); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.withdraw {
		if _, err = w.Exec(ctx, `UPDATE identity.users SET status='suspended' WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), string(b.UserID)); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	if p.failApply {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	s, _ := c.Feature()
	return identity.FeatureReceipt{Operation: s.Operation, AfterVersion: 1}, nil
}
func (p *assertionOwner) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p.failCommit {
		return identity.ForbiddenError{}
	}
	if p.creation != nil {
		return p.creation.Check(ctx, w, p, c)
	}
	return p.finalization.Check(ctx, w, p, c)
}
func (p *assertionOwner) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	protocol, err := p.store.RecoverAssertion(ctx, w, p)
	if err != nil || protocol != kernel.RecoveryNotCommitted {
		return protocol, err
	}
	b, _, _, err := w.FeatureScope(p)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	rows, err := w.Query(ctx, `SELECT 1 FROM assertion_participation_metadata WHERE command_id=$1`, string(b.CommandID))
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if rows.Next() {
		return kernel.RecoveryUnknown, nil
	}
	if err = rows.Err(); err != nil {
		return kernel.RecoveryUnknown, err
	}
	return kernel.RecoveryNotCommitted, nil
}

type assertionStore struct {
	*webauthnpg.Store
	pool                                     *database.Pool
	config                                   kernel.CoordinatorConfig
	failApply, failCommit, foreign, withdraw bool
	invalidParent                            string
	observeCreation                          func(*webauthnpg.AssertionCreation, identity.CommandResult)
	observeFinalization                      func(*webauthnpg.AssertionFinalization, identity.CommandResult)
}

func (s *assertionStore) coordinator(p *assertionOwner) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	d, err := kernel.NewRepository(s.pool, kernel.Config{MaximumDuration: 5 * time.Second})
	if err != nil {
		return nil, nil, err
	}
	a, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	l, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	r, err := kernel.NewContributorRegistry([]kernel.Contributor{d, a, l, p})
	if err != nil {
		return nil, nil, err
	}
	coordinator, err := kernel.NewCoordinator(s.pool, r, s.config)
	return coordinator, r, err
}
func (s *assertionStore) execute(ctx context.Context, p *assertionOwner, scope webauthn.CeremonyContext, fields []identity.FeatureField) (identity.CommandResult, error) {
	op := assertionOperation(p.finalization != nil)
	b := identity.CommandBinding{CommandID: scope.CommandID, TenantID: scope.TenantID, UserID: scope.UserID, ActorID: scope.ActorID, ActorKind: authorization.SubjectUser, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "assertion-participation-test", PolicyVersion: 1, CorrelationID: scope.CorrelationID, RecordID: string(scope.CommandID)}
	switch s.invalidParent {
	case "scope":
		b.CorrelationID = "different-valid-parent-correlation"
	case "tenant":
		b.TenantID = "tenant-b"
	case "user":
		b.UserID, b.ActorID = "user-b", "user-b"
	case "actor":
		b.ActorID = "other-user"
	case "intent":
		fields[0].Value.Bytes = bytes.Clone(fields[0].Value.Bytes)
		fields[0].Value.Bytes[0] ^= 1
	}
	c, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields})
	if err != nil {
		return identity.CommandResult{}, err
	}
	p.command, p.store, p.failApply, p.failCommit, p.foreign, p.withdraw = c, s.Store, s.failApply, s.failCommit, s.foreign, s.withdraw
	coordinator, r, err := s.coordinator(p)
	if err != nil {
		return identity.CommandResult{}, err
	}
	builder, _ := audit.NewBuilder(audit.BuilderConfig{})
	seed, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC().Truncate(time.Microsecond), Action: op.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "passkey", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "passkey", "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
	if err != nil {
		return identity.CommandResult{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, op, "passkey", seed)
	if err != nil {
		return identity.CommandResult{}, err
	}
	plan, err := coordinator.PrepareCommandPlan(b, c, kernel.CommandPlan{Contributors: r.Descriptors(), SubjectType: "passkey", Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}, Lifecycle: &kernel.LifecyclePlan{EventType: op.OperationID + ".v1", AfterVersion: 1}, Audits: []kernel.AuditPlan{{EventType: op.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
	if err != nil {
		return identity.CommandResult{}, err
	}
	reservation, result, err := coordinator.ReserveCommand(ctx, b, c, plan)
	if err != nil || reservation == (kernel.Reservation{}) {
		return result, err
	}
	if p.creation != nil {
		var now time.Time
		if err = s.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return identity.CommandResult{}, err
		}
		if err = p.creation.Generate(ctx, now); err != nil {
			return identity.CommandResult{}, err
		}
	}
	w, err := coordinator.Begin(ctx, reservation)
	if err != nil {
		return identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeUnknown}, err
	}
	defer coordinator.Abort(w, identity.UnavailableError{})
	provisional, err := coordinator.ApplyFeature(ctx, w, c)
	if err != nil {
		return coordinator.Abort(w, err)
	}
	return coordinator.Commit(w, provisional)
}
func (s *assertionStore) CreateCeremony(ctx context.Context, c webauthn.CeremonyCreation) (webauthn.CeremonyRecord, webauthn.Challenge, identity.CommitOutcome, error) {
	p, err := s.Store.AssertionCreation(c)
	if err != nil {
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, identity.CommitOutcomeInvalid, err
	}
	defer p.Discard()
	i, _ := c.Intent()
	fields, _ := p.Fields()
	result, runErr := s.execute(ctx, &assertionOwner{creation: p}, i.Context, fields)
	record, challenge, err := p.Result(result)
	if s.observeCreation != nil {
		s.observeCreation(p, result)
	}
	if runErr != nil {
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, result.Outcome, runErr
	}
	return record, challenge, result.Outcome, err
}
func (s *assertionStore) FinalizeAssertion(ctx context.Context, t webauthn.AssertionTransition) (webauthn.Credential, identity.CommitOutcome, error) {
	p, err := s.Store.AssertionFinalization(t)
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	m, _ := t.Mutation()
	fields, _ := p.Fields()
	result, runErr := s.execute(ctx, &assertionOwner{finalization: p}, m.Context, fields)
	credential, err := p.Result(result)
	if s.observeFinalization != nil {
		s.observeFinalization(p, result)
	}
	if runErr != nil {
		return webauthn.Credential{}, result.Outcome, runErr
	}
	return credential, result.Outcome, err
}
func (s *assertionStore) Recover(ctx context.Context, r webauthn.RecoveryRequest) (identity.CommitOutcome, error) {
	if r.Operation != webauthn.BeginAssertionOperation && r.Operation != webauthn.AssertionOperation {
		return identity.CommitOutcomeInvalid, webauthn.Invalid{Field: "test_recovery"}
	}
	p := &assertionOwner{store: s.Store}
	coordinator, _, err := s.coordinator(p)
	if err != nil {
		return identity.CommitOutcomeUnknown, err
	}
	op := assertionOperation(r.Operation == webauthn.AssertionOperation)
	q := identity.RecoveryQuery{CommandID: r.Context.CommandID, TenantID: r.Context.TenantID, UserID: r.Context.UserID, ActorID: r.Context.ActorID, ActorKind: authorization.SubjectUser, OperationID: op.OperationID, RecordID: string(r.Context.CommandID)}
	caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(q.ActorID), Kind: q.ActorKind}, Tenant: authorization.TenantID(q.TenantID), Action: authorization.Action(q.OperationID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(q.UserID)}}}
	result, err := coordinator.RecoverCommand(ctx, q, caller)
	return result.Outcome, err
}

func TestAssertionParticipationPostgres(t *testing.T) {
	ctx, pool, config, native := nativeFixture(t)
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE assertion_participation_metadata(command_id text PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	store := &assertionStore{Store: native, pool: pool, config: config}
	key, _ := webauthn.NewChallengeDigestKey(bytes.Repeat([]byte{91}, 32))
	serviceConfig := webauthn.Config{TenantID: "tenant-a", RelyingParty: webauthn.RelyingParty{ID: "example.com", Name: "Assertion Participant", Origins: []string{"https://login.example.com"}, Version: 1}, ChallengeKey: key, MaximumDuration: 10 * time.Second}
	svc, err := webauthn.New(serviceConfig, webauthn.Dependencies{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	registrationService, err := webauthn.New(serviceConfig, webauthn.Dependencies{Store: native})
	if err != nil {
		t.Fatal(err)
	}
	fresh := func() webauthn.CeremonyContext {
		id, _ := identity.NewCommandID()
		return webauthn.CeremonyContext{CommandID: id, TenantID: "tenant-a", UserID: "user-a", ActorID: "user-a", CorrelationID: "assertion-participation"}
	}
	handle, id := bytes.Repeat([]byte{92}, 32), bytes.Repeat([]byte{93}, 32)
	private, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	opts, err := registrationService.BeginRegistration(ctx, webauthn.BeginRegistrationRequest{Context: fresh(), UserHandle: handle, Origin: "https://login.example.com", ResidentKeyRequired: true})
	if err != nil {
		t.Fatal(err)
	}
	ceremony, _ := opts.Ceremony()
	challenge := optionChallenge(t, ctx, opts.TransferJSON)
	registered, err := registrationService.VerifyRegistration(ctx, webauthn.VerifyRegistrationRequest{Context: fresh(), CeremonyID: ceremony.ID, Origin: "https://login.example.com", ExpectedVersion: 1, Response: registrationResponse(t, private, id, challenge, 0x45, 0)})
	if err != nil {
		t.Fatal(err)
	}
	credential, _ := registered.Credential()
	beginRequest := func() webauthn.BeginAssertionRequest {
		return webauthn.BeginAssertionRequest{Context: fresh(), UserHandle: handle, Origin: "https://login.example.com", AllowedCredentials: [][]byte{id}}
	}
	counts := func() [6]int {
		var n [6]int
		if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM webauthn.ceremonies),(SELECT count(*) FROM webauthn.credentials),(SELECT count(*) FROM webauthn.effects),(SELECT count(*) FROM assertion_participation_metadata),(SELECT count(*) FROM audit.records WHERE outcome=$1),(SELECT count(*) FROM public.outbox_messages)`, int(audit.OutcomeSucceeded)).Scan(&n[0], &n[1], &n[2], &n[3], &n[4], &n[5]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	current := func() webauthn.Credential {
		c, err := native.LoadCredential(ctx, webauthn.Lookup{Context: fresh(), RPID: "example.com"}, id)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	t.Run("unsupported-profile-fails-closed", func(t *testing.T) {
		before := counts()
		options, err := svc.BeginRegistration(ctx, webauthn.BeginRegistrationRequest{Context: fresh(), UserHandle: handle, Origin: "https://login.example.com", ResidentKeyRequired: true})
		if err == nil {
			t.Fatal("assertion participant accepted creation ceremony")
		}
		if _, ok := options.Ceremony(); ok {
			t.Fatal("unsupported creation exposed options")
		}
		expanded := serviceConfig
		expanded.Algorithms = []webauthn.Algorithm{webauthn.ES256, webauthn.EdDSA}
		expandedService, err := webauthn.New(expanded, webauthn.Dependencies{Store: store})
		if err != nil {
			t.Fatal(err)
		}
		if options, err := expandedService.BeginAssertion(ctx, beginRequest()); err == nil {
			t.Fatal("expanded algorithm profile accepted")
		} else if _, ok := options.Ceremony(); ok {
			t.Fatal("expanded profile exposed ceremony")
		}
		request := beginRequest()
		request.Context.ActorID = "different-actor"
		if options, err := svc.BeginAssertion(ctx, request); err == nil {
			t.Fatal("non-self actor accepted")
		} else if _, ok := options.Ceremony(); ok {
			t.Fatal("foreign actor exposed ceremony")
		}
		if counts() != before {
			t.Fatal("unsupported profile committed effects")
		}
	})
	t.Run("creation-copy-reveals-once", func(t *testing.T) {
		store.observeCreation = func(p *webauthnpg.AssertionCreation, result identity.CommandResult) {
			alias := *p
			if _, _, err := alias.Result(result); err == nil {
				t.Fatal("creation alias rereleased custody")
			}
			if err := alias.Generate(ctx, time.Now()); err == nil {
				t.Fatal("creation alias regenerated entropy")
			}
			alias.Discard()
		}
		defer func() { store.observeCreation = nil }()
		options, err := svc.BeginAssertion(ctx, beginRequest())
		if err != nil {
			t.Fatal(err)
		}
		optionChallenge(t, ctx, options.TransferJSON)
	})
	for _, failure := range []string{"foreign", "apply", "commit", "withdraw", "scope", "tenant", "user", "actor", "intent"} {
		t.Run("creation-"+failure, func(t *testing.T) {
			before := counts()
			store.foreign, store.failApply, store.failCommit, store.withdraw = failure == "foreign", failure == "apply", failure == "commit", failure == "withdraw"
			if failure == "scope" || failure == "tenant" || failure == "user" || failure == "actor" || failure == "intent" {
				store.invalidParent = failure
			}
			options, err := svc.BeginAssertion(ctx, beginRequest())
			if err == nil {
				t.Fatal("failed parent exposed options")
			}
			if _, ok := options.Ceremony(); ok {
				t.Fatal("failed parent exposed ceremony")
			}
			if err := options.TransferJSON(ctx, func(context.Context, []byte) error { t.Fatal("failed parent exposed challenge"); return nil }); err == nil {
				t.Fatal("failed parent returned custody")
			}
			if counts() != before {
				t.Fatal("failed parent retained protected effects")
			}
			store.foreign, store.failApply, store.failCommit, store.withdraw, store.invalidParent = false, false, false, false, ""
		})
	}
	newAssertion := func(t *testing.T) webauthn.VerifyAssertionRequest {
		t.Helper()
		options, err := svc.BeginAssertion(ctx, beginRequest())
		if err != nil {
			t.Fatal(err)
		}
		r, _ := options.Ceremony()
		ch := optionChallenge(t, ctx, options.TransferJSON)
		c := current()
		return webauthn.VerifyAssertionRequest{Context: fresh(), CeremonyID: r.ID, Origin: "https://login.example.com", ExpectedVersion: 1, ExpectedCredentialVersion: c.Version, Response: assertionResponse(t, private, id, handle, ch, 0x05, c.Counter+1)}
	}
	t.Run("finalization-copy-returns-once", func(t *testing.T) {
		request := newAssertion(t)
		store.observeFinalization = func(p *webauthnpg.AssertionFinalization, result identity.CommandResult) {
			alias := *p
			if _, err := alias.Result(result); err == nil {
				t.Fatal("finalization alias reissued result")
			}
		}
		defer func() { store.observeFinalization = nil }()
		if _, err := svc.VerifyAssertion(ctx, request); err != nil {
			t.Fatal(err)
		}
	})
	for _, failure := range []string{"foreign", "apply", "commit", "withdraw", "scope", "tenant", "user", "actor", "intent", "success"} {
		t.Run("finalization-"+failure, func(t *testing.T) {
			request := newAssertion(t)
			before, c := counts(), current()
			store.foreign, store.failApply, store.failCommit, store.withdraw = failure == "foreign", failure == "apply", failure == "commit", failure == "withdraw"
			if failure == "scope" || failure == "tenant" || failure == "user" || failure == "actor" || failure == "intent" {
				store.invalidParent = failure
			}
			verified, err := svc.VerifyAssertion(ctx, request)
			if failure != "success" {
				if err == nil {
					t.Fatal("failed parent returned verification")
				}
				if _, ok := verified.Credential(); ok {
					t.Fatal("uncommitted protocol evidence exposed")
				}
				if counts() != before || current().Counter != c.Counter || current().Version != c.Version {
					t.Fatal("failed parent retained counter/parent/effect")
				}
				var consumed bool
				if err := pool.Raw().QueryRow(ctx, `SELECT consumed_by IS NOT NULL FROM webauthn.ceremonies WHERE ceremony_id=$1`, request.CeremonyID).Scan(&consumed); err != nil || consumed {
					t.Fatal("failed parent consumed ceremony", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				got, ok := verified.Credential()
				if !ok || got.Counter != c.Counter+1 || got.Version != c.Version+1 {
					t.Fatal("committed assertion missing counter transition")
				}
				if current().Counter != c.Counter+1 || current().Version != c.Version+1 {
					t.Fatal("successful protocol output did not persist its counter/version")
				}
				if counts() != [6]int{before[0], before[1], before[2] + 1, before[3] + 1, before[4] + 1, before[5] + 1} {
					t.Fatal("protocol/parent did not commit together")
				}
				var purpose string
				if err := pool.Raw().QueryRow(ctx, `SELECT purpose FROM webauthn.effects WHERE command_id=$1`, string(request.Context.CommandID)).Scan(&purpose); err != nil || purpose != "identity.passkey.signin-verify" {
					t.Fatal("effect detached from parent", err)
				}
				var replay webauthn.Replay
				if again, err := svc.VerifyAssertion(ctx, request); !errors.As(err, &replay) {
					t.Fatal("replay reissued verification", err)
				} else if _, ok := again.Credential(); ok {
					t.Fatal("replay authenticated")
				}
			}
			store.foreign, store.failApply, store.failCommit, store.withdraw, store.invalidParent = false, false, false, false, ""
		})
	}
	t.Run("single-consumption-concurrent", func(t *testing.T) {
		request := newAssertion(t)
		before, c := counts(), current()
		results := make(chan bool, 2)
		for range 2 {
			r := request
			r.Context = fresh()
			go func() { v, err := svc.VerifyAssertion(ctx, r); _, ok := v.Credential(); results <- err == nil && ok }()
		}
		winners := 0
		for range 2 {
			if <-results {
				winners++
			}
		}
		if winners != 1 || current().Counter != c.Counter+1 || current().Version != c.Version+1 {
			t.Fatal("concurrent completion had", winners, "winners")
		}
		if counts() != [6]int{before[0], before[1], before[2] + 1, before[3] + 1, before[4] + 1, before[5] + 1} {
			t.Fatal("concurrent completion duplicated effects")
		}
	})
	t.Run("stale-credential-snapshot", func(t *testing.T) {
		first, second := newAssertion(t), newAssertion(t)
		if _, err := svc.VerifyAssertion(ctx, first); err != nil {
			t.Fatal(err)
		}
		before := counts()
		if v, err := svc.VerifyAssertion(ctx, second); err == nil {
			t.Fatal("stale assertion accepted")
		} else if _, ok := v.Credential(); ok {
			t.Fatal("stale assertion verified")
		}
		if counts() != before {
			t.Fatal("stale assertion retained effects")
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
		cutStore := &assertionStore{Store: cutNative, pool: cutPool, config: config}
		cutService, err := webauthn.New(serviceConfig, webauthn.Dependencies{Store: cutStore})
		if err != nil {
			t.Fatal(err)
		}
		original := beginRequest()
		before := counts()
		cut.remaining.Store(2)
		options, err := cutService.BeginAssertion(ctx, original)
		var unknown webauthn.UnknownCommit
		if !errors.As(err, &unknown) || !cut.cut.Load() {
			t.Fatal("lost creation COMMIT was not unknown", err)
		}
		if _, ok := options.Ceremony(); ok {
			t.Fatal("unknown creation exposed options")
		}
		if counts() != [6]int{before[0] + 1, before[1], before[2] + 1, before[3] + 1, before[4] + 1, before[5] + 1} {
			t.Fatal("lost creation acknowledgement did not commit protocol and parent together")
		}
		before = counts()
		if outcome, err := svc.Recover(ctx, webauthn.RecoveryRequest{Context: original.Context, Operation: webauthn.BeginAssertionOperation}); err != nil || outcome != identity.CommitOutcomeCommitted {
			t.Fatal("original creation not recovered", err)
		}
		var replay webauthn.Replay
		if retry, err := svc.BeginAssertion(ctx, original); !errors.As(err, &replay) {
			t.Fatal("lost challenge recreated", err)
		} else if err := retry.TransferJSON(ctx, func(context.Context, []byte) error { t.Fatal("lost challenge revealed"); return nil }); err == nil {
			t.Fatal("replay returned custody")
		}
		if counts() != before {
			t.Fatal("creation recovery repeated effects")
		}
		request := newAssertion(t)
		c := current()
		before = counts()
		cut.cut.Store(false)
		cut.remaining.Store(2)
		verified, err := cutService.VerifyAssertion(ctx, request)
		if !errors.As(err, &unknown) || !cut.cut.Load() {
			t.Fatal("lost final COMMIT was not unknown", err)
		}
		if _, ok := verified.Credential(); ok {
			t.Fatal("unknown commit exposed verification")
		}
		if counts() != [6]int{before[0], before[1], before[2] + 1, before[3] + 1, before[4] + 1, before[5] + 1} {
			t.Fatal("lost assertion acknowledgement did not commit protocol and parent together")
		}
		before = counts()
		if current().Counter != c.Counter+1 || current().Version != c.Version+1 {
			t.Fatal("server did not actually commit counter")
		}
		if outcome, err := svc.Recover(ctx, webauthn.RecoveryRequest{Context: request.Context, Operation: webauthn.AssertionOperation, CredentialID: credential.ID}); err != nil || outcome != identity.CommitOutcomeCommitted {
			t.Fatal("original assertion not recovered", err)
		}
		if again, err := svc.VerifyAssertion(ctx, request); !errors.As(err, &replay) {
			t.Fatal("recovered completion reverified", err)
		} else if _, ok := again.Credential(); ok {
			t.Fatal("recovery authenticated")
		}
		foreign := request.Context
		foreign.ActorID = "other-user"
		if outcome, _ := svc.Recover(ctx, webauthn.RecoveryRequest{Context: foreign, Operation: webauthn.AssertionOperation, CredentialID: id}); outcome == identity.CommitOutcomeCommitted {
			t.Fatal("foreign actor recovered assertion")
		}
		if counts() != before {
			t.Fatal("assertion recovery repeated effects")
		}
		original = beginRequest()
		cut.cut.Store(false)
		cut.remaining.Store(1)
		if options, err := cutService.BeginAssertion(ctx, original); !errors.As(err, &unknown) {
			t.Fatal("lost reservation was not unknown", err)
		} else if _, ok := options.Ceremony(); ok {
			t.Fatal("unknown reservation exposed options")
		}
		commandID, _ := base64.RawURLEncoding.DecodeString(string(original.Context.CommandID))
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET created_at=clock_timestamp()-interval '3 seconds',heartbeat_at=clock_timestamp()-interval '2 seconds',updated_at=clock_timestamp()-interval '2 seconds',lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, commandID); err != nil {
			t.Fatal(err)
		}
		var unavailable identity.UnavailableError
		if outcome, err := svc.Recover(ctx, webauthn.RecoveryRequest{Context: original.Context, Operation: webauthn.BeginAssertionOperation}); !errors.As(err, &unavailable) || outcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("pending original did not reconcile absence", err)
		}
		if counts() != before {
			t.Fatal("noncommit recovery created effects")
		}
	})
}
