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

// This is deliberately a protocol-participant consumer, not a passkey workflow
// or fresh-authentication substitute. Only real protocol objects and the real
// public coordinator reach storage. Parent-only metadata proves shared rollback.
type registrationOwner struct {
	command                        identity.Command
	creation                       *webauthnpg.RegistrationCreation
	finalization                   *webauthnpg.RegistrationFinalization
	store                          *webauthnpg.Store
	failApply, failCommit, foreign bool
	signupFlow                     string
	tamperSignup                   string
}

func (*registrationOwner) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}
}
func (*registrationOwner) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{registrationOperation(false), registrationOperation(true), signupRegistrationOperation(false), signupRegistrationOperation(true)}
}
func signupRegistrationOperation(finish bool) identity.FeatureOperation {
	op := registrationOperation(finish)
	op.SchemaID = op.OperationID + ".signup-v1"
	op.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
	return op
}
func registrationOperation(finish bool) identity.FeatureOperation {
	name := "identity.passkey.register-options"
	if finish {
		name = "identity.passkey.register-verify"
	}
	return identity.FeatureOperation{Owner: "passkey", OperationID: name, SchemaID: name + ".native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}
func (p *registrationOwner) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
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
func (p *registrationOwner) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	owner := p
	if p.foreign {
		owner = &registrationOwner{}
	}
	var err error
	if p.signupFlow != "" && p.finalization != nil {
		// This protocol-only consumer stands in for the parent-owned creation
		// effect, not for the native identity creation API or signup authority.
		spec, _ := c.Feature()
		for _, field := range spec.Fields {
			if field.Name == "registration.user" {
				if _, err = w.Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,$2,'active',1)`, string(spec.Binding.TenantID), field.Value.Text); err != nil {
					return identity.FeatureReceipt{}, err
				}
			}
		}
	}
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
	if _, err = w.Exec(ctx, `INSERT INTO participation_metadata(command_id) VALUES($1)`, string(b.CommandID)); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.failApply {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	s, _ := c.Feature()
	return identity.FeatureReceipt{Operation: s.Operation, AfterVersion: 1}, nil
}
func (p *registrationOwner) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p.failCommit {
		return identity.ForbiddenError{}
	}
	if p.finalization != nil && p.tamperSignup != "" {
		b, _, _, err := w.FeatureScope(p)
		if err != nil {
			return err
		}
		switch p.tamperSignup {
		case "flow-fence":
			_, err = w.Exec(ctx, `UPDATE webauthn.ceremonies SET signup_flow_id='changed-before-final-check' WHERE consumed_by=$1`, string(b.CommandID))
		case "active-fence":
			_, err = w.Exec(ctx, `UPDATE identity.users SET status='suspended' WHERE tenant_id=$1 AND user_id='prospective-user'`, string(b.TenantID))
		}
		if err != nil {
			return err
		}
	}
	if p.creation != nil {
		return p.creation.Check(ctx, w, p, c)
	}
	return p.finalization.Check(ctx, w, p, c)
}
func (p *registrationOwner) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return p.store.RecoverRegistration(ctx, w, p)
}

type registrationStore struct {
	*webauthnpg.Store
	pool                           *database.Pool
	config                         kernel.CoordinatorConfig
	failApply, failCommit, foreign bool
	invalidParent                  string
	signupFlow                     string
	tamperSignup                   string
}

func (s *registrationStore) coordinator(p *registrationOwner) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	directory, err := kernel.NewRepository(s.pool, kernel.Config{MaximumDuration: 5 * time.Second})
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
	r, err := kernel.NewContributorRegistry([]kernel.Contributor{directory, a, l, p})
	if err != nil {
		return nil, nil, err
	}
	coordinator, err := kernel.NewCoordinator(s.pool, r, s.config)
	return coordinator, r, err
}

func (s *registrationStore) execute(ctx context.Context, p *registrationOwner, scope webauthn.CeremonyContext, fields []identity.FeatureField) (identity.CommandResult, error) {
	op := registrationOperation(p.finalization != nil)
	b := identity.CommandBinding{CommandID: scope.CommandID, TenantID: scope.TenantID, UserID: scope.UserID, ActorID: scope.ActorID, ActorKind: authorization.SubjectUser, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "participation-test", PolicyVersion: 1, CorrelationID: scope.CorrelationID, RecordID: string(scope.CommandID)}
	if s.signupFlow != "" {
		op = signupRegistrationOperation(p.finalization != nil)
		b.SchemaID, b.UserID, b.AnonymousFlowID, b.ActorKind = op.SchemaID, "", s.signupFlow, authorization.SubjectServiceAccount
		fields = append(fields, identity.FeatureField{Name: "registration.user", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(scope.UserID)}})
		p.signupFlow = s.signupFlow
	}
	// Both mutations remain valid root commands. Keep the real opaque protocol
	// input unchanged, so only the participant's original-intent guard can deny
	// them; no foreign owner, malformed command or incidental SQL mismatch helps.
	switch s.invalidParent {
	case "scope":
		b.CorrelationID = "different-valid-parent-correlation"
	case "intent":
		fields[0].Value.Bytes = bytes.Clone(fields[0].Value.Bytes)
		fields[0].Value.Bytes[0] ^= 1
	case "actor":
		b.ActorID = "other-signup-service"
	case "flow":
		b.AnonymousFlowID = "other-parent-flow"
	case "pending-user":
		fields[len(fields)-1].Value.Text = "other-prospective-user"
	case "missing-user":
		fields = fields[:len(fields)-1]
	case "typed-user":
		fields[len(fields)-1].Value = identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: []byte("prospective-user")}
	case "command":
		b.CommandID, _ = identity.NewCommandID()
	case "schema":
		op.SchemaID = op.OperationID + ".unselected-v1"
		b.SchemaID = op.SchemaID
	case "mixed-user":
		b.UserID = scope.UserID
	case "actor-kind":
		b.ActorKind = authorization.SubjectUser
	}
	c, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields})
	if err != nil {
		return identity.CommandResult{}, err
	}
	p.command, p.store, p.failApply, p.failCommit, p.foreign = c, s.Store, s.failApply, s.failCommit, s.foreign
	p.tamperSignup = s.tamperSignup
	coordinator, r, err := s.coordinator(p)
	if err != nil {
		return identity.CommandResult{}, err
	}
	builder, _ := audit.NewBuilder(audit.BuilderConfig{})
	actorKind := audit.ActorHuman
	if s.signupFlow != "" {
		actorKind = audit.ActorService
	}
	seed, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC().Truncate(time.Microsecond), Action: op.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: actorKind, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "passkey", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "passkey", "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
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
		result, err = coordinator.Abort(w, err)
	} else {
		result, err = coordinator.Commit(w, provisional)
	}
	return result, err
}

func (s *registrationStore) Recover(ctx context.Context, r webauthn.RecoveryRequest) (identity.CommitOutcome, error) {
	if r.Operation != webauthn.BeginRegistrationOperation && r.Operation != webauthn.RegistrationOperation {
		return identity.CommitOutcomeInvalid, webauthn.Invalid{Field: "test_recovery"}
	}
	p := &registrationOwner{store: s.Store}
	coordinator, _, err := s.coordinator(p)
	if err != nil {
		return identity.CommitOutcomeUnknown, err
	}
	op := registrationOperation(r.Operation == webauthn.RegistrationOperation)
	q := identity.RecoveryQuery{CommandID: r.Context.CommandID, TenantID: r.Context.TenantID, UserID: r.Context.UserID, ActorID: r.Context.ActorID, ActorKind: authorization.SubjectUser, OperationID: op.OperationID, RecordID: string(r.Context.CommandID)}
	caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(q.ActorID), Kind: q.ActorKind}, Tenant: authorization.TenantID(q.TenantID), Action: authorization.Action(q.OperationID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(q.UserID)}}}
	if s.signupFlow != "" {
		q.UserID, q.AnonymousFlowID, q.ActorKind = "", s.signupFlow, authorization.SubjectServiceAccount
		caller.Request.Subject.Kind = q.ActorKind
		caller.Request.Resource.Type, caller.Request.Resource.ID = "identity.anonymous-flow", authorization.ResourceID(s.signupFlow)
	}
	result, err := coordinator.RecoverCommand(ctx, q, caller)
	return result.Outcome, err
}
func (s *registrationStore) CreateCeremony(ctx context.Context, c webauthn.CeremonyCreation) (webauthn.CeremonyRecord, webauthn.Challenge, identity.CommitOutcome, error) {
	p, err := s.Store.RegistrationCreation(c)
	if s.signupFlow != "" {
		p, err = s.Store.SignupRegistrationCreation(c, s.signupFlow)
	}
	if err != nil {
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, identity.CommitOutcomeInvalid, err
	}
	defer p.Discard()
	i, _ := c.Intent()
	fields, _ := p.Fields()
	result, runErr := s.execute(ctx, &registrationOwner{creation: p}, i.Context, fields)
	record, challenge, err := p.Result(result)
	if runErr != nil {
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, result.Outcome, runErr
	}
	return record, challenge, result.Outcome, err
}
func (s *registrationStore) FinalizeRegistration(ctx context.Context, t webauthn.RegistrationTransition) (webauthn.Credential, identity.CommitOutcome, error) {
	p, err := s.Store.RegistrationFinalization(t)
	if s.signupFlow != "" {
		p, err = s.Store.SignupRegistrationFinalization(t, s.signupFlow)
	}
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	m, _ := t.Mutation()
	fields, _ := p.Fields()
	result, runErr := s.execute(ctx, &registrationOwner{finalization: p}, m.Context, fields)
	credential, err := p.Result(result)
	if runErr != nil {
		return webauthn.Credential{}, result.Outcome, runErr
	}
	return credential, result.Outcome, err
}

func TestSignupRegistrationParticipationPostgres(t *testing.T) {
	ctx, pool, config, native := nativeFixture(t)
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE participation_metadata(command_id text PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	store := &registrationStore{Store: native, pool: pool, config: config, signupFlow: "original-signup-flow"}
	key, _ := webauthn.NewChallengeDigestKey(bytes.Repeat([]byte{61}, 32))
	svc, err := webauthn.New(webauthn.Config{TenantID: "tenant-a", RelyingParty: webauthn.RelyingParty{ID: "example.com", Name: "Signup", Origins: []string{"https://login.example.com"}, Version: 1}, ChallengeKey: key, MaximumDuration: 10 * time.Second}, webauthn.Dependencies{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	fresh := func() webauthn.CeremonyContext {
		id, _ := identity.NewCommandID()
		return webauthn.CeremonyContext{CommandID: id, TenantID: "tenant-a", UserID: "prospective-user", ActorID: "signup-service", CorrelationID: "signup-participation"}
	}
	options, err := svc.BeginRegistration(ctx, webauthn.BeginRegistrationRequest{Context: fresh(), UserHandle: bytes.Repeat([]byte{62}, 32), Origin: "https://login.example.com", ResidentKeyRequired: true})
	if err != nil {
		t.Fatal("real signup options without a durable identity", err)
	}
	assertCounts := func(users, handles, credentials int) {
		t.Helper()
		var actual [3]int
		if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users WHERE user_id='prospective-user'),(SELECT count(*) FROM webauthn.user_handles WHERE user_id='prospective-user'),(SELECT count(*) FROM webauthn.credentials WHERE user_id='prospective-user')`).Scan(&actual[0], &actual[1], &actual[2]); err != nil || actual != [3]int{users, handles, credentials} {
			t.Fatal("unexpected committed signup state", actual, err)
		}
		var protected [5]int
		if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM webauthn.ceremonies),(SELECT count(*) FROM webauthn.effects),(SELECT count(*) FROM participation_metadata),(SELECT count(*) FROM audit.records WHERE outcome=$1),(SELECT count(*) FROM public.outbox_messages)`, int(audit.OutcomeSucceeded)).Scan(&protected[0], &protected[1], &protected[2], &protected[3], &protected[4]); err != nil || protected != [5]int{1, 1 + credentials, 1 + credentials, 1 + credentials, 1 + credentials} {
			t.Fatal("signup effects did not commit or roll back together", protected, err)
		}
	}
	assertCounts(0, 0, 0)
	for _, mismatch := range []string{"scope", "intent", "actor", "actor-kind", "flow", "pending-user", "missing-user", "typed-user", "mixed-user", "command", "schema"} {
		store.invalidParent = mismatch
		if denied, err := svc.BeginRegistration(ctx, webauthn.BeginRegistrationRequest{Context: fresh(), UserHandle: bytes.Repeat([]byte{62}, 32), Origin: "https://login.example.com", ResidentKeyRequired: true}); err == nil {
			t.Fatal("different parent accepted signup options", mismatch)
		} else if _, ok := denied.Ceremony(); ok {
			t.Fatal("different parent exposed signup options", mismatch)
		}
		assertCounts(0, 0, 0)
	}
	store.invalidParent = ""
	record, _ := options.Ceremony()
	challenge := optionChallenge(t, ctx, options.TransferJSON)
	private, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	response := registrationResponse(t, private, bytes.Repeat([]byte{83}, 32), challenge, 0x45, 0)
	request := func() webauthn.VerifyRegistrationRequest {
		return webauthn.VerifyRegistrationRequest{Context: fresh(), CeremonyID: record.ID, Origin: "https://login.example.com", ExpectedVersion: 1, Response: response}
	}
	bad := request()
	bad.Response = registrationResponse(t, private, bytes.Repeat([]byte{83}, 32), challenge, 0x41, 0)
	if verified, err := svc.VerifyRegistration(ctx, bad); err == nil {
		t.Fatal("non-UV registration admitted")
	} else if _, ok := verified.Credential(); ok {
		t.Fatal("non-UV result revealed")
	}
	assertCounts(0, 0, 0)
	store.signupFlow = "other-original-flow"
	if _, err := svc.VerifyRegistration(ctx, request()); err == nil {
		t.Fatal("stored ceremony reinterpreted under another signup flow")
	}
	assertCounts(0, 0, 0)
	store.signupFlow = "original-signup-flow"
	for _, failure := range []string{"foreign", "apply", "commit", "flow-fence", "active-fence"} {
		store.failApply, store.failCommit = failure == "apply", failure == "commit"
		store.foreign = failure == "foreign"
		store.tamperSignup = failure
		if verified, err := svc.VerifyRegistration(ctx, request()); err == nil {
			t.Fatal("failed parent committed", failure)
		} else if _, ok := verified.Credential(); ok {
			t.Fatal("failed parent exposed credential", failure)
		}
		assertCounts(0, 0, 0)
	}
	store.failApply, store.failCommit, store.foreign = false, false, false
	store.tamperSignup = ""
	verified, err := svc.VerifyRegistration(ctx, request())
	if err != nil {
		t.Fatal("real UV signup finalization", err)
	}
	if credential, ok := verified.Credential(); !ok || credential.UserID != "prospective-user" {
		t.Fatal("finalized signup credential missing")
	}
	assertCounts(1, 1, 1)
	if _, err := svc.VerifyRegistration(ctx, request()); err == nil {
		t.Fatal("signup ceremony replay accepted")
	}
	assertCounts(1, 1, 1)
}

func TestSignupRegistrationUnknownPostgres(t *testing.T) {
	ctx, pool, config, native := nativeFixture(t)
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE participation_metadata(command_id text PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
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
	cutNative, err := webauthnpg.New(cutPool, webauthnpg.Config{Coordinator: config, PolicyID: "participation-test", PolicyVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	key, _ := webauthn.NewChallengeDigestKey(bytes.Repeat([]byte{61}, 32))
	serviceConfig := webauthn.Config{TenantID: "tenant-a", RelyingParty: webauthn.RelyingParty{ID: "example.com", Name: "Signup", Origins: []string{"https://login.example.com"}, Version: 1}, ChallengeKey: key, MaximumDuration: 10 * time.Second}
	store := &registrationStore{Store: cutNative, pool: cutPool, config: config, signupFlow: "original-signup-flow"}
	svc, err := webauthn.New(serviceConfig, webauthn.Dependencies{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	restartedStore := &registrationStore{Store: native, pool: pool, config: config, signupFlow: store.signupFlow}
	restarted, err := webauthn.New(serviceConfig, webauthn.Dependencies{Store: restartedStore})
	if err != nil {
		t.Fatal(err)
	}
	fresh := func() webauthn.CeremonyContext {
		id, _ := identity.NewCommandID()
		return webauthn.CeremonyContext{CommandID: id, TenantID: "tenant-a", UserID: "prospective-user", ActorID: "signup-service", CorrelationID: "signup-unknown"}
	}
	original := webauthn.BeginRegistrationRequest{Context: fresh(), UserHandle: bytes.Repeat([]byte{62}, 32), Origin: "https://login.example.com", ResidentKeyRequired: true}
	cut.remaining.Store(2)
	options, err := svc.BeginRegistration(ctx, original)
	var unknown webauthn.UnknownCommit
	if !errors.As(err, &unknown) || !cut.cut.Load() {
		t.Fatal("signup options acknowledgement loss not unknown", err)
	}
	if _, ok := options.Ceremony(); ok {
		t.Fatal("unknown signup options revealed")
	}
	if outcome, err := restarted.Recover(ctx, webauthn.RecoveryRequest{Context: original.Context, Operation: webauthn.BeginRegistrationOperation}); err != nil || outcome != identity.CommitOutcomeCommitted {
		t.Fatal("original signup options not recovered", err)
	}
	if retry, err := restarted.BeginRegistration(ctx, original); err == nil {
		t.Fatal("signup challenge reissued after unknown commit")
	} else if err := retry.TransferJSON(ctx, func(context.Context, []byte) error { t.Fatal("unknown challenge revealed again"); return nil }); err == nil {
		t.Fatal("signup replay retained challenge custody")
	}
	var users int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.users WHERE user_id='prospective-user'`).Scan(&users); err != nil || users != 0 {
		t.Fatal("unknown options created an identity", err)
	}
	original.Context = fresh()
	options, err = svc.BeginRegistration(ctx, original)
	if err != nil {
		t.Fatal(err)
	}
	record, _ := options.Ceremony()
	challenge := optionChallenge(t, ctx, options.TransferJSON)
	private, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	request := webauthn.VerifyRegistrationRequest{Context: fresh(), CeremonyID: record.ID, Origin: original.Origin, ExpectedVersion: 1, Response: registrationResponse(t, private, bytes.Repeat([]byte{84}, 32), challenge, 0x45, 0)}
	cut.cut.Store(false)
	cut.remaining.Store(2)
	if verified, err := svc.VerifyRegistration(ctx, request); !errors.As(err, &unknown) || !cut.cut.Load() {
		t.Fatal("signup verification acknowledgement loss not unknown", err)
	} else if _, ok := verified.Credential(); ok {
		t.Fatal("unknown signup authenticated")
	}
	if outcome, err := restarted.Recover(ctx, webauthn.RecoveryRequest{Context: request.Context, Operation: webauthn.RegistrationOperation, CredentialID: bytes.Repeat([]byte{84}, 32)}); err != nil || outcome != identity.CommitOutcomeCommitted {
		t.Fatal("original signup verification not recovered", err)
	}
	if verified, err := restarted.VerifyRegistration(ctx, request); err == nil {
		t.Fatal("signup recovery reissued verification")
	} else if _, ok := verified.Credential(); ok {
		t.Fatal("signup recovery authenticated")
	}
	var committed [4]int
	if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users WHERE user_id='prospective-user'),(SELECT count(*) FROM webauthn.user_handles),(SELECT count(*) FROM webauthn.credentials),(SELECT count(*) FROM webauthn.ceremonies WHERE signup_user_id IS NULL AND signup_flow_id='original-signup-flow' AND user_id='prospective-user' AND consumed_by IS NOT NULL)`).Scan(&committed[0], &committed[1], &committed[2], &committed[3]); err != nil || committed != [4]int{1, 1, 1, 1} {
		t.Fatal("unknown signup lost atomic persisted effects", committed, err)
	}
}

func TestRegistrationParticipationPostgres(t *testing.T) {
	ctx, pool, config, native := nativeFixture(t)
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE participation_metadata(command_id text PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	store := &registrationStore{Store: native, pool: pool, config: config}
	key, _ := webauthn.NewChallengeDigestKey(bytes.Repeat([]byte{61}, 32))
	serviceConfig := webauthn.Config{TenantID: "tenant-a", RelyingParty: webauthn.RelyingParty{ID: "example.com", Name: "Participant", Origins: []string{"https://login.example.com"}, Version: 1}, ChallengeKey: key, MaximumDuration: 10 * time.Second}
	svc, err := webauthn.New(serviceConfig, webauthn.Dependencies{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	fresh := func() webauthn.CeremonyContext {
		id, _ := identity.NewCommandID()
		return webauthn.CeremonyContext{CommandID: id, TenantID: "tenant-a", UserID: "user-a", ActorID: "user-a", CorrelationID: "participation"}
	}
	begin := func() (webauthn.RegistrationOptions, error) {
		return svc.BeginRegistration(ctx, webauthn.BeginRegistrationRequest{Context: fresh(), UserHandle: bytes.Repeat([]byte{62}, 32), Origin: "https://login.example.com", ResidentKeyRequired: true})
	}
	counts := func() [6]int {
		var n [6]int
		if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM webauthn.ceremonies),(SELECT count(*) FROM webauthn.credentials),(SELECT count(*) FROM webauthn.effects),(SELECT count(*) FROM participation_metadata),(SELECT count(*) FROM audit.records WHERE outcome=$1),(SELECT count(*) FROM public.outbox_messages)`, int(audit.OutcomeSucceeded)).Scan(&n[0], &n[1], &n[2], &n[3], &n[4], &n[5]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	for _, failure := range []string{"foreign", "apply", "commit"} {
		t.Run("creation-"+failure, func(t *testing.T) {
			before := counts()
			store.foreign, store.failApply, store.failCommit = failure == "foreign", failure == "apply", failure == "commit"
			options, err := begin()
			if err == nil {
				t.Fatal("failed parent returned options")
			}
			if _, ok := options.Ceremony(); ok {
				t.Fatal("failed parent exposed ceremony")
			}
			if after := counts(); after != before {
				t.Fatal("failed parent retained creation/mapping/effect")
			}
		})
	}
	store.foreign, store.failApply, store.failCommit = false, false, false
	for _, mismatch := range []string{"scope", "intent"} {
		t.Run("creation-parent-"+mismatch, func(t *testing.T) {
			// First prove the same real producer/store accepts the unchanged
			// profile, so a configuration failure cannot satisfy the denial.
			control, err := begin()
			if err != nil {
				t.Fatal("valid creation control", err)
			}
			if err = control.TransferJSON(ctx, func(context.Context, []byte) error { return nil }); err != nil {
				t.Fatal("valid creation control delivery", err)
			}
			before := counts()
			store.invalidParent = mismatch
			defer func() { store.invalidParent = "" }()
			options, err := begin()
			if err == nil {
				t.Fatal("different parent " + mismatch + " accepted real creation input")
			}
			if _, ok := options.Ceremony(); ok {
				t.Fatal("parent mismatch exposed creation")
			}
			if err := options.TransferJSON(ctx, func(context.Context, []byte) error { t.Fatal("parent mismatch revealed challenge"); return nil }); err == nil {
				t.Fatal("parent mismatch returned challenge custody")
			}
			if counts() != before {
				t.Fatal("parent mismatch committed creation, parent, audit or outbox effects")
			}
		})
	}
	private, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for index, failure := range []string{"apply", "commit", "success", "parent-scope", "parent-intent"} {
		t.Run("registration-"+failure, func(t *testing.T) {
			options, err := begin()
			if err != nil {
				t.Fatal(err)
			}
			record, _ := options.Ceremony()
			challenge := optionChallenge(t, ctx, options.TransferJSON)
			before := counts()
			store.failApply, store.failCommit = failure == "apply", failure == "commit"
			switch failure {
			case "parent-scope":
				store.invalidParent = "scope"
			case "parent-intent":
				store.invalidParent = "intent"
			}
			request := webauthn.VerifyRegistrationRequest{Context: fresh(), CeremonyID: record.ID, Origin: "https://login.example.com", ExpectedVersion: 1, Response: registrationResponse(t, private, bytes.Repeat([]byte{byte(70 + index)}, 32), challenge, 0x45, 0)}
			verified, err := svc.VerifyRegistration(ctx, request)
			if failure != "success" {
				if err == nil {
					t.Fatal("failed parent returned verification")
				}
				if _, ok := verified.Credential(); ok {
					t.Fatal("uncommitted protocol evidence exposed")
				}
				if counts() != before {
					t.Fatal("failed parent retained credential/mapping/effect")
				}
				var consumed bool
				if err := pool.Raw().QueryRow(ctx, `SELECT consumed_by IS NOT NULL FROM webauthn.ceremonies WHERE ceremony_id=$1`, record.ID).Scan(&consumed); err != nil || consumed {
					t.Fatal("failed parent consumed ceremony", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if _, ok := verified.Credential(); !ok {
					t.Fatal("committed registration missing")
				}
				after := counts()
				if after != [6]int{before[0], before[1] + 1, before[2] + 1, before[3] + 1, before[4] + 1, before[5] + 1} {
					t.Fatal("protocol/parent did not commit together")
				}
				var purpose string
				if err := pool.Raw().QueryRow(ctx, `SELECT purpose FROM webauthn.effects WHERE command_id=$1`, string(request.Context.CommandID)).Scan(&purpose); err != nil || purpose != "identity.passkey.register-verify" {
					t.Fatal("effect detached from actual parent", err)
				}
				var replay webauthn.Replay
				if again, e := svc.VerifyRegistration(ctx, request); !errors.As(e, &replay) {
					t.Fatal("replay reissued verification", e)
				} else if _, ok := again.Credential(); ok {
					t.Fatal("replay authenticated")
				}
			}
			store.failApply, store.failCommit = false, false
			store.invalidParent = ""
		})
	}
	t.Run("withdrawn-current-user", func(t *testing.T) {
		options, err := begin()
		if err != nil {
			t.Fatal(err)
		}
		record, _ := options.Ceremony()
		challenge := optionChallenge(t, ctx, options.TransferJSON)
		before := counts()
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='suspended' WHERE tenant_id='tenant-a' AND user_id='user-a'`); err != nil {
			t.Fatal(err)
		}
		request := webauthn.VerifyRegistrationRequest{Context: fresh(), CeremonyID: record.ID, Origin: "https://login.example.com", ExpectedVersion: 1, Response: registrationResponse(t, private, bytes.Repeat([]byte{80}, 32), challenge, 0x45, 0)}
		if verified, err := svc.VerifyRegistration(ctx, request); err == nil {
			t.Fatal("withdrawn user enrolled")
		} else if _, ok := verified.Credential(); ok {
			t.Fatal("withdrawn user obtained verification")
		}
		if options, err := begin(); err == nil {
			t.Fatal("withdrawn user created ceremony")
		} else if _, ok := options.Ceremony(); ok {
			t.Fatal("withdrawn user obtained options")
		}
		if counts() != before {
			t.Fatal("withdrawn user retained protected effects")
		}
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='active' WHERE tenant_id='tenant-a' AND user_id='user-a'`); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("concurrent-completion-single-winner", func(t *testing.T) {
		options, err := begin()
		if err != nil {
			t.Fatal(err)
		}
		record, _ := options.Ceremony()
		challenge := optionChallenge(t, ctx, options.TransferJSON)
		before := counts()
		response := registrationResponse(t, private, bytes.Repeat([]byte{81}, 32), challenge, 0x45, 0)
		results := make(chan bool, 2)
		for range 2 {
			request := webauthn.VerifyRegistrationRequest{Context: fresh(), CeremonyID: record.ID, Origin: "https://login.example.com", ExpectedVersion: 1, Response: response}
			go func() {
				verified, err := svc.VerifyRegistration(ctx, request)
				_, ok := verified.Credential()
				results <- err == nil && ok
			}()
		}
		winners := 0
		for range 2 {
			if <-results {
				winners++
			}
		}
		if winners != 1 {
			t.Fatal("concurrent ceremony completion had", winners, "winners")
		}
		if counts() != [6]int{before[0], before[1] + 1, before[2] + 1, before[3] + 1, before[4] + 1, before[5] + 1} {
			t.Fatal("concurrent completion duplicated effects")
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
		cutNative, err := webauthnpg.New(cutPool, webauthnpg.Config{Coordinator: config, PolicyID: "participation-test", PolicyVersion: 1})
		if err != nil {
			t.Fatal(err)
		}
		cutStore := &registrationStore{Store: cutNative, pool: cutPool, config: config}
		cutService, err := webauthn.New(serviceConfig, webauthn.Dependencies{Store: cutStore})
		if err != nil {
			t.Fatal(err)
		}
		original := webauthn.BeginRegistrationRequest{Context: fresh(), UserHandle: bytes.Repeat([]byte{62}, 32), Origin: "https://login.example.com", ResidentKeyRequired: true}
		cut.remaining.Store(2)
		options, err := cutService.BeginRegistration(ctx, original)
		var unknown webauthn.UnknownCommit
		if !errors.As(err, &unknown) || !cut.cut.Load() {
			t.Fatal("lost creation commit not unknown", err)
		}
		if _, ok := options.Ceremony(); ok {
			t.Fatal("unknown creation exposed options")
		}
		// A new native service uses only the original journal scope, not a new
		// challenge, session, proof, password or current authentication event.
		restartedNative, err := webauthnpg.New(pool, webauthnpg.Config{Coordinator: config, PolicyID: "participation-test", PolicyVersion: 1})
		if err != nil {
			t.Fatal(err)
		}
		restartedStore := &registrationStore{Store: restartedNative, pool: pool, config: config}
		restarted, err := webauthn.New(serviceConfig, webauthn.Dependencies{Store: restartedStore})
		if err != nil {
			t.Fatal(err)
		}
		before := counts()
		if outcome, err := restarted.Recover(ctx, webauthn.RecoveryRequest{Context: original.Context, Operation: webauthn.BeginRegistrationOperation}); err != nil || outcome != identity.CommitOutcomeCommitted {
			t.Fatal("original creation not recovered", err)
		}
		retry, err := restarted.BeginRegistration(ctx, original)
		var replay webauthn.Replay
		if !errors.As(err, &replay) {
			t.Fatal("lost original challenge was recreated", err)
		}
		if err := retry.TransferJSON(ctx, func(context.Context, []byte) error { t.Fatal("lost challenge re-revealed"); return nil }); err == nil {
			t.Fatal("replay challenge became available")
		}
		if counts() != before {
			t.Fatal("recovery/replay repeated creation")
		}
		// Completion loses its actual server COMMIT acknowledgement separately.
		original.Context = fresh()
		options, err = cutService.BeginRegistration(ctx, original)
		if err != nil {
			t.Fatal(err)
		}
		record, _ := options.Ceremony()
		challenge := optionChallenge(t, ctx, options.TransferJSON)
		request := webauthn.VerifyRegistrationRequest{Context: fresh(), CeremonyID: record.ID, Origin: original.Origin, ExpectedVersion: 1, Response: registrationResponse(t, private, bytes.Repeat([]byte{82}, 32), challenge, 0x45, 0)}
		cut.cut.Store(false)
		cut.remaining.Store(2)
		verified, err := cutService.VerifyRegistration(ctx, request)
		if !errors.As(err, &unknown) || !cut.cut.Load() {
			t.Fatal("lost completion commit not unknown", err)
		}
		if _, ok := verified.Credential(); ok {
			t.Fatal("unknown completion authenticated")
		}
		before = counts()
		if outcome, err := restarted.Recover(ctx, webauthn.RecoveryRequest{Context: request.Context, Operation: webauthn.RegistrationOperation, CredentialID: bytes.Repeat([]byte{82}, 32)}); err != nil || outcome != identity.CommitOutcomeCommitted {
			t.Fatal("original completion not recovered", err)
		}
		if again, err := restarted.VerifyRegistration(ctx, request); !errors.As(err, &replay) {
			t.Fatal("recovered completion reauthenticated", err)
		} else if _, ok := again.Credential(); ok {
			t.Fatal("recovery issued verification")
		}
		foreign := request.Context
		foreign.ActorID = "foreign-user"
		if outcome, _ := restarted.Recover(ctx, webauthn.RecoveryRequest{Context: foreign, Operation: webauthn.RegistrationOperation, CredentialID: bytes.Repeat([]byte{82}, 32)}); outcome == identity.CommitOutcomeCommitted {
			t.Fatal("foreign actor recovered original")
		}
		if counts() != before {
			t.Fatal("completion recovery/replay repeated effects")
		}
		// Losing reservation acknowledgement leaves no domain transaction. The
		// original journal alone fences retry; once its real lease is expired,
		// every native owner (including this participant) must reconcile absence.
		original.Context = fresh()
		cut.cut.Store(false)
		cut.remaining.Store(1)
		if options, err := cutService.BeginRegistration(ctx, original); !errors.As(err, &unknown) {
			t.Fatal("lost reservation was not unknown", err)
		} else if _, ok := options.Ceremony(); ok {
			t.Fatal("unknown reservation exposed options")
		}
		commandID, _ := base64.RawURLEncoding.DecodeString(string(original.Context.CommandID))
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET created_at=clock_timestamp()-interval '3 seconds',heartbeat_at=clock_timestamp()-interval '2 seconds',updated_at=clock_timestamp()-interval '2 seconds',lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, commandID); err != nil {
			t.Fatal(err)
		}
		// The owning kernel deliberately pairs its terminal noncommit receipt
		// with UnavailableError: historical absence is not successful execution.
		var unavailable identity.UnavailableError
		if outcome, err := restarted.Recover(ctx, webauthn.RecoveryRequest{Context: original.Context, Operation: webauthn.BeginRegistrationOperation}); !errors.As(err, &unavailable) || outcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("original pending command did not reconcile absence", err)
		}
		if counts() != before {
			t.Fatal("noncommit recovery created protocol or parent state")
		}
	})
}
