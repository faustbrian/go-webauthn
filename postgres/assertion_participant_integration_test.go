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
	"strconv"
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
	removalFinalization                      *webauthnpg.RemovalAssertionFinalization
	store                                    *webauthnpg.Store
	discoverable                             bool
	update                                   bool
	removal                                  bool
	recoveryStatus                           *kernel.RecoveryStatus
	remainingID                              []byte
	lifecycle                                kernel.LifecyclePlan
	afterApply                               func(context.Context, kernel.Work, identity.Command) error
	failApply, failCommit, foreign, withdraw bool
}

func (*assertionOwner) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}
}
func (p *assertionOwner) FeatureOperations() []identity.FeatureOperation {
	if p.removal {
		return []identity.FeatureOperation{removalAssertionOperation(false), removalAssertionOperation(true)}
	}
	if p.update {
		return []identity.FeatureOperation{updateAssertionOperation(false), updateAssertionOperation(true)}
	}
	begin := assertionOperation(false)
	if p.discoverable {
		begin.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
	}
	return []identity.FeatureOperation{begin, assertionOperation(true)}
}
func assertionOperation(finish bool) identity.FeatureOperation {
	id := "identity.passkey.signin-options"
	if finish {
		id = "identity.passkey.signin-verify"
	}
	return identity.FeatureOperation{Owner: "passkey", OperationID: id, SchemaID: id + ".native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}
func updateAssertionOperation(finish bool) identity.FeatureOperation {
	op := identity.FeatureOperation{Owner: "passkey", OperationID: "identity.passkey.update", SchemaID: "identity.passkey.update.options-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	if finish {
		op.OperationID, op.SchemaID = "identity.passkey.update", "identity.passkey.update.assertion-v1"
	}
	return op
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
	if p.removalFinalization != nil {
		return p.removalFinalization.Validate(c, plan)
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
	} else if p.removalFinalization != nil {
		err = p.removalFinalization.Apply(ctx, w, owner, c)
	} else {
		err = p.finalization.Apply(ctx, w, owner, c)
	}
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.removalFinalization != nil && p.remainingID != nil {
		if _, err := p.removalFinalization.CheckRemainingCredential(ctx, w, owner, c, p.remainingID); err != nil {
			return identity.FeatureReceipt{}, err
		}
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
	if p.afterApply != nil {
		if err := p.afterApply(ctx, w, c); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	s, _ := c.Feature()
	return identity.FeatureReceipt{Operation: s.Operation, BeforeVersion: p.lifecycle.BeforeVersion, AfterVersion: p.lifecycle.AfterVersion}, nil
}
func (p *assertionOwner) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p.failCommit {
		return identity.ForbiddenError{}
	}
	if p.creation != nil {
		return p.creation.Check(ctx, w, p, c)
	}
	if p.removalFinalization != nil {
		if p.remainingID != nil {
			if _, err := p.removalFinalization.CheckRemainingCredential(ctx, w, p, c, p.remainingID); err != nil {
				return err
			}
		}
		return p.removalFinalization.Check(ctx, w, p, c)
	}
	return p.finalization.Check(ctx, w, p, c)
}
func (p *assertionOwner) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	recoverProtocol := p.store.RecoverAssertion
	recoverOther := p.store.RecoverUpdateAssertion
	if p.update {
		recoverProtocol = p.store.RecoverUpdateAssertion
		recoverOther = p.store.RecoverAssertion
	}
	if p.removal {
		recoverProtocol = p.store.RecoverRemovalAssertion
	}
	if _, err := recoverOther(ctx, w, p); err == nil {
		return kernel.RecoveryUnknown, errors.New("foreign assertion profile admitted recovery")
	}
	if _, err := recoverProtocol(ctx, w, &assertionOwner{}); err == nil {
		return kernel.RecoveryUnknown, errors.New("foreign assertion owner admitted recovery")
	}
	protocol, err := recoverProtocol(ctx, w, p)
	if p.recoveryStatus != nil {
		*p.recoveryStatus = protocol
	}
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
	preauth                                  bool
	discoverable                             bool
	update                                   bool
	removal                                  bool
	removalTarget                            webauthnpg.RemovalRequest
	generationOffset                         time.Duration
	afterApply                               func(context.Context, kernel.Work, identity.Command) error
	failApply, failCommit, foreign, withdraw bool
	invalidParent                            string
	observeCreation                          func(*webauthnpg.AssertionCreation, identity.CommandResult)
	observeFinalization                      func(*webauthnpg.AssertionFinalization, identity.CommandResult)
	observeTransition                        func(webauthn.AssertionTransition)
	finalResult                              func(identity.CommandResult) identity.CommandResult
	observeRemoval                           func(*webauthnpg.RemovalAssertionFinalization, identity.CommandResult)
	recoveredProtocol                        kernel.RecoveryStatus
	remainingID                              []byte
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
	p.discoverable = s.discoverable
	p.update = s.update
	p.removal = s.removal
	if s.update {
		op = updateAssertionOperation(p.finalization != nil)
	}
	if s.removal {
		op = removalAssertionOperation(p.removalFinalization != nil)
	}
	lifecycle := kernel.LifecyclePlan{EventType: op.OperationID + ".v1", AfterVersion: 1}
	if s.update {
		lifecycle.EventType = "passkey.reauthentication.started.v1"
		if p.finalization != nil {
			lifecycle = kernel.LifecyclePlan{EventType: "identity.passkey.rename_credential", BeforeVersion: 7, AfterVersion: 8}
		}
	}
	if s.removal {
		lifecycle.EventType = "passkey.reauthentication.started.v1"
		if p.removalFinalization != nil {
			lifecycle = kernel.LifecyclePlan{EventType: "identity.passkey.remove_credential", BeforeVersion: 7, AfterVersion: 8}
		}
	}
	if s.discoverable && p.finalization == nil {
		op.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
	}
	b := identity.CommandBinding{CommandID: scope.CommandID, TenantID: scope.TenantID, UserID: scope.UserID, ActorID: scope.ActorID, ActorKind: authorization.SubjectUser, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "assertion-participation-test", PolicyVersion: 1, CorrelationID: scope.CorrelationID, RecordID: string(scope.CommandID)}
	b.AnonymousFlowID = scope.AnonymousFlowID
	if s.preauth {
		if p.finalization == nil {
			b.ActorKind = authorization.SubjectServiceAccount
		} else {
			b.ActorID = identity.ActorID(scope.UserID)
		}
	}
	switch s.invalidParent {
	case "profile":
		if s.removal {
			op.SchemaID = "identity.passkey.delete.native-v1"
			b.SchemaID = op.SchemaID
		}
	case "scope":
		b.CorrelationID = "different-valid-parent-correlation"
	case "tenant":
		b.TenantID = "tenant-b"
	case "user":
		b.UserID, b.ActorID = "user-b", "user-b"
	case "actor":
		b.ActorID = "other-user"
	case "kind":
		if b.ActorKind == authorization.SubjectUser {
			b.ActorKind = authorization.SubjectServiceAccount
		} else {
			b.ActorKind = authorization.SubjectUser
		}
	case "flow":
		b.AnonymousFlowID = "different-original-flow"
	case "intent":
		fields[0].Value.Bytes = bytes.Clone(fields[0].Value.Bytes)
		fields[0].Value.Bytes[0] ^= 1
	case "lifecycle-zero":
		lifecycle.BeforeVersion, lifecycle.AfterVersion = 0, 1
	case "lifecycle-event":
		lifecycle.EventType = "identity.passkey.signin-verify.v1"
	case "lifecycle-jump":
		lifecycle.AfterVersion++
	case "lifecycle-index":
		lifecycle.EventIndex = 1
	}
	p.lifecycle = lifecycle
	c, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields})
	if err != nil {
		return identity.CommandResult{}, err
	}
	p.command, p.store, p.failApply, p.failCommit, p.foreign, p.withdraw = c, s.Store, s.failApply, s.failCommit, s.foreign, s.withdraw
	p.afterApply = s.afterApply
	p.remainingID = bytes.Clone(s.remainingID)
	coordinator, r, err := s.coordinator(p)
	if err != nil {
		return identity.CommandResult{}, err
	}
	builder, _ := audit.NewBuilder(audit.BuilderConfig{})
	actorKind := audit.ActorHuman
	if b.ActorKind == authorization.SubjectServiceAccount {
		actorKind = audit.ActorService
	}
	seed, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC().Truncate(time.Microsecond), Action: op.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: actorKind, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "passkey", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "passkey", "aggregate.id": b.RecordID, "aggregate.before_version": strconv.FormatUint(lifecycle.BeforeVersion, 10), "aggregate.after_version": strconv.FormatUint(lifecycle.AfterVersion, 10), "retention.class": "protected"}})
	if err != nil {
		return identity.CommandResult{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, op, "passkey", seed)
	if err != nil {
		return identity.CommandResult{}, err
	}
	plan, err := coordinator.PrepareCommandPlan(b, c, kernel.CommandPlan{Contributors: r.Descriptors(), SubjectType: "passkey", Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}, Lifecycle: &lifecycle, Audits: []kernel.AuditPlan{{EventType: op.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
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
		if err = p.creation.Generate(ctx, now.Add(s.generationOffset)); err != nil {
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
	create := s.Store.AssertionCreation
	if s.preauth {
		create = s.Store.PreauthAssertionCreation
	}
	if s.update {
		create = s.Store.UpdateAssertionCreation
	}
	if s.removal {
		create = s.Store.RemovalAssertionCreation
	}
	if s.invalidParent == "profile" {
		create = s.Store.UpdateAssertionCreation
		if s.update {
			create = s.Store.AssertionCreation
		}
	}
	p, err := create(c)
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
	if s.observeTransition != nil {
		s.observeTransition(t)
	}
	if s.removal {
		m, _ := t.Mutation()
		target := s.removalTarget
		target.Context = m.Context
		p, err := s.Store.RemovalAssertionFinalization(t, target)
		if err != nil {
			return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
		}
		fields, err := p.Fields()
		if err != nil {
			return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
		}
		result, runErr := s.execute(ctx, &assertionOwner{removalFinalization: p}, m.Context, fields)
		if s.finalResult != nil && result.Outcome == identity.CommitOutcomeCommitted {
			result = s.finalResult(result)
		}
		credential, err := p.Result(result)
		if s.observeRemoval != nil {
			s.observeRemoval(p, result)
		}
		if runErr != nil {
			return webauthn.Credential{}, result.Outcome, runErr
		}
		return credential, result.Outcome, err
	}
	finalize := s.Store.AssertionFinalization
	if s.preauth {
		finalize = s.Store.PreauthAssertionFinalization
	}
	if s.update {
		finalize = s.Store.UpdateAssertionFinalization
	}
	if s.invalidParent == "profile" {
		finalize = s.Store.UpdateAssertionFinalization
		if s.update {
			finalize = s.Store.AssertionFinalization
		}
	}
	p, err := finalize(t)
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	m, _ := t.Mutation()
	fields, _ := p.Fields()
	result, runErr := s.execute(ctx, &assertionOwner{finalization: p}, m.Context, fields)
	if s.finalResult != nil && result.Outcome == identity.CommitOutcomeCommitted {
		result = s.finalResult(result)
	}
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
	p := &assertionOwner{store: s.Store, update: s.update, removal: s.removal, recoveryStatus: &s.recoveredProtocol}
	coordinator, _, err := s.coordinator(p)
	if err != nil {
		return identity.CommitOutcomeUnknown, err
	}
	op := assertionOperation(r.Operation == webauthn.AssertionOperation)
	if s.update {
		op = updateAssertionOperation(r.Operation == webauthn.AssertionOperation)
	}
	if s.removal {
		op = removalAssertionOperation(r.Operation == webauthn.AssertionOperation)
	}
	q := identity.RecoveryQuery{CommandID: r.Context.CommandID, TenantID: r.Context.TenantID, UserID: r.Context.UserID, ActorID: r.Context.ActorID, ActorKind: authorization.SubjectUser, OperationID: op.OperationID, RecordID: string(r.Context.CommandID)}
	if s.preauth {
		if r.Operation == webauthn.BeginAssertionOperation {
			q.ActorKind = authorization.SubjectServiceAccount
		} else {
			// A real parent authenticates the recovery caller separately. This
			// fixture checks that its exact human command still reconciles.
			if r.Context.ActorID != "ingress-service" {
				return identity.CommitOutcomeInvalid, webauthn.Denied{}
			}
			q.ActorID = identity.ActorID(r.Context.UserID)
		}
	}
	caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(q.ActorID), Kind: q.ActorKind}, Tenant: authorization.TenantID(q.TenantID), Action: authorization.Action(q.OperationID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(q.UserID)}}}
	result, err := coordinator.RecoverCommand(ctx, q, caller)
	return result.Outcome, err
}

func TestAssertionParticipationPostgres(t *testing.T) {
	testAssertionParticipationPostgres(t, false)
}

func TestPreauthAssertionParticipationPostgres(t *testing.T) {
	testAssertionParticipationPostgres(t, true)
}

func testAssertionParticipationPostgres(t *testing.T, preauth bool, updateProfile ...bool) {
	update := len(updateProfile) > 0 && updateProfile[0]
	testAssertionAlgorithmsPostgres(t, preauth, update, participantProfile{})
}

func testAssertionAlgorithmsPostgres(t *testing.T, preauth, update bool, profile participantProfile) {
	registrationResponse, assertionResponse := profile.registration, profile.assertion
	ctx, pool, config, native := nativeFixture(t)
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE assertion_participation_metadata(command_id text PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	store := &assertionStore{Store: native, pool: pool, config: config, preauth: preauth, update: update}
	key, _ := webauthn.NewChallengeDigestKey(bytes.Repeat([]byte{91}, 32))
	serviceConfig := webauthn.Config{TenantID: "tenant-a", RelyingParty: webauthn.RelyingParty{ID: "example.com", Name: "Assertion Participant", Origins: []string{"https://login.example.com"}, Version: 1}, ChallengeKey: key, MaximumDuration: 10 * time.Second}
	serviceConfig.Algorithms = profile.algorithms
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
	private := profile.key(t)
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
		scope := fresh()
		if preauth {
			scope.ActorID = "ingress-service"
		}
		return webauthn.BeginAssertionRequest{Context: scope, UserHandle: handle, Origin: "https://login.example.com", AllowedCredentials: [][]byte{id}}
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
		expanded.Algorithms = []webauthn.Algorithm{webauthn.ES256, -257}
		if _, err := webauthn.New(expanded, webauthn.Dependencies{Store: store}); err == nil {
			t.Fatal("unsupported RSA algorithm profile accepted")
		}
		request := beginRequest()
		request.Context.ActorID = "different-actor"
		if preauth {
			request.Context.ActorID = identity.ActorID(request.Context.UserID)
		}
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
	creationFailures := []string{"foreign", "apply", "commit", "withdraw", "scope", "tenant", "user", "actor", "kind", "intent", "profile", "lifecycle-jump"}
	if update {
		creationFailures = append(creationFailures, "lifecycle-event", "lifecycle-index")
	}
	for _, failure := range creationFailures {
		t.Run("creation-"+failure, func(t *testing.T) {
			before := counts()
			store.foreign, store.failApply, store.failCommit, store.withdraw = failure == "foreign", failure == "apply", failure == "commit", failure == "withdraw"
			if failure == "scope" || failure == "tenant" || failure == "user" || failure == "actor" || failure == "kind" || failure == "intent" || failure == "profile" || failure == "lifecycle-jump" || failure == "lifecycle-event" || failure == "lifecycle-index" {
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
		return webauthn.VerifyAssertionRequest{Context: beginRequest().Context, CeremonyID: r.ID, Origin: "https://login.example.com", ExpectedVersion: 1, ExpectedCredentialVersion: c.Version, Response: assertionResponse(t, private, id, handle, ch, 0x05, c.Counter+1)}
	}
	if update {
		for _, mismatch := range []string{"profile", "lifecycle", "target"} {
			t.Run("result-original-"+mismatch, func(t *testing.T) {
				request := newAssertion(t)
				store.finalResult = func(result identity.CommandResult) identity.CommandResult {
					r := *result.Feature
					result.Feature = &r
					switch mismatch {
					case "profile":
						r.Operation = assertionOperation(true)
						result.Binding.OperationID, result.Binding.SchemaID = r.Operation.OperationID, r.Operation.SchemaID
					case "lifecycle":
						r.BeforeVersion, r.AfterVersion = 8, 9
					case "target":
						result.Binding.RecordID = "different-original-target"
					}
					if err := result.Validate(); err != nil {
						t.Fatal("mismatch must remain a structurally valid receipt", err)
					}
					return result
				}
				defer func() { store.finalResult = nil }()
				if v, err := svc.VerifyAssertion(ctx, request); err == nil {
					t.Fatal("mismatched final parent receipt released verification")
				} else if _, ok := v.Credential(); ok {
					t.Fatal("mismatched receipt exposed credential")
				}
			})
		}
	}
	t.Run("original-protocol-actor-continuity", func(t *testing.T) {
		request := newAssertion(t)
		before := counts()
		request.Context.ActorID = "foreign-service"
		if preauth {
			request.Context.ActorID = identity.ActorID(request.Context.UserID)
		}
		if verified, err := svc.VerifyAssertion(ctx, request); err == nil {
			t.Fatal("root accepted different original ceremony actor")
		} else if _, ok := verified.Credential(); ok {
			t.Fatal("changed protocol actor exposed verification")
		}
		if counts() != before {
			t.Fatal("changed protocol actor retained effects")
		}
	})
	t.Run("finalization-copy-returns-once", func(t *testing.T) {
		request := newAssertion(t)
		store.observeTransition = func(transition webauthn.AssertionTransition) {
			mutation, err := transition.Mutation()
			if err != nil || mutation.Context.ActorID != request.Context.ActorID || mutation.Ceremony.Intent.Context.ActorID != request.Context.ActorID {
				t.Fatal("verified transition rewrote original protocol actor", err)
			}
			if preauth {
				if participant, err := native.AssertionFinalization(transition); err == nil || participant != nil {
					t.Fatal("self-user API implicitly accepted preauth transition")
				}
			} else if participant, err := native.PreauthAssertionFinalization(transition); err == nil || participant != nil {
				t.Fatal("preauth API implicitly accepted self-user transition")
			}
			wire, err := json.Marshal(mutation)
			if err != nil {
				t.Fatal(err)
			}
			var reconstructed webauthn.AssertionTransition
			if err := json.Unmarshal(wire, &reconstructed); err != nil {
				t.Fatal(err)
			}
			if participant, err := native.AssertionFinalization(reconstructed); err == nil || participant != nil {
				t.Fatal("reconstructed mutation supplied verifier custody")
			}
			if participant, err := native.PreauthAssertionFinalization(reconstructed); err == nil || participant != nil {
				t.Fatal("reconstructed mutation supplied preauth verifier custody")
			}
			if participant, err := native.UpdateAssertionFinalization(reconstructed); err == nil || participant != nil {
				t.Fatal("reconstructed mutation supplied update verifier custody")
			}
		}
		store.observeFinalization = func(p *webauthnpg.AssertionFinalization, result identity.CommandResult) {
			alias := *p
			if _, err := alias.Result(result); err == nil {
				t.Fatal("finalization alias reissued result")
			}
		}
		defer func() { store.observeFinalization, store.observeTransition = nil, nil }()
		if _, err := svc.VerifyAssertion(ctx, request); err != nil {
			t.Fatal(err)
		}
	})
	failures := []string{"foreign", "apply", "commit", "withdraw", "scope", "tenant", "user", "actor", "kind", "intent", "profile", "lifecycle-jump"}
	if update {
		failures = append(failures, "lifecycle-zero", "lifecycle-event", "lifecycle-index")
	}
	failures = append(failures, "success")
	for _, failure := range failures {
		t.Run("finalization-"+failure, func(t *testing.T) {
			request := newAssertion(t)
			before, c := counts(), current()
			store.foreign, store.failApply, store.failCommit, store.withdraw = failure == "foreign", failure == "apply", failure == "commit", failure == "withdraw"
			if failure == "scope" || failure == "tenant" || failure == "user" || failure == "actor" || failure == "kind" || failure == "intent" || failure == "profile" || failure == "lifecycle-jump" || failure == "lifecycle-zero" || failure == "lifecycle-event" || failure == "lifecycle-index" {
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
				expectedPurpose := "identity.passkey.signin-verify"
				if update {
					expectedPurpose = "identity.passkey.update"
				}
				if err := pool.Raw().QueryRow(ctx, `SELECT purpose FROM webauthn.effects WHERE command_id=$1`, string(request.Context.CommandID)).Scan(&purpose); err != nil || purpose != expectedPurpose {
					t.Fatal("effect detached from parent", err)
				}
				if update {
					lookup := webauthn.Lookup{Context: request.Context, RPID: "example.com", CeremonyID: request.CeremonyID}
					if snapshot, err := native.LoadCredential(ctx, lookup, id); err != nil || snapshot.Version != c.Version || snapshot.Counter != c.Counter {
						t.Fatal("exact self-user update retry lost original credential snapshot", err)
					}
					for _, mismatch := range []string{"actor", "command", "tenant", "user", "rp", "ceremony"} {
						foreign := lookup
						switch mismatch {
						case "actor":
							foreign.Context.ActorID = "ingress-service"
						case "command":
							foreign.Context.CommandID, _ = identity.NewCommandID()
						case "tenant":
							foreign.Context.TenantID = "other-tenant"
						case "user":
							foreign.Context.UserID = "other-user"
						case "rp":
							foreign.RPID = "other.example.com"
						case "ceremony":
							foreign.CeremonyID = "other-ceremony"
						}
						if snapshot, err := native.LoadCredential(ctx, foreign, id); err == nil && snapshot.Version == c.Version {
							t.Fatal("foreign update lookup selected original snapshot:", mismatch)
						}
					}
				}
				if preauth {
					var parentActor, protocolActor string
					if err := pool.Raw().QueryRow(ctx, `SELECT actor_id,ceremony->'Intent'->'Context'->>'ActorID' FROM webauthn.effects WHERE command_id=$1`, string(request.Context.CommandID)).Scan(&parentActor, &protocolActor); err != nil || parentActor != "user-a" || protocolActor != "ingress-service" {
						t.Fatal("human parent lost original service attribution", err)
					}
					lookup := webauthn.Lookup{Context: request.Context, RPID: "example.com", CeremonyID: request.CeremonyID}
					if snapshot, err := native.LoadCredential(ctx, lookup, id); err != nil || snapshot.Version != c.Version || snapshot.Counter != c.Counter {
						t.Fatal("exact service retry lost original credential snapshot", err)
					}
					foreign := lookup
					foreign.Context.ActorID = "foreign-service"
					if snapshot, err := native.LoadCredential(ctx, foreign, id); err == nil && snapshot.Version == c.Version {
						t.Fatal("foreign service selected original retry history")
					}
					foreign = lookup
					foreign.Context.CommandID, _ = identity.NewCommandID()
					if snapshot, err := native.LoadCredential(ctx, foreign, id); err == nil && snapshot.Version == c.Version {
						t.Fatal("foreign command selected original retry history")
					}
					var original []byte
					if err := pool.Raw().QueryRow(ctx, `SELECT ceremony FROM webauthn.effects WHERE command_id=$1`, string(request.Context.CommandID)).Scan(&original); err != nil {
						t.Fatal(err)
					}
					for _, defect := range []string{"kind", "tenant", "target", "rp", "handle", "anonymous", "actor"} {
						t.Run("retry-retained-"+defect, func(t *testing.T) {
							var retained webauthn.CeremonyRecord
							if err := json.Unmarshal(original, &retained); err != nil {
								t.Fatal(err)
							}
							switch defect {
							case "kind":
								retained.Intent.Kind = "create"
							case "tenant":
								retained.Intent.Context.TenantID = "other-tenant"
							case "target":
								retained.Intent.Context.UserID = "other-user"
							case "rp":
								retained.Intent.RPID = "other.example.com"
							case "handle":
								retained.Intent.UserHandle[0] ^= 1
							case "anonymous":
								retained.Intent.Context.AnonymousFlowID = "other-flow"
							case "actor":
								retained.Intent.Context.ActorID = "other-service"
							}
							wire, err := json.Marshal(retained)
							if err != nil {
								t.Fatal(err)
							}
							if _, err := pool.Raw().Exec(ctx, `UPDATE webauthn.effects SET ceremony=$1::jsonb WHERE command_id=$2`, string(wire), string(request.Context.CommandID)); err != nil {
								t.Fatal(err)
							}
							defer func() {
								if _, err := pool.Raw().Exec(ctx, `UPDATE webauthn.effects SET ceremony=$1::jsonb WHERE command_id=$2`, string(original), string(request.Context.CommandID)); err != nil {
									t.Fatal(err)
								}
							}()
							if snapshot, err := native.LoadCredential(ctx, lookup, id); err == nil && snapshot.Version == c.Version {
								t.Fatal("invalid retained ceremony supplied original retry snapshot")
							}
						})
					}
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
			r.Context = beginRequest().Context
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
		cutStore := &assertionStore{Store: cutNative, pool: cutPool, config: config, preauth: preauth, update: update}
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
		request = newAssertion(t)
		before, c = counts(), current()
		cut.cut.Store(false)
		cut.remaining.Store(1)
		if verified, err := cutService.VerifyAssertion(ctx, request); !errors.As(err, &unknown) {
			t.Fatal("lost final reservation was not unknown", err)
		} else if _, ok := verified.Credential(); ok {
			t.Fatal("unknown final reservation exposed verification")
		}
		commandID, _ = base64.RawURLEncoding.DecodeString(string(request.Context.CommandID))
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET created_at=clock_timestamp()-interval '3 seconds',heartbeat_at=clock_timestamp()-interval '2 seconds',updated_at=clock_timestamp()-interval '2 seconds',lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, commandID); err != nil {
			t.Fatal(err)
		}
		if outcome, err := svc.Recover(ctx, webauthn.RecoveryRequest{Context: request.Context, Operation: webauthn.AssertionOperation, CredentialID: id}); !errors.As(err, &unavailable) || outcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("pending original final command did not reconcile absence", err)
		}
		if counts() != before || current().Version != c.Version || current().Counter != c.Counter {
			t.Fatal("final noncommit recovery changed protected effects")
		}
	})
}
