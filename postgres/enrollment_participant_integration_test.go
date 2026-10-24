//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
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
)

type enrollmentParticipant interface {
	Fields() ([]identity.FeatureField, error)
	Validate(identity.Command, kernel.CommandPlan) error
	Apply(context.Context, kernel.Work, kernel.FeatureExecutionContributor, identity.Command) error
	Check(context.Context, kernel.Work, kernel.FeatureExecutionContributor, identity.Command) error
}

type enrollmentOwner struct {
	participant enrollmentParticipant
	command     identity.Command
	stage       int
	store       *enrollmentStore
}

func (*enrollmentOwner) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}
}
func (*enrollmentOwner) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{enrollmentOperation(0), enrollmentOperation(1), enrollmentOperation(2)}
}
func enrollmentOperation(stage int) identity.FeatureOperation {
	id, schema := "identity.passkey.register-options", "identity.passkey.register-options.session-assertion-options-v1"
	if stage == 1 {
		schema = "identity.passkey.register-options.session-registration-options-v1"
	}
	if stage == 2 {
		id, schema = "identity.passkey.register-verify", "identity.passkey.register-verify.session-registration-v1"
	}
	return identity.FeatureOperation{Owner: "passkey", OperationID: id, SchemaID: schema, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}
func (p *enrollmentOwner) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if c != p.command {
		return webauthn.Denied{}
	}
	return p.participant.Validate(c, plan)
}
func (p *enrollmentOwner) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	owner := p
	if p.store.invalidParent == "foreign-owner" {
		owner = &enrollmentOwner{}
	}
	if err := p.participant.Apply(ctx, w, owner, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	spec, _ := c.Feature()
	if _, err := w.Exec(ctx, `INSERT INTO enrollment_metadata(command_id) VALUES($1)`, string(spec.Binding.CommandID)); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.store.failApply {
		return identity.FeatureReceipt{}, webauthn.Denied{}
	}
	if p.store.afterApply != nil {
		if err := p.store.afterApply(ctx, w, c); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	return identity.FeatureReceipt{Operation: enrollmentOperation(p.stage), AfterVersion: 1}, nil
}
func (p *enrollmentOwner) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p.store.failCheck {
		return webauthn.Denied{}
	}
	return p.participant.Check(ctx, w, p, c)
}
func (p *enrollmentOwner) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return p.store.Store.RecoverEnrollment(ctx, w, p)
}

type enrollmentStore struct {
	*webauthnpg.Store
	pool                 *database.Pool
	config               kernel.CoordinatorConfig
	service              webauthn.Service
	transition           *webauthn.AssertionTransition
	compound             *webauthnpg.EnrollmentAuthorization
	options              webauthn.RegistrationOptions
	assertionCredential  webauthn.Credential
	failApply, failCheck bool
	afterApply           func(context.Context, kernel.Work, identity.Command) error
	lastResult           identity.CommandResult
	generationOffset     time.Duration
	registrationService  webauthn.Service
	registrationRequest  func(*webauthn.BeginRegistrationRequest)
	beforeCompound       func()
	beforeRegistration   func()
	legacyFinalization   bool
	invalidParent        string
}

func (s *enrollmentStore) coordinator(p *enrollmentOwner) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
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
	c, err := kernel.NewCoordinator(s.pool, r, s.config)
	return c, r, err
}

func (s *enrollmentStore) execute(ctx context.Context, participant enrollmentParticipant, stage int, scope webauthn.CeremonyContext) (identity.CommandResult, error) {
	p := &enrollmentOwner{participant: participant, stage: stage, store: s}
	coordinator, r, err := s.coordinator(p)
	if err != nil {
		return identity.CommandResult{}, err
	}
	op := enrollmentOperation(stage)
	b := identity.CommandBinding{CommandID: scope.CommandID, TenantID: scope.TenantID, UserID: scope.UserID, ActorID: scope.ActorID, ActorKind: authorization.SubjectUser, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "enrollment-test", PolicyVersion: 1, CorrelationID: scope.CorrelationID, RecordID: string(scope.CommandID)}
	fields, err := participant.Fields()
	if err != nil {
		return identity.CommandResult{}, err
	}
	c, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields})
	if err != nil {
		return identity.CommandResult{}, err
	}
	p.command = c
	event := []string{"passkey.reauthentication.started.v1", "passkey.registration.started.v1", "identity.passkey.create_credential"}[stage]
	lifecycle := kernel.LifecyclePlan{EventType: event, AfterVersion: 1}
	switch s.invalidParent {
	case "profile":
		op.SchemaID += ".foreign"
		b.SchemaID = op.SchemaID
	case "intent":
		fields[0].Value.Bytes[0] ^= 1
	case "tenant":
		b.TenantID = "other-tenant"
	case "actor":
		b.ActorID = "other-user"
	case "lifecycle":
		lifecycle.EventType = "passkey.foreign.v1"
	case "version":
		lifecycle.AfterVersion = 2
	}
	if s.invalidParent != "" {
		c, err = identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields})
		if err != nil {
			return identity.CommandResult{}, err
		}
		p.command = c
	}
	builder, _ := audit.NewBuilder(audit.BuilderConfig{})
	seed, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC().Truncate(time.Microsecond), Action: op.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "passkey", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "passkey", "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": strconv.Itoa(1), "retention.class": "protected"}})
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
	if generator, ok := participant.(interface {
		Generate(context.Context, time.Time) error
	}); ok {
		var now time.Time
		if err = s.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return identity.CommandResult{}, err
		}
		if stage == 0 {
			now = now.Add(s.generationOffset)
		}
		if err = generator.Generate(ctx, now); err != nil {
			return identity.CommandResult{}, err
		}
	}
	w, err := coordinator.Begin(ctx, reservation)
	if err != nil {
		return identity.CommandResult{}, err
	}
	defer coordinator.Abort(w, webauthn.Unavailable{})
	provisional, err := coordinator.ApplyFeature(ctx, w, c)
	if err != nil {
		return coordinator.Abort(w, err)
	}
	return coordinator.Commit(w, provisional)
}

func (s *enrollmentStore) CreateCeremony(ctx context.Context, input webauthn.CeremonyCreation) (webauthn.CeremonyRecord, webauthn.Challenge, identity.CommitOutcome, error) {
	i, _ := input.Intent()
	if s.transition == nil {
		p, err := s.Store.EnrollmentAssertionCreation(input)
		if err != nil {
			return webauthn.CeremonyRecord{}, webauthn.Challenge{}, identity.CommitOutcomeInvalid, err
		}
		defer p.Discard()
		r, runErr := s.execute(ctx, p, 0, i.Context)
		s.lastResult = r
		record, ch, err := p.Result(r)
		if runErr != nil {
			err = runErr
		}
		return record, ch, r.Outcome, err
	}
	if s.beforeCompound != nil {
		s.beforeCompound()
	}
	p, err := s.Store.EnrollmentAuthorization(*s.transition, input)
	if err != nil {
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, identity.CommitOutcomeInvalid, err
	}
	defer p.Discard()
	s.compound = p
	r, runErr := s.execute(ctx, p, 1, i.Context)
	s.lastResult = r
	record, ch, credential, err := p.Result(r)
	s.assertionCredential = credential
	if runErr != nil {
		err = runErr
	}
	return record, ch, r.Outcome, err
}
func (s *enrollmentStore) FinalizeAssertion(ctx context.Context, input webauthn.AssertionTransition) (webauthn.Credential, identity.CommitOutcome, error) {
	m, _ := input.Mutation()
	s.transition = &input
	defer func() { s.transition = nil }()
	request := webauthn.BeginRegistrationRequest{Context: m.Context, UserHandle: m.Before.UserHandle, Origin: m.Ceremony.Intent.Origin, ResidentKeyRequired: true, ExcludedCredentials: [][]byte{m.Before.ID}}
	if s.registrationRequest != nil {
		s.registrationRequest(&request)
	}
	service := s.service
	if s.registrationService != nil {
		service = s.registrationService
	}
	options, err := service.BeginRegistration(ctx, request)
	s.options = options
	return s.assertionCredential, s.lastResult.Outcome, err
}
func (s *enrollmentStore) FinalizeRegistration(ctx context.Context, input webauthn.RegistrationTransition) (webauthn.Credential, identity.CommitOutcome, error) {
	if s.legacyFinalization {
		return s.Store.FinalizeRegistration(ctx, input)
	}
	p, err := s.Store.SessionRegistrationFinalization(input)
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	if s.beforeRegistration != nil {
		s.beforeRegistration()
	}
	m, _ := input.Mutation()
	r, runErr := s.execute(ctx, p, 2, m.Context)
	s.lastResult = r
	credential, err := p.Result(r)
	if runErr != nil {
		err = runErr
	}
	return credential, r.Outcome, err
}

func (s *enrollmentStore) recover(ctx context.Context, scope webauthn.CeremonyContext, stage int) (identity.CommitOutcome, error) {
	p := &enrollmentOwner{store: s, stage: stage}
	coordinator, _, err := s.coordinator(p)
	if err != nil {
		return identity.CommitOutcomeUnknown, err
	}
	q := identity.RecoveryQuery{CommandID: scope.CommandID, TenantID: scope.TenantID, UserID: scope.UserID, ActorID: scope.ActorID, ActorKind: authorization.SubjectUser, OperationID: enrollmentOperation(stage).OperationID, RecordID: string(scope.CommandID)}
	caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(q.ActorID), Kind: q.ActorKind}, Tenant: authorization.TenantID(q.TenantID), Action: authorization.Action(q.OperationID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(q.UserID)}}}
	r, err := coordinator.RecoverCommand(ctx, q, caller)
	return r.Outcome, err
}

func TestEnrollmentParticipationPostgres(t *testing.T) {
	testEnrollmentParticipationPostgres(t, participantProfile{})
}

func testEnrollmentParticipationPostgres(t *testing.T, profile participantProfile) {
	registrationResponse, assertionResponse := profile.registration, profile.assertion
	ctx, pool, config, native := nativeFixture(t)
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE enrollment_metadata(command_id text PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	key, _ := webauthn.NewChallengeDigestKey(bytes.Repeat([]byte{101}, 32))
	cfg := webauthn.Config{TenantID: "tenant-a", RelyingParty: webauthn.RelyingParty{ID: "example.com", Name: "Enrollment", Origins: []string{"https://login.example.com"}, Version: 1}, ChallengeKey: key, MaximumDuration: 10 * time.Second}
	cfg.Algorithms = profile.algorithms
	initial, err := webauthn.New(cfg, webauthn.Dependencies{Store: native})
	if err != nil {
		t.Fatal(err)
	}
	store := &enrollmentStore{Store: native, pool: pool, config: config}
	store.service, err = webauthn.New(cfg, webauthn.Dependencies{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	fresh := func() webauthn.CeremonyContext {
		id, _ := identity.NewCommandID()
		return webauthn.CeremonyContext{CommandID: id, TenantID: "tenant-a", UserID: "user-a", ActorID: "user-a", CorrelationID: "enrollment"}
	}
	handle, id := bytes.Repeat([]byte{102}, 32), bytes.Repeat([]byte{103}, 32)
	private := profile.key(t)
	options, err := initial.BeginRegistration(ctx, webauthn.BeginRegistrationRequest{Context: fresh(), UserHandle: handle, Origin: "https://login.example.com", ResidentKeyRequired: true})
	if err != nil {
		t.Fatal(err)
	}
	record, _ := options.Ceremony()
	challenge := optionChallenge(t, ctx, options.TransferJSON)
	if _, err = initial.VerifyRegistration(ctx, webauthn.VerifyRegistrationRequest{Context: fresh(), CeremonyID: record.ID, Origin: "https://login.example.com", ExpectedVersion: 1, Response: registrationResponse(t, private, id, challenge, 0x45, 0)}); err != nil {
		t.Fatal(err)
	}
	request := func(t *testing.T, profile ...byte) webauthn.VerifyAssertionRequest {
		t.Helper()
		o, e := store.service.BeginAssertion(ctx, webauthn.BeginAssertionRequest{Context: fresh(), UserHandle: handle, Origin: "https://login.example.com", AllowedCredentials: [][]byte{id}})
		if e != nil {
			t.Fatal(e)
		}
		r, _ := o.Ceremony()
		ch := optionChallenge(t, ctx, o.TransferJSON)
		c, e := native.LoadCredential(ctx, webauthn.Lookup{Context: fresh(), RPID: "example.com"}, id)
		if e != nil {
			t.Fatal(e)
		}
		flags, counter := byte(0x05), c.Counter+1
		if len(profile) > 0 {
			flags = profile[0]
		}
		if len(profile) > 1 {
			counter = c.Counter + uint32(profile[1])
		}
		return webauthn.VerifyAssertionRequest{Context: fresh(), CeremonyID: r.ID, Origin: "https://login.example.com", ExpectedVersion: 1, ExpectedCredentialVersion: c.Version, Response: assertionResponse(t, private, id, handle, ch, flags, counter)}
	}
	counts := func() [5]int {
		var n [5]int
		if e := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM webauthn.ceremonies),(SELECT count(*) FROM webauthn.effects),(SELECT count(*) FROM enrollment_metadata),(SELECT count(*) FROM audit.records WHERE outcome=$1),(SELECT count(*) FROM public.outbox_messages)`, int(audit.OutcomeSucceeded)).Scan(&n[0], &n[1], &n[2], &n[3], &n[4]); e != nil {
			t.Fatal(e)
		}
		return n
	}
	unconsumed := func(t *testing.T, ceremony string) {
		t.Helper()
		var consumed bool
		if e := pool.Raw().QueryRow(ctx, `SELECT consumed_by IS NOT NULL FROM webauthn.ceremonies WHERE ceremony_id=$1`, ceremony).Scan(&consumed); e != nil || consumed {
			t.Fatal("source consumed after rejected compound", e)
		}
	}
	registrationRequest := func(t *testing.T) webauthn.VerifyRegistrationRequest {
		t.Helper()
		r, ok := store.options.Ceremony()
		if !ok {
			t.Fatal("missing genuine options")
		}
		ch := optionChallenge(t, ctx, store.options.TransferJSON)
		nextID := make([]byte, 32)
		_, _ = rand.Read(nextID)
		nextKey := profile.key(t)
		return webauthn.VerifyRegistrationRequest{Context: fresh(), CeremonyID: r.ID, Origin: "https://login.example.com", ExpectedVersion: 1, Response: registrationResponse(t, nextKey, nextID, ch, 0x45, 0)}
	}
	for _, defect := range []string{"UV", "counter"} {
		t.Run("genuine-proof-denies-"+defect, func(t *testing.T) {
			flags, delta := byte(0x05), byte(1)
			if defect == "UV" {
				flags = 0x01
			} else {
				if _, e := store.service.VerifyAssertion(ctx, request(t)); e != nil {
					t.Fatal(e)
				}
				delta = 0
			}
			req := request(t, flags, delta)
			before := counts()
			if _, e := store.service.VerifyAssertion(ctx, req); e == nil {
				t.Fatal("unsafe proof authorized enrollment")
			}
			if counts() != before {
				t.Fatal("unsafe proof persisted effects")
			}
			unconsumed(t, req.CeremonyID)
		})
	}
	t.Run("genuine-backup-counter-risk-denies", func(t *testing.T) {
		key := profile.key(t)
		credentialID := bytes.Repeat([]byte{109}, 32)
		o, e := initial.BeginRegistration(ctx, webauthn.BeginRegistrationRequest{Context: fresh(), UserHandle: handle, Origin: "https://login.example.com", ResidentKeyRequired: true})
		if e != nil {
			t.Fatal(e)
		}
		r, _ := o.Ceremony()
		ch := optionChallenge(t, ctx, o.TransferJSON)
		if _, e = initial.VerifyRegistration(ctx, webauthn.VerifyRegistrationRequest{Context: fresh(), CeremonyID: r.ID, Origin: "https://login.example.com", ExpectedVersion: 1, Response: registrationResponse(t, key, credentialID, ch, 0x4d, 4)}); e != nil {
			t.Fatal(e)
		}
		assertion, e := store.service.BeginAssertion(ctx, webauthn.BeginAssertionRequest{Context: fresh(), UserHandle: handle, Origin: "https://login.example.com", AllowedCredentials: [][]byte{credentialID}})
		if e != nil {
			t.Fatal(e)
		}
		a, _ := assertion.Ceremony()
		challenge := optionChallenge(t, ctx, assertion.TransferJSON)
		before := counts()
		if _, e = store.service.VerifyAssertion(ctx, webauthn.VerifyAssertionRequest{Context: fresh(), CeremonyID: a.ID, Origin: "https://login.example.com", ExpectedVersion: 1, ExpectedCredentialVersion: 1, Response: assertionResponse(t, key, credentialID, handle, challenge, 0x0d, 3)}); e == nil {
			t.Fatal("genuine backup counter-risk authorized enrollment")
		}
		if counts() != before {
			t.Fatal("counter-risk persisted protected effects")
		}
		unconsumed(t, a.ID)
	})
	for _, defect := range []string{"profile", "intent", "tenant", "actor", "lifecycle", "version", "foreign-owner"} {
		t.Run("A-parent-"+defect, func(t *testing.T) {
			before := counts()
			store.invalidParent = defect
			defer func() { store.invalidParent = "" }()
			if o, e := store.service.BeginAssertion(ctx, webauthn.BeginAssertionRequest{Context: fresh(), UserHandle: handle, Origin: "https://login.example.com", AllowedCredentials: [][]byte{id}}); e == nil {
				t.Fatal("foreign A parent accepted", o)
			}
			if counts() != before {
				t.Fatal("foreign A parent persisted effects")
			}
		})
		t.Run("B-parent-"+defect, func(t *testing.T) {
			req := request(t)
			before := counts()
			store.invalidParent = defect
			defer func() { store.invalidParent = "" }()
			if _, e := store.service.VerifyAssertion(ctx, req); e == nil {
				t.Fatal("foreign B parent accepted")
			}
			if counts() != before {
				t.Fatal("foreign B parent persisted effects")
			}
			unconsumed(t, req.CeremonyID)
		})
	}
	for _, defect := range []string{"command", "correlation", "handle", "resident", "origin", "rp", "rp-version", "extensions", "algorithms"} {
		t.Run("opaque-input-"+defect, func(t *testing.T) {
			req := request(t)
			before := counts()
			alternate := cfg
			alternate.RelyingParty.Origins = []string{"https://login.example.com", "https://alternate.example.com"}
			if defect == "rp" {
				alternate.RelyingParty.ID = "other.example.com"
				alternate.RelyingParty.Origins = []string{"https://login.other.example.com"}
			}
			if defect == "rp-version" {
				alternate.RelyingParty.Version++
			}
			if defect == "extensions" {
				alternate.Extensions.CredentialProperties = true
			}
			if defect == "algorithms" {
				alternate.Algorithms = []webauthn.Algorithm{webauthn.ES256, webauthn.EdDSA}
			}
			var e error
			store.registrationService, e = webauthn.New(alternate, webauthn.Dependencies{Store: store})
			if e != nil {
				t.Fatal(e)
			}
			store.registrationRequest = func(r *webauthn.BeginRegistrationRequest) {
				switch defect {
				case "command":
					r.Context.CommandID, _ = identity.NewCommandID()
				case "correlation":
					r.Context.CorrelationID = "other-correlation"
				case "handle":
					r.UserHandle = bytes.Repeat([]byte{99}, 32)
				case "resident":
					r.ResidentKeyRequired = false
				case "origin":
					r.Origin = "https://alternate.example.com"
				case "rp":
					r.Origin = "https://login.other.example.com"
				}
			}
			defer func() { store.registrationService = nil; store.registrationRequest = nil }()
			if _, e = store.service.VerifyAssertion(ctx, req); e == nil {
				t.Fatal("mismatched opaque creation accepted")
			}
			if counts() != before {
				t.Fatal("mismatched opaque creation persisted effects")
			}
			unconsumed(t, req.CeremonyID)
		})
	}
	for _, cut := range []string{"apply", "precommit"} {
		t.Run("atomic-rollback-"+cut, func(t *testing.T) {
			req := request(t)
			store.failApply = cut == "apply"
			store.failCheck = cut == "precommit"
			if v, e := store.service.VerifyAssertion(ctx, req); e == nil {
				t.Fatal("failed parent accepted", v)
			}
			store.failApply, store.failCheck = false, false
			var consumed bool
			if e := pool.Raw().QueryRow(ctx, `SELECT consumed_by IS NOT NULL FROM webauthn.ceremonies WHERE ceremony_id=$1`, req.CeremonyID).Scan(&consumed); e != nil || consumed {
				t.Fatal("assertion consumption survived rollback", e)
			}
			req.Context = fresh()
			if _, e := store.service.VerifyAssertion(ctx, req); e != nil {
				t.Fatal("rolled-back source was not reusable by a fresh command", e)
			}
		})
	}
	t.Run("genuine-compound-then-registration", func(t *testing.T) {
		req := request(t)
		verified, e := store.service.VerifyAssertion(ctx, req)
		if e != nil {
			var invalid webauthn.Invalid
			errors.As(e, &invalid)
			t.Fatal("genuine compound B", e, invalid.Field)
		}
		if _, ok := verified.Credential(); !ok {
			t.Fatal("acknowledged compound did not return assertion")
		}
		r, ok := store.options.Ceremony()
		if !ok {
			t.Fatal("compound did not return genuine registration options")
		}
		var source, created string
		if e = pool.Raw().QueryRow(ctx, `SELECT consumed_by FROM webauthn.ceremonies WHERE ceremony_id=$1`, req.CeremonyID).Scan(&source); e != nil {
			t.Fatal(e)
		}
		if e = pool.Raw().QueryRow(ctx, `SELECT ceremony_id FROM webauthn.effects WHERE command_id=$1`, string(req.Context.CommandID)).Scan(&created); e != nil || source != r.ID || created != r.ID {
			t.Fatal("effects did not share original B command", e)
		}
		lookup := webauthn.Lookup{Context: req.Context, RPID: "example.com", CeremonyID: req.CeremonyID}
		prior, e := native.LoadCredential(ctx, lookup, id)
		if e != nil || prior.Version != req.ExpectedCredentialVersion {
			t.Fatal("original B retry lost exact prior snapshot", e)
		}
		currentLookup := lookup
		currentLookup.Context = fresh()
		current, e := native.LoadCredential(ctx, currentLookup, id)
		if e != nil || current.Version != prior.Version+1 {
			t.Fatal("ordinary current lookup selected retained before-state", e)
		}
		for _, mismatch := range []string{"actor", "command", "tenant", "user", "rp", "ceremony"} {
			foreign := lookup
			switch mismatch {
			case "actor":
				foreign.Context.ActorID = "different-user"
			case "command":
				foreign.Context.CommandID, _ = identity.NewCommandID()
			case "tenant":
				foreign.Context.TenantID = "other-tenant"
			case "user":
				foreign.Context.UserID = "other-user"
			case "rp":
				foreign.RPID = "other.example.com"
			case "ceremony":
				foreign.CeremonyID = "different-ceremony"
			}
			if snapshot, e := native.LoadCredential(ctx, foreign, id); e == nil && snapshot.Version == prior.Version {
				t.Fatal("foreign lookup selected retained B before-state", mismatch)
			}
		}
		before := counts()
		if v, e := initial.VerifyAssertion(ctx, req); e == nil {
			t.Fatal("ordinary protocol signin reused B command", v)
		}
		if counts() != before {
			t.Fatal("ordinary signin changed compound command effects")
		}
		if _, _, _, e = store.compound.Result(store.lastResult); e == nil {
			t.Fatal("compound rereleased outputs")
		}
		ch := optionChallenge(t, ctx, store.options.TransferJSON)
		nextID := bytes.Repeat([]byte{104}, 32)
		nextKey := profile.key(t)
		registered, e := store.service.VerifyRegistration(ctx, webauthn.VerifyRegistrationRequest{Context: fresh(), CeremonyID: r.ID, Origin: "https://login.example.com", ExpectedVersion: 1, Response: registrationResponse(t, nextKey, nextID, ch, 0x45, 0)})
		if e != nil {
			var invalid webauthn.Invalid
			errors.As(e, &invalid)
			t.Fatal("genuine registration C", e, invalid.Field)
		}
		if _, ok := registered.Credential(); !ok {
			t.Fatal("registration result unavailable")
		}
		if _, e = store.service.VerifyAssertion(ctx, req); e == nil {
			t.Fatal("consumed assertion reused")
		}
	})
	t.Run("session-C-denies-ordinary-ceremony", func(t *testing.T) {
		o, e := initial.BeginRegistration(ctx, webauthn.BeginRegistrationRequest{Context: fresh(), UserHandle: handle, Origin: "https://login.example.com", ResidentKeyRequired: true})
		if e != nil {
			t.Fatal(e)
		}
		store.options = o
		req := registrationRequest(t)
		before := counts()
		if _, e = store.service.VerifyRegistration(ctx, req); e == nil {
			t.Fatal("ordinary ceremony gained session authorization")
		}
		if counts() != before {
			t.Fatal("ordinary ceremony persisted C effects")
		}
		unconsumed(t, req.CeremonyID)
	})
	t.Run("legacy-C-cannot-consume-compound", func(t *testing.T) {
		req := request(t)
		if _, e := store.service.VerifyAssertion(ctx, req); e != nil {
			t.Fatal(e)
		}
		registration := registrationRequest(t)
		store.legacyFinalization = true
		before := counts()
		if _, e := store.service.VerifyRegistration(ctx, registration); e == nil {
			t.Fatal("legacy finalization bypassed session profile")
		}
		store.legacyFinalization = false
		if counts() != before {
			t.Fatal("legacy finalization persisted effects")
		}
		unconsumed(t, registration.CeremonyID)
		registration.Context = fresh()
		if _, e := store.service.VerifyRegistration(ctx, registration); e != nil {
			t.Fatal("proper selector failed after legacy rejection", e)
		}
	})
	for _, defect := range []string{"profile", "intent", "tenant", "actor", "lifecycle", "version", "foreign-owner"} {
		t.Run("C-parent-"+defect, func(t *testing.T) {
			req := request(t)
			if _, e := store.service.VerifyAssertion(ctx, req); e != nil {
				t.Fatal(e)
			}
			registration := registrationRequest(t)
			before := counts()
			store.invalidParent = defect
			defer func() { store.invalidParent = "" }()
			if _, e := store.service.VerifyRegistration(ctx, registration); e == nil {
				t.Fatal("foreign C parent accepted")
			}
			if counts() != before {
				t.Fatal("foreign C parent persisted effects")
			}
			unconsumed(t, registration.CeremonyID)
		})
	}
	t.Run("source-expiry-fences-B-final-precommit", func(t *testing.T) {
		store.generationOffset = -5*time.Minute + 2*time.Second
		req := request(t)
		store.generationOffset = 0
		before := counts()
		store.afterApply = func(ctx context.Context, w kernel.Work, _ identity.Command) error {
			wait := time.Until(store.compound.AuthorizationExpiresAt()) + 10*time.Millisecond
			if wait > 0 {
				_, e := w.Exec(ctx, `SELECT pg_sleep($1)`, wait.Seconds())
				return e
			}
			return nil
		}
		defer func() { store.afterApply = nil }()
		if _, e := store.service.VerifyAssertion(ctx, req); e == nil {
			t.Fatal("B renewed source authority")
		}
		if counts() != before {
			t.Fatal("expired B persisted compound effects")
		}
		unconsumed(t, req.CeremonyID)
	})
	for _, defect := range []string{"A-profile", "B-profile", "source", "ceiling", "created-record", "source-consumption"} {
		t.Run("C-authoritative-linkage-"+defect, func(t *testing.T) {
			req := request(t)
			if _, e := store.service.VerifyAssertion(ctx, req); e != nil {
				t.Fatal(e)
			}
			registration := registrationRequest(t)
			var e error
			switch defect {
			case "A-profile":
				_, e = pool.Raw().Exec(ctx, `UPDATE webauthn.effects SET enrollment_stage=NULL WHERE command_id=$1`, req.CeremonyID)
			case "B-profile":
				_, e = pool.Raw().Exec(ctx, `UPDATE webauthn.effects SET enrollment_stage=NULL,enrollment_source=NULL WHERE command_id=$1`, string(req.Context.CommandID))
			case "source":
				_, e = pool.Raw().Exec(ctx, `UPDATE webauthn.effects SET enrollment_source=jsonb_set(enrollment_source,'{Intent,Context,UserID}','"other-user"'::jsonb) WHERE command_id=$1`, string(req.Context.CommandID))
			case "ceiling":
				_, e = pool.Raw().Exec(ctx, `UPDATE webauthn.ceremonies SET authorization_expires_at=expires_at WHERE ceremony_id=$1`, registration.CeremonyID)
			case "created-record":
				_, e = pool.Raw().Exec(ctx, `UPDATE webauthn.effects SET ceremony=jsonb_set(ceremony,'{Intent,Origin}','"https://different.example.com"'::jsonb) WHERE command_id=$1`, string(req.Context.CommandID))
			case "source-consumption":
				other := fresh()
				_, e = pool.Raw().Exec(ctx, `UPDATE webauthn.ceremonies SET consumed_by=$1 WHERE ceremony_id=$2`, string(other.CommandID), req.CeremonyID)
			}
			if e != nil {
				t.Fatal(e)
			}
			before := counts()
			if _, e = store.service.VerifyRegistration(ctx, registration); e == nil {
				t.Fatal("broken A/B authority linkage accepted")
			}
			if counts() != before {
				t.Fatal("broken source linkage persisted C effects")
			}
			unconsumed(t, registration.CeremonyID)
		})
	}
	t.Run("source-expiry-fences-C-not-registration-TTL", func(t *testing.T) {
		store.generationOffset = -5*time.Minute + 2*time.Second
		req := request(t)
		store.generationOffset = 0
		if _, e := store.service.VerifyAssertion(ctx, req); e != nil {
			t.Fatal(e)
		}
		registration := registrationRequest(t)
		r, e := native.LoadCeremony(ctx, webauthn.Lookup{Context: registration.Context, RPID: "example.com", CeremonyID: registration.CeremonyID})
		if e != nil {
			t.Fatal(e)
		}
		expiry := store.compound.AuthorizationExpiresAt()
		if !r.ExpiresAt.After(expiry.Add(time.Minute)) {
			t.Fatal("registration TTL replaced source expiry")
		}
		before := counts()
		store.afterApply = func(ctx context.Context, w kernel.Work, _ identity.Command) error {
			wait := time.Until(expiry) + 10*time.Millisecond
			if wait > 0 {
				_, e := w.Exec(ctx, `SELECT pg_sleep($1)`, wait.Seconds())
				return e
			}
			return nil
		}
		if _, e = store.service.VerifyRegistration(ctx, registration); e == nil {
			t.Fatal("C final precommit ignored expired source")
		}
		store.afterApply = nil
		if !time.Now().Before(r.ExpiresAt) {
			t.Fatal("test did not distinguish registration TTL")
		}
		if counts() != before {
			t.Fatal("expired C persisted effects")
		}
		unconsumed(t, registration.CeremonyID)
		registration.Context = fresh()
		if _, e = store.service.VerifyRegistration(ctx, registration); e == nil {
			t.Fatal("already-expired source accepted at C Apply")
		}
	})
	t.Run("single-source-contention", func(t *testing.T) {
		req := request(t)
		before := counts()
		ready, resume := make(chan struct{}, 2), make(chan struct{})
		results := make(chan error, 2)
		for range 2 {
			contender := &enrollmentStore{Store: native, pool: pool, config: config, beforeCompound: func() {
				ready <- struct{}{}
				select {
				case <-resume:
				case <-ctx.Done():
				}
			}}
			contender.service, err = webauthn.New(cfg, webauthn.Dependencies{Store: contender})
			if err != nil {
				t.Fatal(err)
			}
			r := req
			r.Context = fresh()
			go func() { _, e := contender.service.VerifyAssertion(ctx, r); results <- e }()
		}
		for range 2 {
			select {
			case <-ready:
			case <-ctx.Done():
				t.Fatal("contenders never reached genuine opaque boundary")
			}
		}
		close(resume)
		winners := 0
		for range 2 {
			if <-results == nil {
				winners++
			}
		}
		if winners != 1 {
			t.Fatal("compound contention winners", winners)
		}
		after := counts()
		if after != [5]int{before[0] + 1, before[1] + 1, before[2] + 1, before[3] + 1, before[4] + 1} {
			t.Fatal("contention duplicated or split effects", before, after)
		}
	})
	t.Run("single-registration-contention", func(t *testing.T) {
		req := request(t)
		if _, e := store.service.VerifyAssertion(ctx, req); e != nil {
			t.Fatal(e)
		}
		registration := registrationRequest(t)
		before := counts()
		ready, resume := make(chan struct{}, 2), make(chan struct{})
		results := make(chan error, 2)
		for range 2 {
			contender := &enrollmentStore{Store: native, pool: pool, config: config, beforeRegistration: func() {
				ready <- struct{}{}
				select {
				case <-resume:
				case <-ctx.Done():
				}
			}}
			contender.service, err = webauthn.New(cfg, webauthn.Dependencies{Store: contender})
			if err != nil {
				t.Fatal(err)
			}
			r := registration
			r.Context = fresh()
			go func() { _, e := contender.service.VerifyRegistration(ctx, r); results <- e }()
		}
		for range 2 {
			select {
			case <-ready:
			case <-ctx.Done():
				t.Fatal("registration contenders never reached genuine opaque boundary")
			}
		}
		close(resume)
		winners := 0
		for range 2 {
			if <-results == nil {
				winners++
			}
		}
		if winners != 1 {
			t.Fatal("registration contention winners", winners)
		}
		after := counts()
		if after != [5]int{before[0], before[1] + 1, before[2] + 1, before[3] + 1, before[4] + 1} {
			t.Fatal("registration contention split or duplicated effects", before, after)
		}
	})
	t.Run("compound-commit-loss-original-recovery", func(t *testing.T) {
		cut := &commitCut{}
		cutPool, e := database.New(ctx, database.Config{DSN: os.Getenv("WEBAUTHN_TEST_DSN"), MaxConns: 2, Configure: func(c *database.PoolConfig) error {
			dial := c.ConnConfig.DialFunc
			c.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
				conn, e := dial(ctx, network, address)
				if e != nil {
					return nil, e
				}
				return &commitCutConn{Conn: conn, cut: cut}, nil
			}
			return nil
		}})
		if e != nil {
			t.Fatal(e)
		}
		defer cutPool.Close(context.Background())
		cutNative, e := webauthnpg.New(cutPool, webauthnpg.Config{Coordinator: config, PolicyID: "enrollment-test", PolicyVersion: 1})
		if e != nil {
			t.Fatal(e)
		}
		cutStore := &enrollmentStore{Store: cutNative, pool: cutPool, config: config}
		cutStore.service, e = webauthn.New(cfg, webauthn.Dependencies{Store: cutStore})
		if e != nil {
			t.Fatal(e)
		}
		for _, number := range []int32{2, 1} {
			req := request(t)
			before := counts()
			cut.cut.Store(false)
			cut.remaining.Store(number)
			v, e := cutStore.service.VerifyAssertion(ctx, req)
			var unknown webauthn.UnknownCommit
			if !errors.As(e, &unknown) || !cut.cut.Load() {
				t.Fatal("cut did not report unknown compound", number, e)
			}
			if _, ok := v.Credential(); ok {
				t.Fatal("unknown compound exposed assertion")
			}
			if _, ok := cutStore.options.Ceremony(); ok {
				t.Fatal("unknown compound exposed registration options")
			}
			if number == 2 {
				after := counts()
				if after != [5]int{before[0] + 1, before[1] + 1, before[2] + 1, before[3] + 1, before[4] + 1} {
					t.Fatal("lost ACK split compound effects", before, after)
				}
				if outcome, e := store.recover(ctx, req.Context, 1); e != nil || outcome != identity.CommitOutcomeCommitted {
					t.Fatal("committed compound recovery", outcome, e)
				}
			} else {
				command, _ := base64.RawURLEncoding.DecodeString(string(req.Context.CommandID))
				if _, e = pool.Raw().Exec(ctx, `UPDATE identity.commands SET created_at=clock_timestamp()-interval '3 seconds',heartbeat_at=clock_timestamp()-interval '2 seconds',updated_at=clock_timestamp()-interval '2 seconds',lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, command); e != nil {
					t.Fatal(e)
				}
				outcome, e := store.recover(ctx, req.Context, 1)
				if outcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("pending compound absence recovery", outcome, e)
				}
				if counts() != before {
					t.Fatal("unknown reservation created effects")
				}
				unconsumed(t, req.CeremonyID)
			}
			before = counts()
			if _, e = cutStore.service.VerifyAssertion(ctx, req); e == nil {
				t.Fatal("recovery/retry reissued authentication")
			}
			if counts() != before {
				t.Fatal("retry regenerated compound effects")
			}
		}
	})
}
