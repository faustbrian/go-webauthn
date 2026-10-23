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

// Only the protocol participant is under test. This owner does not substitute
// passkey proof/session/authority policy; its metadata establishes atomic Work.
type removalOwner struct {
	command                                identity.Command
	participant                            *webauthnpg.CredentialRemoval
	failApply, failCommit, foreign, tamper bool
	recovery                               kernel.RecoveryStatus
}

func (*removalOwner) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}
}
func removalOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "passkey", OperationID: "identity.passkey.delete", SchemaID: "identity.passkey.delete.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}
func (*removalOwner) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{removalOperation()}
}
func (p *removalOwner) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	return p.participant.Validate(c, plan)
}
func (p *removalOwner) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	owner := p
	if p.foreign {
		owner = &removalOwner{}
	}
	if err := p.participant.Apply(ctx, w, owner, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	b, _, lifecycle, err := w.FeatureScope(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if _, err = w.Exec(ctx, `INSERT INTO removal_parent_metadata(command_id) VALUES($1)`, string(b.CommandID)); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.tamper {
		if _, err = w.Exec(ctx, `UPDATE webauthn.credentials SET record=jsonb_set(record,'{Counter}','999'::jsonb) WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), string(b.UserID)); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	if p.failApply {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	return identity.FeatureReceipt{Operation: removalOperation(), BeforeVersion: lifecycle.BeforeVersion, AfterVersion: lifecycle.AfterVersion}, nil
}
func (p *removalOwner) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p.failCommit {
		return identity.ForbiddenError{}
	}
	return p.participant.Check(ctx, w, p, c)
}
func (p *removalOwner) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	s, err := p.participant.Recover(ctx, w, p)
	p.recovery = s
	return s, err
}

func removalCoordinator(t *testing.T, pool *database.Pool, config kernel.CoordinatorConfig, p *removalOwner) (*kernel.Coordinator, *kernel.ContributorRegistry) {
	t.Helper()
	directory, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	a, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		t.Fatal(err)
	}
	l, err := lifecyclepg.NewContributor()
	if err != nil {
		t.Fatal(err)
	}
	r, err := kernel.NewContributorRegistry([]kernel.Contributor{directory, a, l, p})
	if err != nil {
		t.Fatal(err)
	}
	c, err := kernel.NewCoordinator(pool, r, config)
	if err != nil {
		t.Fatal(err)
	}
	return c, r
}

func removalPlan(t *testing.T, c *kernel.Coordinator, r *kernel.ContributorRegistry, p *removalOwner, request webauthnpg.RemovalRequest, mismatch string) (identity.CommandBinding, kernel.CommandPlan) {
	t.Helper()
	op := removalOperation()
	b := identity.CommandBinding{CommandID: request.Context.CommandID, TenantID: request.Context.TenantID, UserID: request.Context.UserID, ActorID: request.Context.ActorID, ActorKind: authorization.SubjectUser, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "removal-test", PolicyVersion: 1, CorrelationID: request.Context.CorrelationID, RecordID: "native-reference"}
	fields, err := p.participant.Fields()
	if err != nil {
		t.Fatal(err)
	}
	if mismatch == "scope" {
		b.CorrelationID = "foreign-correlation"
	}
	if mismatch == "intent" {
		fields[0].Value.Bytes[0] ^= 1
	}
	p.command, err = identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields})
	if err != nil {
		t.Fatal(err)
	}
	const event = "identity.passkey.remove_credential"
	builder, _ := audit.NewBuilder(audit.BuilderConfig{})
	seed, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC().Truncate(time.Microsecond), Action: event, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "passkey", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "passkey", "aggregate.id": b.RecordID, "aggregate.before_version": "7", "aggregate.after_version": "8", "retention.class": "protected"}})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, op, "passkey", seed)
	if err != nil {
		t.Fatal(err)
	}
	// The kernel-reference version is deliberately independent of protocol CAS.
	plan := kernel.CommandPlan{Contributors: r.Descriptors(), SubjectType: "passkey", Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}, Lifecycle: &kernel.LifecyclePlan{EventType: event, BeforeVersion: 7, AfterVersion: 8}, Audits: []kernel.AuditPlan{{EventType: event, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}}
	if mismatch == "lifecycle" {
		plan.Lifecycle.EventType = "identity.passkey.rename_credential"
	}
	plan, err = c.PrepareCommandPlan(b, p.command, plan)
	if mismatch == "scope" || mismatch == "intent" || mismatch == "lifecycle" {
		if err == nil {
			t.Fatal("different original parent admitted")
		}
		return b, kernel.CommandPlan{}
	}
	if err != nil {
		t.Fatal(err)
	}
	return b, plan
}

func TestRemovalParticipationPostgres(t *testing.T) {
	ctx, pool, config, store := nativeFixture(t)
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE removal_parent_metadata(command_id text PRIMARY KEY);CREATE TABLE assertion_participation_metadata(command_id text PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	key, _ := webauthn.NewChallengeDigestKey(bytes.Repeat([]byte{91}, 32))
	serviceConfig := webauthn.Config{TenantID: "tenant-a", RelyingParty: webauthn.RelyingParty{ID: "example.com", Name: "Removal", Origins: []string{"https://login.example.com"}, Version: 1}, ChallengeKey: key, MaximumDuration: 10 * time.Second}
	svc, err := webauthn.New(serviceConfig, webauthn.Dependencies{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	fresh := func() webauthn.CeremonyContext {
		id, _ := identity.NewCommandID()
		return webauthn.CeremonyContext{CommandID: id, TenantID: "tenant-a", UserID: "user-a", ActorID: "user-a", CorrelationID: "removal"}
	}
	private, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	handle := bytes.Repeat([]byte{92}, 32)
	credentialID := bytes.Repeat([]byte{93}, 32)
	options, err := svc.BeginRegistration(ctx, webauthn.BeginRegistrationRequest{Context: fresh(), UserHandle: handle, Origin: "https://login.example.com", ResidentKeyRequired: true})
	if err != nil {
		t.Fatal(err)
	}
	ceremony, _ := options.Ceremony()
	challenge := optionChallenge(t, ctx, options.TransferJSON)
	verified, err := svc.VerifyRegistration(ctx, webauthn.VerifyRegistrationRequest{Context: fresh(), CeremonyID: ceremony.ID, Origin: "https://login.example.com", ExpectedVersion: 1, Response: registrationResponse(t, private, credentialID, challenge, 0x45, 0)})
	if err != nil {
		t.Fatal(err)
	}
	credential, _ := verified.Credential()
	assert := func() webauthn.VerifyAssertionRequest {
		options, err := svc.BeginAssertion(ctx, webauthn.BeginAssertionRequest{Context: fresh(), UserHandle: handle, Origin: "https://login.example.com", AllowedCredentials: [][]byte{credentialID}})
		if err != nil {
			t.Fatal(err)
		}
		ceremony, _ := options.Ceremony()
		challenge := optionChallenge(t, ctx, options.TransferJSON)
		return webauthn.VerifyAssertionRequest{Context: fresh(), CeremonyID: ceremony.ID, Origin: "https://login.example.com", ExpectedVersion: 1, ExpectedCredentialVersion: credential.Version, Response: assertionResponse(t, private, credentialID, handle, challenge, 0x05, credential.Counter+1)}
	}
	// Real verified history is retained, not a caller-assembled protocol row.
	priorAssertion := assert()
	prior, err := svc.VerifyAssertion(ctx, priorAssertion)
	if err != nil {
		t.Fatal(err)
	}
	credential, _ = prior.Credential()
	// Complete a genuine resident discovery ceremony before removal. Its
	// original anonymous command retains a different before-snapshot from
	// today's credential, so the control proves the retained lookup branch.
	discoverable, err := webauthn.NewDiscoverable(serviceConfig, webauthn.Dependencies{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	discoveryScope := func() webauthn.CeremonyContext {
		c := fresh()
		c.UserID = ""
		c.ActorID = "discovery-service"
		c.AnonymousFlowID = "removal-resident-original"
		return c
	}
	discoveryOptions, err := discoverable.BeginDiscoverableAssertion(ctx, webauthn.BeginDiscoverableAssertionRequest{Context: discoveryScope(), Origin: serviceConfig.RelyingParty.Origins[0]})
	if err != nil {
		t.Fatal(err)
	}
	discoveryCeremony, _ := discoveryOptions.Ceremony()
	discoveryChallenge := optionChallenge(t, ctx, discoveryOptions.TransferJSON)
	beforeDiscovery := credential
	priorDiscovery := webauthn.VerifyDiscoverableAssertionRequest{Context: discoveryScope(), CeremonyID: discoveryCeremony.ID, Origin: serviceConfig.RelyingParty.Origins[0], ExpectedVersion: 1, Response: assertionResponse(t, private, credentialID, handle, discoveryChallenge, 0x05, credential.Counter+1)}
	discovered, err := discoverable.VerifyDiscoverableAssertion(ctx, priorDiscovery)
	if err != nil {
		t.Fatal("genuine resident assertion did not finalize", err)
	}
	var discoveredOK bool
	credential, discoveredOK = discovered.Credential()
	if !discoveredOK || credential.UserID != beforeDiscovery.UserID || credential.Version != beforeDiscovery.Version+1 || credential.Counter != beforeDiscovery.Counter+1 {
		t.Fatal("resident assertion did not advance actual protocol state")
	}
	retainedDiscovery := webauthn.Lookup{Context: priorDiscovery.Context, RPID: credential.RPID, CeremonyID: priorDiscovery.CeremonyID}
	if retained, err := store.LoadDiscoverableCredential(ctx, retainedDiscovery, credentialID, handle); err != nil || retained.Version != beforeDiscovery.Version || retained.Counter != beforeDiscovery.Counter || !bytes.Equal(retained.PublicKey, beforeDiscovery.PublicKey) {
		t.Fatal("original discovery command did not load its retained before-snapshot", err)
	}
	outstanding := assert()
	counts := func() [4]int {
		var n [4]int
		if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM webauthn.effects),(SELECT count(*) FROM removal_parent_metadata),(SELECT count(*) FROM audit.records WHERE outcome=$1),(SELECT count(*) FROM public.outbox_messages)`, int(audit.OutcomeSucceeded)).Scan(&n[0], &n[1], &n[2], &n[3]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	runPool, runStore := pool, store
	run := func(request webauthnpg.RemovalRequest, failure string) (identity.CommandResult, error) {
		participant, err := runStore.CredentialRemoval(request)
		if err != nil {
			return identity.CommandResult{}, err
		}
		p := &removalOwner{participant: participant, failApply: failure == "apply", failCommit: failure == "commit", foreign: failure == "foreign", tamper: failure == "tamper"}
		coordinator, registry := removalCoordinator(t, runPool, config, p)
		b, plan := removalPlan(t, coordinator, registry, p, request, failure)
		if plan.Feature == nil {
			return identity.CommandResult{}, identity.ForbiddenError{}
		}
		r, result, err := coordinator.ReserveCommand(ctx, b, p.command, plan)
		if err != nil || r == (kernel.Reservation{}) {
			return result, err
		}
		w, err := coordinator.Begin(ctx, r)
		if err != nil {
			return identity.CommandResult{}, err
		}
		defer coordinator.Abort(w, identity.UnavailableError{})
		provisional, err := coordinator.ApplyFeature(ctx, w, p.command)
		if err != nil {
			return coordinator.Abort(w, err)
		}
		return coordinator.Commit(w, provisional)
	}
	request := func() webauthnpg.RemovalRequest {
		return webauthnpg.RemovalRequest{Context: fresh(), RPID: credential.RPID, CredentialID: bytes.Clone(credential.ID), Version: credential.Version}
	}
	t.Run("assertion-final-successor-rewrite-denied", func(t *testing.T) {
		before := counts()
		parent := &assertionStore{Store: store, pool: pool, config: config, afterApply: func(ctx context.Context, w kernel.Work, c identity.Command) error {
			spec, _ := c.Feature()
			if spec.Operation.OperationID != "identity.passkey.signin-verify" {
				return nil
			}
			_, err := w.Exec(ctx, `UPDATE webauthn.credentials SET record=jsonb_set(record,'{PublicKey}','null'::jsonb) WHERE rp_id=$1 AND credential_id=$2`, credential.RPID, credential.ID)
			return err
		}}
		consumer, err := webauthn.New(serviceConfig, webauthn.Dependencies{Store: parent})
		if err != nil {
			t.Fatal(err)
		}
		if verified, err := consumer.VerifyAssertion(ctx, outstanding); err == nil {
			t.Fatal("same-Work denied successor authenticated", verified)
		} else if _, ok := verified.Credential(); ok {
			t.Fatal("rewritten successor released verification")
		}
		current, err := store.LoadCredential(ctx, webauthn.Lookup{Context: fresh(), RPID: credential.RPID}, credential.ID)
		if err != nil || current.Version != credential.Version || !bytes.Equal(current.PublicKey, credential.PublicKey) || counts() != before {
			t.Fatal("final assertion rejection failed shared rollback", err)
		}
		var consumed bool
		if err = pool.Raw().QueryRow(ctx, `SELECT consumed_by IS NOT NULL FROM webauthn.ceremonies WHERE ceremony_id=$1`, outstanding.CeremonyID).Scan(&consumed); err != nil || consumed {
			t.Fatal("rejected successor consumed ceremony", err)
		}
	})
	for _, failure := range []string{"foreign", "apply", "commit", "tamper", "scope", "intent", "lifecycle", "stale", "tenant", "rp", "user"} {
		t.Run(failure, func(t *testing.T) {
			before := counts()
			r := request()
			switch failure {
			case "stale":
				r.Version--
			case "tenant":
				r.Context.TenantID = "tenant-b"
			case "rp":
				r.RPID = "foreign.example.com"
			case "user":
				r.Context.UserID = "user-b"
				r.Context.ActorID = "user-b"
			}
			if result, err := run(r, failure); err == nil || result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("invalid or failed parent removed credential", err)
			}
			current, err := store.LoadCredential(ctx, webauthn.Lookup{Context: fresh(), RPID: credential.RPID}, credential.ID)
			if err != nil || current.Version != credential.Version || !bytes.Equal(current.PublicKey, credential.PublicKey) || counts() != before {
				t.Fatal("failed parent retained protocol/parent/audit/outbox mutation", err)
			}
		})
	}
	t.Run("success-terminal-reservation", func(t *testing.T) {
		before := counts()
		r := request()
		ready, resume := make(chan struct{}), make(chan struct{})
		released := false
		defer func() {
			if !released {
				close(resume)
			}
		}()
		pendingService, err := webauthn.New(serviceConfig, webauthn.Dependencies{Store: pausedAssertionStore{Store: store, ready: ready, resume: resume}})
		if err != nil {
			t.Fatal(err)
		}
		type pendingResult struct {
			err           error
			authenticated bool
		}
		pending := make(chan pendingResult, 1)
		go func() {
			v, err := pendingService.VerifyAssertion(ctx, outstanding)
			_, ok := v.Credential()
			pending <- pendingResult{err, ok}
		}()
		select {
		case <-ready:
		case <-ctx.Done():
			t.Fatal("preloaded assertion did not reach finalization")
		}
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
		}, SessionInit: func(ctx context.Context, c *pgx.Conn) error {
			_, err := c.Exec(ctx, `SET search_path=public`)
			return err
		}})
		if err != nil {
			t.Fatal(err)
		}
		defer cutPool.Close(context.Background())
		cutNative, err := webauthnpg.New(cutPool, webauthnpg.Config{Coordinator: config, PolicyID: "webauthn-test", PolicyVersion: 1})
		if err != nil {
			t.Fatal(err)
		}
		runPool, runStore = cutPool, cutNative
		defer func() { runPool, runStore = pool, store }()
		cut.remaining.Store(2)
		result, err := run(r, "")
		if result.Outcome != identity.CommitOutcomeUnknown || !cut.cut.Load() {
			t.Fatal("actual lost removal COMMIT acknowledgement not unknown", result.Outcome, err)
		}
		// A fresh participant and coordinator disclose only the original kernel
		// receipt; today's tombstone itself is not historical success authority.
		p0, err := store.CredentialRemoval(r)
		if err != nil {
			t.Fatal(err)
		}
		p := &removalOwner{participant: p0}
		coordinator, _ := removalCoordinator(t, pool, config, p)
		binding := identity.CommandBinding{CommandID: r.Context.CommandID, TenantID: r.Context.TenantID, UserID: r.Context.UserID, ActorID: r.Context.ActorID, ActorKind: authorization.SubjectUser, OperationID: removalOperation().OperationID, RecordID: "native-reference"}
		query := identity.RecoveryQuery{CommandID: binding.CommandID, TenantID: binding.TenantID, UserID: binding.UserID, ActorID: binding.ActorID, ActorKind: binding.ActorKind, OperationID: binding.OperationID, RecordID: binding.RecordID}
		caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(binding.ActorID), Kind: binding.ActorKind}, Tenant: authorization.TenantID(binding.TenantID), Action: authorization.Action(binding.OperationID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(binding.UserID)}}}
		if recovered, recoverErr := coordinator.RecoverCommand(ctx, query, caller); recoverErr != nil || recovered.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("original acknowledged receipt not recovered", recoverErr)
		}
		close(resume)
		released = true
		select {
		case result := <-pending:
			if result.err == nil || result.authenticated {
				t.Fatal("preloaded verifier resurrected removed protocol state", result.err)
			}
		case <-ctx.Done():
			t.Fatal("preloaded assertion did not terminate")
		}
		if counts() != [4]int{before[0] + 1, before[1] + 1, before[2] + 1, before[3] + 1} {
			t.Fatal("removal effects did not commit together")
		}
		var wire []byte
		var version string
		if err := pool.Raw().QueryRow(ctx, `SELECT record,version::text FROM webauthn.credentials WHERE rp_id=$1 AND credential_id=$2`, credential.RPID, credential.ID).Scan(&wire, &version); err != nil {
			t.Fatal(err)
		}
		var tombstone webauthn.Credential
		if json.Unmarshal(wire, &tombstone) != nil || len(tombstone.PublicKey) != 0 || tombstone.Version != credential.Version+1 || version != strconv.FormatUint(tombstone.Version, 10) || !bytes.Equal(tombstone.ID, credential.ID) || !bytes.Equal(tombstone.UserHandle, handle) {
			t.Fatal("not the exact denied retained successor")
		}
		for _, q := range []webauthn.VerifyAssertionRequest{outstanding, priorAssertion} {
			if v, err := svc.VerifyAssertion(ctx, q); err == nil {
				t.Fatal("removed credential verified", v)
			} else if _, ok := v.Credential(); ok {
				t.Fatal("removed credential released verification")
			}
		}
		if _, err := store.LoadCredential(ctx, webauthn.Lookup{Context: fresh(), RPID: credential.RPID}, credential.ID); err == nil {
			t.Fatal("tombstone projected as usable credential")
		}
		anonymous := fresh()
		anonymous.UserID = ""
		anonymous.AnonymousFlowID = "removal-discovery"
		if _, err := store.LoadDiscoverableCredential(ctx, webauthn.Lookup{Context: anonymous, RPID: credential.RPID}, credential.ID, handle); err == nil {
			t.Fatal("discovery resolved tombstone")
		}
		if retained, err := store.LoadDiscoverableCredential(ctx, retainedDiscovery, credentialID, handle); err == nil || len(retained.PublicKey) != 0 {
			t.Fatal("original discoverable command resolved its usable pre-removal snapshot", err)
		}
		if again, err := discoverable.VerifyDiscoverableAssertion(ctx, priorDiscovery); err == nil {
			t.Fatal("removed resident discovery replay verified", again)
		} else if _, ok := again.Credential(); ok {
			t.Fatal("removed resident discovery replay released verification")
		}
		// Existing public verifier sees the erased-key row as denied even when
		// an old store query shape returns it without today's tombstone filter.
		legacy, err := webauthn.New(webauthn.Config{TenantID: "tenant-a", RelyingParty: webauthn.RelyingParty{ID: "example.com", Name: "Legacy", Origins: []string{"https://login.example.com"}, Version: 1}, ChallengeKey: key, MaximumDuration: 10 * time.Second}, webauthn.Dependencies{Store: removalLegacySnapshot{Store: store, credential: tombstone}})
		if err != nil {
			t.Fatal(err)
		}
		legacyRequest := outstanding
		legacyRequest.ExpectedCredentialVersion = tombstone.Version
		if v, err := legacy.VerifyAssertion(ctx, legacyRequest); err == nil {
			t.Fatal("legacy projection accepted erased key", v)
		}
		// New registration with the old raw ID cannot resurrect the reservation.
		options, err := svc.BeginRegistration(ctx, webauthn.BeginRegistrationRequest{Context: fresh(), UserHandle: handle, Origin: "https://login.example.com", ResidentKeyRequired: true})
		if err != nil {
			t.Fatal(err)
		}
		ceremony, _ := options.Ceremony()
		challenge := optionChallenge(t, ctx, options.TransferJSON)
		if v, err := svc.VerifyRegistration(ctx, webauthn.VerifyRegistrationRequest{Context: fresh(), CeremonyID: ceremony.ID, Origin: "https://login.example.com", ExpectedVersion: 1, Response: registrationResponse(t, private, credentialID, challenge, 0x45, 0)}); err == nil {
			t.Fatal("removed RP-wide credential ID resurrected", v)
		}
		var handles int
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM webauthn.user_handles WHERE rp_id=$1 AND user_handle=$2`, credential.RPID, handle).Scan(&handles); err != nil || handles != 1 {
			t.Fatal("stable handle reservation lost", err)
		}
	})
	t.Run("original-recovery-never-rebuilds-commit", func(t *testing.T) {
		// Reserve an original command but never open its domain Work. Genuine
		// recovery sees no original effect. That proves only this command did
		// not commit, independent of a different command's current tombstone.
		r := request()
		p0, err := store.CredentialRemoval(r)
		if err != nil {
			t.Fatal(err)
		}
		p := &removalOwner{participant: p0}
		coordinator, registry := removalCoordinator(t, pool, config, p)
		b, plan := removalPlan(t, coordinator, registry, p, r, "")
		if _, _, err = coordinator.ReserveCommand(ctx, b, p.command, plan); err != nil {
			t.Fatal(err)
		}
		id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
		if _, err = pool.Raw().Exec(ctx, `UPDATE identity.commands SET created_at=clock_timestamp()-interval '3 seconds',heartbeat_at=clock_timestamp()-interval '2 seconds',updated_at=clock_timestamp()-interval '2 seconds',lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); err != nil {
			t.Fatal(err)
		}
		q := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
		caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(b.ActorID), Kind: b.ActorKind}, Tenant: authorization.TenantID(b.TenantID), Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}}}
		result, _ := coordinator.RecoverCommand(ctx, q, caller)
		if result.Outcome != identity.CommitOutcomeNotCommitted || p.recovery != kernel.RecoveryNotCommitted {
			t.Fatal("absent exact-command effect did not prove noncommit", result.Outcome, p.recovery)
		}
		// A retained marker alongside a pending journal is deliberately
		// inconsistent evidence: never invent a successful receipt from it.
		r = request()
		p0, err = store.CredentialRemoval(r)
		if err != nil {
			t.Fatal(err)
		}
		p = &removalOwner{participant: p0}
		coordinator, registry = removalCoordinator(t, pool, config, p)
		b, plan = removalPlan(t, coordinator, registry, p, r, "")
		if _, _, err = coordinator.ReserveCommand(ctx, b, p.command, plan); err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Raw().Exec(ctx, `INSERT INTO webauthn.effects(command_id,tenant_id,user_id,actor_id,purpose,record_id,fingerprint,ceremony_id,ceremony,before_credential,after_credential) SELECT $1,tenant_id,user_id,actor_id,purpose,record_id,fingerprint,ceremony_id,ceremony,before_credential,after_credential FROM webauthn.effects WHERE purpose='identity.passkey.delete' LIMIT 1`, string(b.CommandID)); err != nil {
			t.Fatal(err)
		}
		id, _ = base64.RawURLEncoding.DecodeString(string(b.CommandID))
		if _, err = pool.Raw().Exec(ctx, `UPDATE identity.commands SET created_at=clock_timestamp()-interval '3 seconds',heartbeat_at=clock_timestamp()-interval '2 seconds',updated_at=clock_timestamp()-interval '2 seconds',lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); err != nil {
			t.Fatal(err)
		}
		q.CommandID = b.CommandID
		result, _ = coordinator.RecoverCommand(ctx, q, caller)
		if result.Outcome == identity.CommitOutcomeCommitted || p.recovery != kernel.RecoveryUnknown {
			t.Fatal("retained effect fabricated committed authority", result.Outcome, p.recovery)
		}
	})
}

type removalLegacySnapshot struct {
	webauthn.Store
	credential webauthn.Credential
}

func (s removalLegacySnapshot) LoadCredential(context.Context, webauthn.Lookup, []byte) (webauthn.Credential, error) {
	return s.credential, nil
}
