package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	webauthn "github.com/faustbrian/go-webauthn"
	"github.com/jackc/pgx/v5"
)

// Config freezes the existing journal's key, lease, query authorization and
// operation policy. QueryPolicy is mandatory for original-command recovery.
// This first native profile owns schema webauthn and rejects shared RP tenancy.
type Config struct {
	Coordinator   kernel.CoordinatorConfig
	PolicyID      string
	PolicyVersion uint64
}

func (Config) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("webauthnpostgres.Config(redacted)"))
}

// Store owns no connection/goroutine lifetime. Concurrent methods use separate
// immutable native invocation phases and the sole public identity coordinator.
// Never supply replicas. The caller owns pool shutdown and migration sequencing.
type Store struct {
	pool      *database.Pool
	directory *kernel.Repository
	config    func() Config
}

func (Store) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("webauthnpostgres.Store(redacted)")) }

var _ webauthn.Store = (*Store)(nil)
var _ webauthn.DiscoverableStore = (*Store)(nil)

// New validates the concrete durable composition without IO. Constructors retain
// no Work, transaction or foreign coordinator. Each execution freezes the same
// public native participants before reservation, following the owning kernel.
func New(pool *database.Pool, c Config) (*Store, error) {
	if pool == nil || pool.Raw() == nil || c.PolicyID == "" || len(c.PolicyID) > 128 || c.PolicyVersion == 0 || c.Coordinator.QueryPolicy == nil {
		return nil, webauthn.Invalid{Field: "postgres_configuration"}
	}
	c.Coordinator.RetainedFingerprintKeys = maps.Clone(c.Coordinator.RetainedFingerprintKeys)
	query := *c.Coordinator.QueryPolicy
	c.Coordinator.QueryPolicy = &query
	d, e := kernel.NewRepository(pool, kernel.Config{MaximumDuration: c.Coordinator.MaximumDuration})
	if e != nil {
		return nil, webauthn.Invalid{Field: "postgres_configuration"}
	}
	s := &Store{pool: pool, directory: d, config: func() Config { return c }}
	if _, _, e = s.runtime(&phase{store: s}); e != nil {
		return nil, webauthn.Invalid{Field: "postgres_configuration"}
	}
	return s, nil
}
func (s *Store) runtime(p *phase) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	a, e := auditpg.NewIdentityContributor(auditpg.Config{})
	if e != nil {
		return nil, nil, e
	}
	l, e := lifecyclepg.NewContributor()
	if e != nil {
		return nil, nil, e
	}
	r, e := kernel.NewContributorRegistry([]kernel.Contributor{s.directory, a, l, p})
	if e != nil {
		return nil, nil, e
	}
	c, e := kernel.NewCoordinator(s.pool, r, s.config().Coordinator)
	return c, r, e
}
func operation(name string) identity.FeatureOperation {
	op := identity.FeatureOperation{Owner: "webauthn", OperationID: "webauthn." + name, SchemaID: "webauthn-ceremony-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	if name == "begin-get-discoverable" || name == "assert-discoverable" {
		op.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
	}
	return op
}
func descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "webauthn/postgres", ContractID: "webauthn.ceremony", Version: 1}
}
func targetID(id []byte) string {
	h := sha256.Sum256(id)
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func (s *Store) command(p *phase, c webauthn.CeremonyContext, name, record string, payload any, before, after uint64) error {
	op := operation(name)
	b := identity.CommandBinding{CommandID: c.CommandID, TenantID: c.TenantID, UserID: c.UserID, AnonymousFlowID: c.AnonymousFlowID, ActorID: c.ActorID, ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID, PolicyID: s.config().PolicyID, PolicyVersion: s.config().PolicyVersion, SchemaID: op.SchemaID, SchemaVersion: 1, CorrelationID: c.CorrelationID, RecordID: record}
	wire, e := json.Marshal(payload)
	if e != nil || len(wire) > 262144 {
		return webauthn.Invalid{Field: "transition"}
	}
	digest := sha256.Sum256(wire)
	clear(wire)
	command, e := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{{Name: "transition.digest", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}}}})
	if e != nil {
		return webauthn.Invalid{Field: "command"}
	}
	p.command, p.binding, p.before, p.after = command, b, before, after
	coordinator, registry, e := s.runtime(p)
	if e != nil {
		return webauthn.Unavailable{}
	}
	p.coordinator = coordinator
	// The kernel owns audit IDs/redaction and stages these exact declarations;
	// this seed computes only its canonical binding, not a second event store.
	builder, e := audit.NewBuilder(audit.BuilderConfig{})
	if e != nil {
		return webauthn.Unavailable{}
	}
	seed, e := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC().Truncate(time.Microsecond), Action: b.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "webauthn", ID: record}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "webauthn", "aggregate.id": record, "aggregate.before_version": strconv.FormatUint(before, 10), "aggregate.after_version": strconv.FormatUint(after, 10), "retention.class": "protected"}})
	if e != nil {
		return webauthn.Unavailable{}
	}
	binding, e := kernel.FeatureAuditBindingDigest(b, op, "webauthn", seed)
	if e != nil {
		return webauthn.Unavailable{}
	}
	plan := kernel.CommandPlan{Contributors: registry.Descriptors(), Feature: &kernel.FeatureRegistration{Contributor: descriptor(), Operation: op}, SubjectType: "webauthn", Lifecycle: &kernel.LifecyclePlan{EventType: op.OperationID + ".v1", BeforeVersion: before, AfterVersion: after}, Audits: []kernel.AuditPlan{{EventType: op.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: binding}}}
	p.plan, e = coordinator.PrepareCommandPlan(b, command, plan)
	if e != nil {
		return webauthn.Invalid{Field: "command_plan"}
	}
	return nil
}
func (s *Store) execute(ctx context.Context, p *phase) (identity.CommitOutcome, error) {
	r, result, e := p.coordinator.ReserveCommand(ctx, p.binding, p.command, p.plan)
	if e != nil || r == (kernel.Reservation{}) {
		return result.Outcome, translate(e)
	}
	if p.creation != nil {
		var now time.Time
		if e = s.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); e != nil {
			return identity.CommitOutcomeUnknown, webauthn.Unavailable{}
		}
		p.ceremony, p.challenge, e = p.creation.Generate(ctx, now)
		if e != nil {
			return identity.CommitOutcomeUnknown, e
		}
	}
	w, e := p.coordinator.Begin(ctx, r)
	if e != nil {
		p.challenge.Discard()
		return identity.CommitOutcomeUnknown, translate(e)
	}
	defer p.coordinator.Abort(w, identity.UnavailableError{})
	provisional, e := p.coordinator.ApplyFeature(ctx, w, p.command)
	if e != nil {
		result, e = p.coordinator.Abort(w, e)
	} else {
		result, e = p.coordinator.Commit(w, provisional)
	}
	if result.Outcome != identity.CommitOutcomeCommitted || e != nil {
		p.challenge.Discard()
	}
	return result.Outcome, translate(e)
}

func (s *Store) CreateCeremony(ctx context.Context, c webauthn.CeremonyCreation) (webauthn.CeremonyRecord, webauthn.Challenge, identity.CommitOutcome, error) {
	i, e := c.Intent()
	if e != nil || ctx == nil || !s.usable() {
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, identity.CommitOutcomeInvalid, webauthn.Invalid{Field: "creation"}
	}
	p := &phase{store: s, creation: &c}
	if e = s.command(p, i.Context, "begin-"+i.Kind, string(i.Context.CommandID), i, 0, 1); e != nil {
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, identity.CommitOutcomeInvalid, e
	}
	ctx, cancel := context.WithTimeout(ctx, s.config().Coordinator.MaximumDuration)
	defer cancel()
	out, e := s.execute(ctx, p)
	if e != nil || out != identity.CommitOutcomeCommitted {
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, out, e
	}
	if p.ceremony.ID != "" {
		return p.ceremony, p.challenge, out, nil
	}
	r, e := s.LoadCeremony(ctx, webauthn.Lookup{Context: i.Context, RPID: i.RPID, CeremonyID: string(i.Context.CommandID)})
	return r, webauthn.Challenge{}, out, e
}
func (s *Store) FinalizeRegistration(ctx context.Context, t webauthn.RegistrationTransition) (webauthn.Credential, identity.CommitOutcome, error) {
	m, e := t.Mutation()
	if e != nil || ctx == nil || !s.usable() {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, webauthn.Invalid{Field: "registration"}
	}
	p := &phase{store: s, registration: &m, ceremony: m.Ceremony}
	if e = s.command(p, m.Context, "register", targetID(m.Credential.ID), m, 0, 1); e != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, e
	}
	ctx, cancel := context.WithTimeout(ctx, s.config().Coordinator.MaximumDuration)
	defer cancel()
	out, e := s.execute(ctx, p)
	if e != nil || out != identity.CommitOutcomeCommitted {
		return webauthn.Credential{}, out, e
	}
	if !p.applied {
		return webauthn.Credential{}, out, webauthn.Replay{CommandID: m.Context.CommandID}
	}
	return m.Credential, out, nil
}
func (s *Store) FinalizeAssertion(ctx context.Context, t webauthn.AssertionTransition) (webauthn.Credential, identity.CommitOutcome, error) {
	m, e := t.Mutation()
	if e != nil || ctx == nil || !s.usable() {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, webauthn.Invalid{Field: "assertion"}
	}
	p := &phase{store: s, assertion: &m, ceremony: m.Ceremony}
	name := "assert"
	if m.Ceremony.Intent.Kind == "get-discoverable" {
		name = "assert-discoverable"
	}
	if e = s.command(p, m.Context, name, targetID(m.Before.ID), m, m.Before.Version, m.After.Version); e != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, e
	}
	ctx, cancel := context.WithTimeout(ctx, s.config().Coordinator.MaximumDuration)
	defer cancel()
	out, e := s.execute(ctx, p)
	if e != nil || out != identity.CommitOutcomeCommitted {
		return webauthn.Credential{}, out, e
	}
	if !p.applied {
		return webauthn.Credential{}, out, webauthn.Replay{CommandID: m.Context.CommandID}
	}
	return m.After, out, nil
}
func (s *Store) LoadCeremony(ctx context.Context, q webauthn.Lookup) (webauthn.CeremonyRecord, error) {
	if ctx == nil || !s.usable() {
		return webauthn.CeremonyRecord{}, webauthn.Invalid{Field: "lookup"}
	}
	ctx, cancel := context.WithTimeout(ctx, s.config().Coordinator.MaximumDuration)
	defer cancel()
	var wire []byte
	e := s.pool.Raw().QueryRow(ctx, `SELECT record FROM webauthn.ceremonies WHERE ceremony_id=$1 AND tenant_id=$2 AND COALESCE(user_id,'')=$3 AND rp_id=$4 AND COALESCE(anonymous_flow_id,'')=$5`, q.CeremonyID, string(q.Context.TenantID), string(q.Context.UserID), q.RPID, q.Context.AnonymousFlowID).Scan(&wire)
	var r webauthn.CeremonyRecord
	if e != nil {
		return r, translate(e)
	}
	if len(wire) > 262144 || json.Unmarshal(wire, &r) != nil {
		return r, webauthn.Unavailable{}
	}
	return r, nil
}
func (s *Store) LoadCredential(ctx context.Context, q webauthn.Lookup, id []byte) (webauthn.Credential, error) {
	if ctx == nil || !s.usable() || len(id) == 0 || len(id) > 1024 {
		return webauthn.Credential{}, webauthn.Invalid{Field: "lookup"}
	}
	ctx, cancel := context.WithTimeout(ctx, s.config().Coordinator.MaximumDuration)
	defer cancel()
	var wire []byte
	// An exact original assertion retry uses retained pre-transition public
	// input, never today's counter rebased as historical verification evidence.
	// The selected native passkey participant records that same input under
	// its actual parent purpose, so its sole coordinator can classify replay.
	var retainedCeremony []byte
	var actor, purpose string
	e := s.pool.Raw().QueryRow(ctx, `SELECT before_credential,ceremony,actor_id,purpose FROM webauthn.effects WHERE command_id=$1 AND tenant_id=$2 AND user_id=$3 AND purpose IN ('webauthn.assert','identity.passkey.signin-verify') AND ceremony_id=$5 AND before_credential->>'RPID'=$6 AND (actor_id=$4 OR (purpose='identity.passkey.signin-verify' AND actor_id=user_id AND ceremony->'Intent'->'Context'->>'ActorID'=$4)) AND EXISTS(SELECT 1 FROM webauthn.credentials c WHERE c.rp_id=$6 AND c.credential_id=$7 AND c.tenant_id=$2 AND c.user_id=$3 AND COALESCE(c.record->>'PublicKey','')<>'')`, string(q.Context.CommandID), string(q.Context.TenantID), string(q.Context.UserID), string(q.Context.ActorID), q.CeremonyID, q.RPID, id).Scan(&wire, &retainedCeremony, &actor, &purpose)
	if errors.Is(e, pgx.ErrNoRows) {
		e = s.pool.Raw().QueryRow(ctx, `SELECT record FROM webauthn.credentials WHERE rp_id=$1 AND credential_id=$2 AND tenant_id=$3 AND user_id=$4 AND COALESCE(record->>'PublicKey','')<>''`, q.RPID, id, string(q.Context.TenantID), string(q.Context.UserID)).Scan(&wire)
	}
	var c webauthn.Credential
	if e != nil {
		return c, translate(e)
	}
	if len(wire) > 32768 || json.Unmarshal(wire, &c) != nil || !bytes.Equal(c.ID, id) || len(c.PublicKey) == 0 {
		return c, webauthn.Unavailable{}
	}
	if actor != "" && actor != string(q.Context.ActorID) {
		// Only native identified preauth assertions bridge service protocol
		// attribution to their verified self-human parent. Check the complete
		// retained ceremony, not caller-supplied context or a JSON actor alone.
		var ceremony webauthn.CeremonyRecord
		if purpose != "identity.passkey.signin-verify" || actor != string(q.Context.UserID) || len(retainedCeremony) > 262144 || json.Unmarshal(retainedCeremony, &ceremony) != nil || !assertionIntent(ceremony.Intent, true) || ceremony.ID != q.CeremonyID || ceremony.Intent.RPID != q.RPID || ceremony.Intent.Context.TenantID != q.Context.TenantID || ceremony.Intent.Context.UserID != q.Context.UserID || ceremony.Intent.Context.ActorID != q.Context.ActorID || q.Context.AnonymousFlowID != "" || ceremony.Version == 0 || ceremony.ChallengeDigest == ([32]byte{}) || ceremony.ExpiresAt.IsZero() || c.TenantID != q.Context.TenantID || c.UserID != q.Context.UserID || c.RPID != q.RPID || c.Version == 0 || !bytes.Equal(c.UserHandle, ceremony.Intent.UserHandle) {
			return webauthn.Credential{}, webauthn.Denied{}
		}
	}
	return c, nil
}

// LoadDiscoverableCredential resolves a mandatory RP-wide credential/handle
// mapping within a trusted tenant and pre-auth ceremony. It grants no authority;
// the participant rechecks active subject and mapping at finalization.
func (s *Store) LoadDiscoverableCredential(ctx context.Context, q webauthn.Lookup, id, handle []byte) (webauthn.Credential, error) {
	if ctx == nil || !s.usable() || q.Context.UserID != "" || q.Context.AnonymousFlowID == "" || len(id) == 0 || len(id) > 1024 || len(handle) != 32 {
		return webauthn.Credential{}, webauthn.Invalid{Field: "lookup"}
	}
	ctx, cancel := context.WithTimeout(ctx, s.config().Coordinator.MaximumDuration)
	defer cancel()
	var wire []byte
	var retainedCeremony []byte
	var actor, purpose, target string
	e := s.pool.Raw().QueryRow(ctx, `SELECT before_credential,ceremony,actor_id,purpose,COALESCE(user_id,'') FROM webauthn.effects WHERE command_id=$1 AND tenant_id=$2 AND ceremony_id=$5 AND before_credential->>'RPID'=$6 AND ((purpose='webauthn.assert-discoverable' AND user_id IS NULL AND anonymous_flow_id=$3 AND actor_id=$4) OR (purpose='identity.passkey.signin-verify' AND actor_id=user_id AND anonymous_flow_id IS NULL AND ceremony->'Intent'->'Context'->>'AnonymousFlowID'=$3 AND ceremony->'Intent'->'Context'->>'ActorID'=$4)) AND EXISTS(SELECT 1 FROM webauthn.credentials c WHERE c.rp_id=$6 AND c.credential_id=$7 AND c.user_handle=$8 AND c.tenant_id=$2 AND COALESCE(c.record->>'PublicKey','')<>'')`, string(q.Context.CommandID), string(q.Context.TenantID), q.Context.AnonymousFlowID, string(q.Context.ActorID), q.CeremonyID, q.RPID, id, handle).Scan(&wire, &retainedCeremony, &actor, &purpose, &target)
	if errors.Is(e, pgx.ErrNoRows) {
		e = s.pool.Raw().QueryRow(ctx, `SELECT c.record FROM webauthn.credentials c JOIN webauthn.user_handles h ON h.rp_id=c.rp_id AND h.user_handle=c.user_handle AND h.tenant_id=c.tenant_id AND h.user_id=c.user_id JOIN webauthn.relying_parties r ON r.rp_id=c.rp_id AND r.tenant_id=c.tenant_id WHERE c.rp_id=$1 AND c.credential_id=$2 AND c.user_handle=$3 AND c.tenant_id=$4 AND COALESCE(c.record->>'PublicKey','')<>''`, q.RPID, id, handle, string(q.Context.TenantID)).Scan(&wire)
	}
	var c webauthn.Credential
	if e != nil {
		return c, translate(e)
	}
	if len(wire) > 32768 || json.Unmarshal(wire, &c) != nil || len(c.PublicKey) == 0 || !bytes.Equal(c.ID, id) || !bytes.Equal(c.UserHandle, handle) || c.TenantID != q.Context.TenantID || c.RPID != q.RPID {
		return webauthn.Credential{}, webauthn.Denied{}
	}
	if purpose == "identity.passkey.signin-verify" {
		// Native finalization belongs to the verified self-human parent, but
		// retries remain in their original anonymous service/flow. Neither a
		// caller-selected target nor a JSON actor alone selects that history.
		var ceremony webauthn.CeremonyRecord
		if target == "" || actor != target || string(c.UserID) != target || c.Algorithm != int32(webauthn.ES256) || c.Version == 0 || len(retainedCeremony) > 262144 || json.Unmarshal(retainedCeremony, &ceremony) != nil || !discoverableAssertionIntent(ceremony.Intent) || ceremony.ID != q.CeremonyID || ceremony.Intent.RPID != q.RPID || ceremony.Intent.Context.TenantID != q.Context.TenantID || ceremony.Intent.Context.ActorID != q.Context.ActorID || ceremony.Intent.Context.AnonymousFlowID != q.Context.AnonymousFlowID || ceremony.Version == 0 || ceremony.ChallengeDigest == ([32]byte{}) || ceremony.ExpiresAt.IsZero() {
			return webauthn.Credential{}, webauthn.Denied{}
		}
	}
	return c, nil
}
func translate(e error) error {
	if e == nil {
		return nil
	}
	var conflict identity.ConflictError
	var denied identity.ForbiddenError
	if errors.As(e, &conflict) {
		return webauthn.Conflict{}
	}
	if errors.As(e, &denied) {
		return webauthn.Denied{}
	}
	return webauthn.Unavailable{}
}

// Recover reconciles only the original exact scope through the sole kernel
// owner. It cannot execute a new command or recover missing challenge bytes.
func (s *Store) Recover(ctx context.Context, r webauthn.RecoveryRequest) (identity.CommitOutcome, error) {
	if !s.usable() || ctx == nil {
		return identity.CommitOutcomeInvalid, webauthn.Invalid{Field: "recovery"}
	}
	name := ""
	record := string(r.Context.CommandID)
	switch r.Operation {
	case webauthn.BeginRegistrationOperation:
		name = "begin-create"
	case webauthn.BeginAssertionOperation:
		name = "begin-get"
	case webauthn.RegistrationOperation:
		name = "register"
		record = targetID(r.CredentialID)
	case webauthn.AssertionOperation:
		name = "assert"
		record = targetID(r.CredentialID)
	case webauthn.BeginDiscoverableAssertionOperation:
		name = "begin-get-discoverable"
	case webauthn.DiscoverableAssertionOperation:
		name = "assert-discoverable"
		record = targetID(r.CredentialID)
	default:
		return identity.CommitOutcomeInvalid, webauthn.Invalid{Field: "recovery"}
	}
	p := &phase{store: s}
	c, _, e := s.runtime(p)
	if e != nil {
		return identity.CommitOutcomeInvalid, webauthn.Unavailable{}
	}
	q := identity.RecoveryQuery{CommandID: r.Context.CommandID, TenantID: r.Context.TenantID, UserID: r.Context.UserID, AnonymousFlowID: r.Context.AnonymousFlowID, ActorID: r.Context.ActorID, ActorKind: authorization.SubjectServiceAccount, OperationID: operation(name).OperationID, RecordID: record}
	subject := string(q.UserID)
	resourceType := authorization.ResourceType("identity.user")
	if q.AnonymousFlowID != "" {
		subject = q.AnonymousFlowID
		resourceType = "identity.anonymous-flow"
	}
	caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(s.config().Coordinator.QueryPolicy.PolicyVersion), Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(q.ActorID), Kind: q.ActorKind}, Tenant: authorization.TenantID(q.TenantID), Action: authorization.Action(q.OperationID), Resource: authorization.Resource{Type: resourceType, ID: authorization.ResourceID(subject)}}}
	out, e := c.RecoverCommand(ctx, q, caller)
	// The public kernel deliberately withholds its CommandRecord on an
	// uncertain reconciliation COMMIT and returns typed UnknownCommitError.
	// Preserve that outcome and the original request identity at this seam;
	// flattening it through translate would falsely expose the invalid zero.
	var unknown identity.UnknownCommitError
	if errors.As(e, &unknown) {
		return identity.CommitOutcomeUnknown, webauthn.UnknownCommit{CommandID: r.Context.CommandID}
	}
	return out.Outcome, translate(e)
}

func (s *Store) usable() bool { return s != nil && s.pool != nil && s.config != nil }
