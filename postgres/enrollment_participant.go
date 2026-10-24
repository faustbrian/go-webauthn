package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	webauthn "github.com/faustbrian/go-webauthn"
	"github.com/jackc/pgx/v5"
)

const enrollmentField = "webauthn.enrollment.intent"

// EnrollmentAssertionCreation selects session-bound, self-human enrollment
// reauthentication options, never signin or password-proof enrollment. Copies
// share serial invocation and challenge custody. The parent owns current
// session, CSRF, risk and policy admission and must defer Discard.
type EnrollmentAssertionCreation struct{ *enrollmentPhase }

// EnrollmentAuthorization consumes one genuine verified enrollment assertion
// and creates its registration ceremony in the same parent Work. It owns no
// transaction, proof store or session. Copies share serial generation/reveal
// custody; zero values deny. The parent must defer Discard on every path.
type EnrollmentAuthorization struct{ *enrollmentPhase }

// SessionRegistrationFinalization accepts a genuine registration only when its
// ceremony was created by EnrollmentAuthorization. Its source assertion's
// original absolute expiry remains an enforced ceiling through final precommit.
// The parent owns identity mapping, metadata and all current session authority.
type SessionRegistrationFinalization struct{ *enrollmentPhase }

// Fields binds only the original A intent and grants no enrollment authority.
func (p *EnrollmentAssertionCreation) Fields() ([]identity.FeatureField, error) {
	if p == nil {
		return nil, webauthn.Invalid{Field: "enrollment_participant"}
	}
	return p.enrollmentPhase.Fields()
}

// Fields binds both genuine opaque B inputs as one original command intent.
func (p *EnrollmentAuthorization) Fields() ([]identity.FeatureField, error) {
	if p == nil {
		return nil, webauthn.Invalid{Field: "enrollment_participant"}
	}
	return p.enrollmentPhase.Fields()
}

// Fields binds the genuine original C registration transition.
func (p *SessionRegistrationFinalization) Fields() ([]identity.FeatureField, error) {
	if p == nil {
		return nil, webauthn.Invalid{Field: "enrollment_participant"}
	}
	return p.enrollmentPhase.Fields()
}

// Validate checks the exact A profile and original input without IO.
func (p *EnrollmentAssertionCreation) Validate(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil {
		return webauthn.Invalid{Field: "enrollment_participant"}
	}
	return p.enrollmentPhase.Validate(c, plan)
}

// Validate checks the exact B profile and combined original input without IO.
func (p *EnrollmentAuthorization) Validate(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil {
		return webauthn.Invalid{Field: "enrollment_participant"}
	}
	return p.enrollmentPhase.Validate(c, plan)
}

// Validate checks the exact C profile and original verified input without IO.
func (p *SessionRegistrationFinalization) Validate(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil {
		return webauthn.Invalid{Field: "enrollment_participant"}
	}
	return p.enrollmentPhase.Validate(c, plan)
}

// Apply stages A options only in its actual parent's Work; errors must abort it.
func (p *EnrollmentAssertionCreation) Apply(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) error {
	if p == nil {
		return webauthn.Invalid{Field: "enrollment_participant"}
	}
	return p.enrollmentPhase.Apply(ctx, w, owner, c)
}

// Apply stages both B effects only in its actual parent's Work; errors abort it.
func (p *EnrollmentAuthorization) Apply(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) error {
	if p == nil {
		return webauthn.Invalid{Field: "enrollment_participant"}
	}
	return p.enrollmentPhase.Apply(ctx, w, owner, c)
}

// Apply consumes authorized C only in its actual parent's Work; errors abort it.
func (p *SessionRegistrationFinalization) Apply(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) error {
	if p == nil {
		return webauthn.Invalid{Field: "enrollment_participant"}
	}
	return p.enrollmentPhase.Apply(ctx, w, owner, c)
}

// Check repeats A's current identity and absolute expiry at final precommit.
func (p *EnrollmentAssertionCreation) Check(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) error {
	if p == nil {
		return webauthn.Invalid{Field: "enrollment_participant"}
	}
	return p.enrollmentPhase.Check(ctx, w, owner, c)
}

// Check repeats B's current credential and original source expiry at precommit.
func (p *EnrollmentAuthorization) Check(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) error {
	if p == nil {
		return webauthn.Invalid{Field: "enrollment_participant"}
	}
	return p.enrollmentPhase.Check(ctx, w, owner, c)
}

// Check repeats C's exact persisted source authority and expiry at precommit.
func (p *SessionRegistrationFinalization) Check(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) error {
	if p == nil {
		return webauthn.Invalid{Field: "enrollment_participant"}
	}
	return p.enrollmentPhase.Check(ctx, w, owner, c)
}

// Discard idempotently clears every unreleased A challenge alias.
func (p *EnrollmentAssertionCreation) Discard() {
	if p != nil {
		p.enrollmentPhase.Discard()
	}
}

// Discard idempotently clears every unreleased B registration challenge alias.
func (p *EnrollmentAuthorization) Discard() {
	if p != nil {
		p.enrollmentPhase.Discard()
	}
}

type enrollmentPhase struct {
	p      *phase
	source *phase
	input  webauthn.CeremonyCreation
	digest [32]byte
	stage  int
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
func enrollmentLifecycle(stage int, l *kernel.LifecyclePlan) bool {
	return l != nil && stage >= 0 && stage <= 2 && l.EventIndex == 0 && l.BeforeVersion == 0 && l.AfterVersion == 1 && l.EventType == []string{"passkey.reauthentication.started.v1", "passkey.registration.started.v1", "identity.passkey.create_credential"}[stage]
}

// EnrollmentAssertionCreation borrows the real root service's opaque identified
// ES256 creation. No caller-assembled ceremony or boolean freshness is accepted.
func (s *Store) EnrollmentAssertionCreation(input webauthn.CeremonyCreation) (*EnrollmentAssertionCreation, error) {
	p, err := s.assertionCreation(input, false)
	if err != nil {
		return nil, err
	}
	return &EnrollmentAssertionCreation{&enrollmentPhase{p: p.phase, input: input, digest: p.digest}}, nil
}

// EnrollmentAuthorization accepts only real root-verifier assertion output and
// real root-service registration creation from that same invocation Context.
// The original assertion ceremony belongs to A, not the new B command. Both
// effects are staged together; neither result is exposed before acknowledged B.
func (s *Store) EnrollmentAuthorization(assertion webauthn.AssertionTransition, creation webauthn.CeremonyCreation) (*EnrollmentAuthorization, error) {
	a, err := s.assertionFinalization(assertion, false)
	if err != nil {
		return nil, err
	}
	c, err := s.RegistrationCreation(creation)
	if err != nil {
		return nil, err
	}
	m := a.phase.assertion
	i, _ := creation.Intent()
	original := m.Ceremony.Intent
	if m.CounterRisk || m.Context != i.Context || m.Ceremony.ID == string(i.Context.CommandID) || original.RPID != i.RPID || original.RPVersion != i.RPVersion || original.Origin != i.Origin || original.Extensions != i.Extensions || !slices.Equal(original.Algorithms, i.Algorithms) || !bytes.Equal(original.UserHandle, i.UserHandle) || m.Ceremony.ExpiresAt.IsZero() {
		return nil, webauthn.Denied{}
	}
	digest, err := assertionDigest(struct {
		Assertion webauthn.AssertionMutation
		Creation  webauthn.CeremonyIntent
	}{*m, i})
	if err != nil {
		return nil, err
	}
	return &EnrollmentAuthorization{&enrollmentPhase{p: c.phase, source: a.phase, input: creation, digest: digest, stage: 1}}, nil
}

// SessionRegistrationFinalization selects the matching native C profile. The
// genuine source authorization is checked in the parent's Work, not trusted
// from application metadata or reconstructed from a fresh ceremony expiry.
func (s *Store) SessionRegistrationFinalization(input webauthn.RegistrationTransition) (*SessionRegistrationFinalization, error) {
	p, err := s.RegistrationFinalization(input)
	if err != nil {
		return nil, err
	}
	p.phase.sessionRegistration = true
	return &SessionRegistrationFinalization{&enrollmentPhase{p: p.phase, digest: p.digest, stage: 2}}, nil
}

func (p *enrollmentPhase) usable() bool {
	return p != nil && p.p != nil && p.p.store != nil && p.stage >= 0 && p.stage <= 2
}
func (p *enrollmentPhase) scope() (webauthn.CeremonyContext, error) {
	if !p.usable() {
		return webauthn.CeremonyContext{}, webauthn.Invalid{Field: "enrollment_participant"}
	}
	if p.stage == 2 {
		return p.p.registration.Context, nil
	}
	i, err := p.input.Intent()
	return i.Context, err
}
func (p *enrollmentPhase) field() string {
	if p.stage == 0 {
		return assertionField
	}
	if p.stage == 2 {
		return registrationField
	}
	return enrollmentField
}

// Fields binds the complete immutable selected input into the original parent
// command. The digest contains no browser bytes and grants no authority.
func (p *enrollmentPhase) Fields() ([]identity.FeatureField, error) {
	if !p.usable() || p.digest == ([32]byte{}) {
		return nil, webauthn.Invalid{Field: "enrollment_participant"}
	}
	return []identity.FeatureField{{Name: p.field(), Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: bytes.Clone(p.digest[:])}}}, nil
}

// Validate is pure selected-profile and original-intent validation. It performs
// no IO, generates no entropy and admits no current identity authority.
func (p *enrollmentPhase) Validate(c identity.Command, plan kernel.CommandPlan) error {
	scope, err := p.scope()
	if err != nil {
		return err
	}
	s, ok := c.Feature()
	if !ok || s.Operation != enrollmentOperation(p.stage) || plan.Feature == nil || plan.Feature.Operation != s.Operation || plan.Feature.Contributor != registrationDescriptor() || !enrollmentLifecycle(p.stage, plan.Lifecycle) {
		return webauthn.Invalid{Field: "enrollment_parent"}
	}
	b := s.Binding
	if b.CommandID != scope.CommandID || b.TenantID != scope.TenantID || b.UserID != scope.UserID || b.ActorID != scope.ActorID || b.ActorKind != authorization.SubjectUser || b.AnonymousFlowID != "" || b.CorrelationID != scope.CorrelationID || !registrationContext(scope) {
		return webauthn.Denied{}
	}
	found := false
	for _, f := range s.Fields {
		if !strings.HasPrefix(f.Name, "webauthn.") {
			continue
		}
		if found || f.Name != p.field() || f.Value.Kind != identity.FeatureBytes || !bytes.Equal(f.Value.Bytes, p.digest[:]) {
			return webauthn.Invalid{Field: "enrollment_intent"}
		}
		found = true
	}
	if !found {
		return webauthn.Invalid{Field: "enrollment_intent"}
	}
	return nil
}
func (p *enrollmentPhase) bind(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command, apply bool) error {
	if !p.usable() || ctx == nil || owner == nil {
		return webauthn.Invalid{Field: "enrollment_work"}
	}
	if apply {
		if err := w.RequireFeatureCommand(ctx, owner, c); err != nil {
			return err
		}
	}
	b, f, l, err := w.FeatureScope(owner)
	if err != nil {
		return err
	}
	if err = p.Validate(c, kernel.CommandPlan{Feature: &f, Lifecycle: &l}); err != nil {
		return err
	}
	if !apply {
		if p.p.command != c || p.p.binding != b {
			return webauthn.Conflict{}
		}
		return nil
	}
	if p.p.command != (identity.Command{}) {
		return webauthn.Conflict{}
	}
	p.p.command, p.p.binding, p.p.before, p.p.after = c, b, 0, 1
	if p.source != nil {
		p.source.command, p.source.binding, p.source.before, p.source.after = c, b, 0, 1
	}
	return nil
}

// Generate runs once after acknowledged reservation, before Work, using the
// parent's actual primary database time. It cannot renew the source assertion.
func (p *enrollmentPhase) generate(ctx context.Context, now time.Time) error {
	if !p.usable() || p.stage == 2 || p.p.participantGenerated || p.p.participantReleased {
		return webauthn.Invalid{Field: "enrollment_generation"}
	}
	p.p.participantGenerated = true
	if p.source != nil && (!now.Before(p.source.ceremony.ExpiresAt) || now.Before(p.source.ceremony.ExpiresAt.Add(-5*time.Minute))) {
		return webauthn.Denied{}
	}
	r, ch, err := p.input.Generate(ctx, now)
	if err != nil {
		return err
	}
	p.p.ceremony, p.p.challenge = r, ch
	return nil
}

// Generate creates original A entropy once after acknowledged reservation and
// before the parent's Work opens. Recovery and retry must never call it.
func (p *EnrollmentAssertionCreation) Generate(ctx context.Context, now time.Time) error {
	if p == nil {
		return webauthn.Invalid{Field: "enrollment_generation"}
	}
	return p.enrollmentPhase.generate(ctx, now)
}

// Generate creates original B registration entropy once without renewing the
// genuine source assertion expiry, after reservation and outside parent Work.
func (p *EnrollmentAuthorization) Generate(ctx context.Context, now time.Time) error {
	if p == nil {
		return webauthn.Invalid{Field: "enrollment_generation"}
	}
	return p.enrollmentPhase.generate(ctx, now)
}

// AuthorizationExpiresAt returns only the genuine source assertion's original
// expiry, never the new registration TTL. Zero means invalid custody.
func (p *EnrollmentAuthorization) AuthorizationExpiresAt() time.Time {
	if p == nil || !p.usable() || p.source == nil {
		return time.Time{}
	}
	return p.source.ceremony.ExpiresAt
}

func (p *enrollmentPhase) sourceCurrent(ctx context.Context, w kernel.Work) error {
	m := p.source.assertion
	wire, err := json.Marshal(m.Ceremony)
	if err != nil {
		return webauthn.Denied{}
	}
	rows, err := w.Query(ctx, `SELECT 1 FROM webauthn.effects e JOIN webauthn.ceremonies a ON a.ceremony_id=e.ceremony_id WHERE e.command_id=$1 AND e.enrollment_stage=1 AND e.purpose='identity.passkey.register-options' AND e.tenant_id=$2 AND e.user_id=$3 AND e.actor_id=$4 AND e.ceremony_id=$1 AND e.ceremony=$5::jsonb AND a.record=e.ceremony AND a.authorization_expires_at IS NULL`, m.Ceremony.ID, string(m.Context.TenantID), string(m.Context.UserID), string(m.Context.ActorID), string(wire))
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		if err = rows.Err(); err != nil {
			return err
		}
		return webauthn.Denied{}
	}
	return rows.Err()
}

// Apply stages every protocol effect inside the existing parent Work. Any
// error must abort the parent; it never opens or commits another transaction.
func (p *enrollmentPhase) Apply(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) error {
	if !p.usable() || p.p.participantReleased || p.p.applied || p.stage != 2 && !p.p.participantGenerated {
		return webauthn.Invalid{Field: "enrollment_apply"}
	}
	if err := p.bind(ctx, w, owner, c, true); err != nil {
		return err
	}
	if err := p.p.current(ctx, w); err != nil {
		return err
	}
	if p.stage == 1 {
		if err := p.sourceCurrent(ctx, w); err != nil {
			return err
		}
		if err := p.source.applyAssertion(ctx, w); err != nil {
			return err
		}
	}
	var err error
	if p.stage == 2 {
		err = p.p.checkEnrollmentAuthorization(ctx, w)
		if err == nil {
			err = p.p.applyRegistration(ctx, w)
		}
	} else {
		err = p.p.applyCreation(ctx, w)
	}
	if err != nil {
		return err
	}
	if p.stage == 1 {
		n, err := w.Exec(ctx, `UPDATE webauthn.ceremonies SET authorization_expires_at=$1,authorization_ceremony_id=$2 WHERE ceremony_id=$3 AND authorization_expires_at IS NULL`, p.source.ceremony.ExpiresAt, p.source.ceremony.ID, p.p.ceremony.ID)
		if err != nil {
			return err
		}
		if n != 1 {
			return webauthn.Conflict{}
		}
		// One effect row retains the new ceremony and the original assertion's
		// before/after states. The source ceremony below makes both identities
		// recoverable without changing the command-id primary key or old codec.
		p.p.assertion = p.source.assertion
	}
	if err = p.p.persistEvidenceFor(ctx, w, owner); err != nil {
		return err
	}
	var source any
	if p.source != nil {
		wire, e := json.Marshal(p.source.ceremony)
		if e != nil {
			return webauthn.Denied{}
		}
		source = string(wire)
	}
	n, err := w.Exec(ctx, `UPDATE webauthn.effects SET enrollment_stage=$1,enrollment_source=$2::jsonb WHERE command_id=$3 AND enrollment_stage IS NULL`, p.stage+1, source, string(p.p.binding.CommandID))
	if err != nil {
		return err
	}
	if n != 1 {
		return webauthn.Conflict{}
	}
	p.p.applied = true
	return p.Check(ctx, w, owner, c)
}

// Check repeats current protocol identity, credential and both absolute expiry
// fences during the parent's final precommit invocation. Parent session, MFA,
// mapping, directory and policy fences remain mandatory and separately owned.
func (p *enrollmentPhase) Check(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) error {
	if err := p.bind(ctx, w, owner, c, false); err != nil {
		return err
	}
	if !p.p.applied {
		return webauthn.Denied{}
	}
	if err := p.p.current(ctx, w); err != nil {
		return err
	}
	if err := p.p.checkAssertionCredential(ctx, w); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if !now.Before(p.p.ceremony.ExpiresAt) || now.Before(p.p.ceremony.ExpiresAt.Add(-5*time.Minute)) {
		return webauthn.Denied{}
	}
	if p.source != nil {
		if !now.Before(p.source.ceremony.ExpiresAt) || now.Before(p.source.ceremony.ExpiresAt.Add(-5*time.Minute)) {
			return webauthn.Denied{}
		}
		if err = p.sourceCurrent(ctx, w); err != nil {
			return err
		}
		return p.p.checkEnrollmentAuthorization(ctx, w)
	}
	if p.stage == 2 {
		return p.p.checkEnrollmentAuthorization(ctx, w)
	}
	return nil
}

func (p *enrollmentPhase) result(r identity.CommandResult) error {
	if !p.usable() || p.p.participantReleased {
		return webauthn.Invalid{Field: "enrollment_result"}
	}
	p.p.participantReleased = true
	if r.Outcome == identity.CommitOutcomeUnknown || r.Outcome == identity.CommitOutcomeInProgress {
		p.Discard()
		return webauthn.UnknownCommit{CommandID: r.Binding.CommandID}
	}
	if r.Outcome != identity.CommitOutcomeCommitted || r.Validate() != nil {
		p.Discard()
		return webauthn.Unavailable{}
	}
	if !p.p.applied {
		p.Discard()
		return webauthn.Replay{CommandID: r.Binding.CommandID}
	}
	if r.Binding != p.p.binding || r.Feature == nil || r.Feature.Operation != enrollmentOperation(p.stage) || r.Feature.BeforeVersion != 0 || r.Feature.AfterVersion != 1 {
		p.Discard()
		return webauthn.Unavailable{}
	}
	return nil
}

// Result transfers original A options exactly once, only after acknowledged
// parent commit. Unknown, failed and replayed commands never reveal a challenge.
func (p *EnrollmentAssertionCreation) Result(r identity.CommandResult) (webauthn.CeremonyRecord, webauthn.Challenge, error) {
	if p == nil || p.enrollmentPhase == nil {
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, webauthn.Invalid{Field: "enrollment_result"}
	}
	if err := p.result(r); err != nil {
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, err
	}
	ch := p.p.challenge
	p.p.challenge = webauthn.Challenge{}
	return p.p.ceremony, ch, nil
}

// Result transfers the original registration ceremony/challenge and finalized
// assertion credential together exactly once. Neither output is provisional;
// the real root callbacks must receive the actual parent coordinator receipt.
func (p *EnrollmentAuthorization) Result(r identity.CommandResult) (webauthn.CeremonyRecord, webauthn.Challenge, webauthn.Credential, error) {
	if p == nil || p.enrollmentPhase == nil {
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, webauthn.Credential{}, webauthn.Invalid{Field: "enrollment_result"}
	}
	if err := p.result(r); err != nil {
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, webauthn.Credential{}, err
	}
	ch := p.p.challenge
	p.p.challenge = webauthn.Challenge{}
	return p.p.ceremony, ch, p.source.assertion.After, nil
}

// Result returns one finalized registration credential to the genuine root
// verifier after acknowledged C commit, never on replay or ambiguous commit.
func (p *SessionRegistrationFinalization) Result(r identity.CommandResult) (webauthn.Credential, error) {
	if p == nil || p.enrollmentPhase == nil {
		return webauthn.Credential{}, webauthn.Invalid{Field: "enrollment_result"}
	}
	if err := p.result(r); err != nil {
		return webauthn.Credential{}, err
	}
	return p.p.registration.Credential, nil
}

// Discard clears all unreleased challenge aliases, including after cancellation
// and panic. It is idempotent and owns no goroutine or database lifetime.
func (p *enrollmentPhase) Discard() {
	if p != nil && p.p != nil {
		p.p.participantReleased = true
		p.p.challenge.Discard()
		p.p.challenge = webauthn.Challenge{}
	}
}

// Format prevents retained protocol inputs and result custody from escaping.
func (*enrollmentPhase) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("webauthnpostgres.EnrollmentParticipant(redacted)"))
}

// MarshalJSON rejects accidental export of retained protocol and command state.
func (*enrollmentPhase) MarshalJSON() ([]byte, error) {
	return nil, webauthn.Invalid{Field: "enrollment_participant"}
}

// RecoverEnrollment participates only in the original selected parent recovery.
// Any effect beneath a pending journal is unknown; absence proves noncommit.
// It never generates options or reconstructs a verified result. The parent must
// reconcile all its own metadata effects through its existing coordinator.
func (s *Store) RecoverEnrollment(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	if !s.usable() || ctx == nil {
		return kernel.RecoveryUnknown, webauthn.Invalid{Field: "enrollment_recovery"}
	}
	b, f, l, err := w.FeatureScope(owner)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	stage := -1
	for n := range 3 {
		if f.Operation == enrollmentOperation(n) {
			stage = n
		}
	}
	if stage < 0 || f.Contributor != registrationDescriptor() || !enrollmentLifecycle(stage, &l) || b.ActorKind != authorization.SubjectUser || b.UserID == "" || string(b.ActorID) != string(b.UserID) || b.AnonymousFlowID != "" {
		return kernel.RecoveryUnknown, webauthn.Denied{}
	}
	rows, err := w.Query(ctx, `SELECT 1 FROM webauthn.effects WHERE command_id=$1`, string(b.CommandID))
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

func (p *phase) checkEnrollmentAuthorization(ctx context.Context, w kernel.Work) error {
	r := p.ceremony
	wire, err := json.Marshal(r)
	if err != nil {
		return webauthn.Denied{}
	}
	// C consumes this row next. Taking its UPDATE lock now avoids two verified
	// contenders both taking SHARE and deadlocking on the consume lock upgrade.
	rows, err := w.Query(ctx, `SELECT 1 FROM webauthn.ceremonies c JOIN webauthn.effects b ON b.command_id=c.ceremony_id JOIN webauthn.ceremonies a ON a.ceremony_id=c.authorization_ceremony_id JOIN webauthn.effects ae ON ae.command_id=a.ceremony_id WHERE c.ceremony_id=$1 AND c.tenant_id=$2 AND c.user_id=$3 AND c.rp_id=$4 AND c.record=$5::jsonb AND c.authorization_expires_at>clock_timestamp() AND c.authorization_expires_at<=c.expires_at AND b.enrollment_stage=2 AND b.purpose='identity.passkey.register-options' AND b.tenant_id=c.tenant_id AND b.user_id=c.user_id AND b.actor_id=c.user_id AND b.ceremony_id=c.ceremony_id AND b.ceremony=c.record AND b.enrollment_source=a.record AND ae.enrollment_stage=1 AND ae.purpose='identity.passkey.register-options' AND ae.ceremony=a.record AND ae.tenant_id=c.tenant_id AND ae.user_id=c.user_id AND ae.actor_id=c.user_id AND a.consumed_by=c.ceremony_id AND a.expires_at=c.authorization_expires_at AND a.tenant_id=c.tenant_id AND a.user_id=c.user_id AND a.rp_id=c.rp_id FOR UPDATE OF c FOR SHARE OF b,a,ae`, r.ID, string(p.binding.TenantID), string(p.binding.UserID), r.Intent.RPID, string(wire))
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		if err = rows.Err(); err != nil {
			return err
		}
		return webauthn.Denied{}
	}
	return rows.Err()
}

// Exact B retries need the original verifier input so the existing coordinator
// can classify the original command. This snapshot is never current credential
// authority or permission to replay a consumed ceremony, and cannot resurrect a
// removed credential. It is scoped by both original A and original B identities.
func (s *Store) loadEnrollmentAssertionCredential(ctx context.Context, q webauthn.Lookup, id []byte) (webauthn.Credential, bool, error) {
	if !registrationContext(q.Context) || q.CeremonyID == "" {
		return webauthn.Credential{}, false, nil
	}
	var before, source []byte
	err := s.pool.Raw().QueryRow(ctx, `SELECT e.before_credential,e.enrollment_source FROM webauthn.effects e JOIN webauthn.ceremonies b ON b.ceremony_id=e.ceremony_id JOIN webauthn.ceremonies a ON a.ceremony_id=b.authorization_ceremony_id JOIN webauthn.effects ae ON ae.command_id=a.ceremony_id WHERE e.command_id=$1 AND e.enrollment_stage=2 AND e.purpose='identity.passkey.register-options' AND e.tenant_id=$2 AND e.user_id=$3 AND e.actor_id=$4 AND b.ceremony_id=e.command_id AND b.record=e.ceremony AND a.ceremony_id=$5 AND a.rp_id=$6 AND a.consumed_by=e.command_id AND a.record=e.enrollment_source AND ae.enrollment_stage=1 AND ae.ceremony=a.record AND EXISTS(SELECT 1 FROM webauthn.credentials c WHERE c.rp_id=$6 AND c.credential_id=$7 AND c.tenant_id=$2 AND c.user_id=$3 AND COALESCE(c.record->>'PublicKey','')<>'')`, string(q.Context.CommandID), string(q.Context.TenantID), string(q.Context.UserID), string(q.Context.ActorID), q.CeremonyID, q.RPID, id).Scan(&before, &source)
	if errors.Is(err, pgx.ErrNoRows) {
		return webauthn.Credential{}, false, nil
	}
	if err != nil {
		return webauthn.Credential{}, false, translate(err)
	}
	var c webauthn.Credential
	var r webauthn.CeremonyRecord
	if len(before) > 32768 || len(source) > 262144 || json.Unmarshal(before, &c) != nil || json.Unmarshal(source, &r) != nil || !assertionIntent(r.Intent, false) || r.ID != q.CeremonyID || r.Intent.Context.CommandID != identity.CommandID(r.ID) || r.Intent.Context.TenantID != q.Context.TenantID || r.Intent.Context.UserID != q.Context.UserID || r.Intent.Context.ActorID != q.Context.ActorID || r.Intent.RPID != q.RPID || r.Version != 1 || r.ChallengeDigest == ([32]byte{}) || r.ExpiresAt.IsZero() || c.TenantID != q.Context.TenantID || c.UserID != q.Context.UserID || c.RPID != q.RPID || c.Algorithm != int32(webauthn.ES256) || c.Version == 0 || len(c.PublicKey) == 0 || !bytes.Equal(c.ID, id) || !bytes.Equal(c.UserHandle, r.Intent.UserHandle) {
		return webauthn.Credential{}, true, webauthn.Denied{}
	}
	return c, true, nil
}
