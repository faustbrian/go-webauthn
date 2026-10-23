package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	webauthn "github.com/faustbrian/go-webauthn"
)

const assertionField = "webauthn.assertion.intent"

// AssertionCreation is one serial-use protocol participant for the native
// passkey signin-options owner. Copies share generation/reveal custody and must
// not run concurrently. It never reserves, opens, commits or retains Work.
// Parent current-authority, risk, mapping and session admission remain required.
// Zero values deny and no goroutine or pool lifetime is owned.
type AssertionCreation struct {
	phase   *phase
	input   webauthn.CeremonyCreation
	digest  [32]byte
	preauth bool
}

// AssertionFinalization retains one genuine root verifier-issued identified
// assertion transition for the native signin-verify owner. It cannot construct
// VerifiedAssertion or authenticate an identity. The root verifier may report
// protocol success only after the parent's actual final commit is acknowledged.
// Copies share serial-use result custody; zero values deny.
type AssertionFinalization struct {
	phase   *phase
	digest  [32]byte
	preauth bool
}

func assertionContext(c webauthn.CeremonyContext, preauth bool) bool {
	if !preauth {
		return registrationContext(c)
	}
	_, err := identity.ParseCommandID(string(c.CommandID))
	return err == nil && c.AnonymousFlowID == "" && c.TenantID != "" && c.UserID != "" && c.ActorID != "" && string(c.ActorID) != string(c.UserID)
}

func assertionIntent(i webauthn.CeremonyIntent, preauth bool) bool {
	// The root owns mandatory UP/UV and none-attestation enrollment. Assertion
	// has no residency claim; the passkey owner admits its enrolled mapping.
	return i.Kind == "get" && len(i.UserHandle) == 32 && len(i.AllowedCredentials) > 0 && assertionContext(i.Context, preauth) && registrationAlgorithms(i.Algorithms)
}

// AssertionCreation borrows the native store and the real root service's opaque
// identified ES256 creation. It accepts no caller-assembled ceremony projection.
// The parent owns primary/pool lifetime and must Discard every abandoned call.
func (s *Store) AssertionCreation(input webauthn.CeremonyCreation) (*AssertionCreation, error) {
	return s.assertionCreation(input, false)
}

// PreauthAssertionCreation selects identified preauthentication participation.
// The original parent must attribute options to its trusted SubjectServiceAccount,
// distinct from the identified target. This grants no authority over that target;
// the parent still owns ingress, risk and current-account admission. The original
// service actor must remain unchanged through root assertion verification.
func (s *Store) PreauthAssertionCreation(input webauthn.CeremonyCreation) (*AssertionCreation, error) {
	return s.assertionCreation(input, true)
}

func (s *Store) assertionCreation(input webauthn.CeremonyCreation, preauth bool) (*AssertionCreation, error) {
	i, err := input.Intent()
	if !s.usable() || err != nil || !assertionIntent(i, preauth) {
		return nil, webauthn.Invalid{Field: "assertion_creation"}
	}
	digest, err := assertionDigest(i)
	if err != nil {
		return nil, err
	}
	return &AssertionCreation{phase: &phase{store: s}, input: input, digest: digest, preauth: preauth}, nil
}

// AssertionFinalization accepts only an opaque cryptographically verified
// transition, never a Credential, AssertionMutation or boolean authentication.
// Exact protocol before/after versions remain independent of the parent's
// command-record 0-to-1 lifecycle. No independent commit or provisional result
// is exposed by this constructor.
func (s *Store) AssertionFinalization(input webauthn.AssertionTransition) (*AssertionFinalization, error) {
	return s.assertionFinalization(input, false)
}

// PreauthAssertionFinalization accepts only a genuine root-verified assertion
// made under the original service actor. Its final parent must be attributed to
// the verified target as SubjectUser. Only parent attribution is bridged: the
// immutable protocol mutation, ceremony and digest retain their service actor.
// The parent separately owns current ingress/browser/risk and session authority;
// this participant alone never authenticates an identity or issues a session.
func (s *Store) PreauthAssertionFinalization(input webauthn.AssertionTransition) (*AssertionFinalization, error) {
	return s.assertionFinalization(input, true)
}

func (s *Store) assertionFinalization(input webauthn.AssertionTransition, preauth bool) (*AssertionFinalization, error) {
	m, err := input.Mutation()
	if !s.usable() || err != nil || !assertionIntent(m.Ceremony.Intent, preauth) || !assertionContext(m.Context, preauth) || m.Ceremony.Intent.Context.ActorID != m.Context.ActorID || m.Before.Algorithm != int32(webauthn.ES256) || m.After.Algorithm != int32(webauthn.ES256) || m.Before.TenantID != m.Context.TenantID || m.Before.UserID != m.Context.UserID || m.After.TenantID != m.Context.TenantID || m.After.UserID != m.Context.UserID || !bytes.Equal(m.Before.UserHandle, m.Ceremony.Intent.UserHandle) {
		return nil, webauthn.Invalid{Field: "assertion_finalization"}
	}
	digest, err := assertionDigest(m)
	if err != nil {
		return nil, err
	}
	return &AssertionFinalization{phase: &phase{store: s, assertion: &m, ceremony: m.Ceremony}, digest: digest, preauth: preauth}, nil
}

func assertionDigest(v any) ([32]byte, error) {
	wire, err := json.Marshal(v)
	if err != nil || len(wire) > 262144 {
		return [32]byte{}, webauthn.Invalid{Field: "assertion_intent"}
	}
	defer clear(wire)
	return sha256.Sum256(wire), nil
}
func assertionFields(digest [32]byte) ([]identity.FeatureField, error) {
	if digest == ([32]byte{}) {
		return nil, webauthn.Invalid{Field: "assertion_participant"}
	}
	return []identity.FeatureField{{Name: assertionField, Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: bytes.Clone(digest[:])}}}, nil
}

// Fields binds the complete original command/tenant/user/actor, RP/version,
// origin, handle, allowed credentials and selected algorithm intent. The owned
// digest belongs in the parent's original command; it is not authorization.
func (p *AssertionCreation) Fields() ([]identity.FeatureField, error) {
	if p == nil || p.phase == nil {
		return nil, webauthn.Invalid{Field: "assertion_creation"}
	}
	return assertionFields(p.digest)
}

// Fields additionally binds the exact verified response and original optimistic
// counter/backup/version transition, without retaining browser response bytes
// in the parent command. The returned owned digest must not be logged.
func (p *AssertionFinalization) Fields() ([]identity.FeatureField, error) {
	if p == nil || p.phase == nil {
		return nil, webauthn.Invalid{Field: "assertion_finalization"}
	}
	return assertionFields(p.digest)
}

func assertionOperation(finish bool) identity.FeatureOperation {
	id := "identity.passkey.signin-options"
	if finish {
		id = "identity.passkey.signin-verify"
	}
	return identity.FeatureOperation{Owner: "passkey", OperationID: id, SchemaID: id + ".native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}
func validateAssertion(c identity.Command, plan kernel.CommandPlan, scope webauthn.CeremonyContext, digest [32]byte, finish, preauth bool) error {
	s, ok := c.Feature()
	if !ok || s.Operation != assertionScopeOperation(finish, scope) || plan.Feature == nil || plan.Feature.Operation != s.Operation || plan.Feature.Contributor != registrationDescriptor() || plan.Lifecycle == nil || plan.Lifecycle.BeforeVersion != 0 || plan.Lifecycle.AfterVersion != 1 {
		return webauthn.Invalid{Field: "assertion_parent"}
	}
	b := s.Binding
	actor, kind := scope.ActorID, authorization.SubjectUser
	if preauth {
		if finish {
			// Root signature verification has already fixed the target. This
			// relation does not rewrite its original service-attributed input.
			actor = identity.ActorID(scope.UserID)
		} else {
			kind = authorization.SubjectServiceAccount
		}
	}
	if b.CommandID != scope.CommandID || b.TenantID != scope.TenantID || b.UserID != scope.UserID || b.ActorID != actor || b.ActorKind != kind || b.AnonymousFlowID != scope.AnonymousFlowID || b.CorrelationID != scope.CorrelationID {
		return webauthn.Denied{}
	}
	found := false
	for _, field := range s.Fields {
		if !strings.HasPrefix(field.Name, "webauthn.") {
			continue
		}
		if found || field.Name != assertionField || field.Value.Kind != identity.FeatureBytes || !bytes.Equal(field.Value.Bytes, digest[:]) {
			return webauthn.Invalid{Field: "assertion_intent"}
		}
		found = true
	}
	if !found {
		return webauthn.Invalid{Field: "assertion_intent"}
	}
	return nil
}

// Validate is bounded pure original-intent validation for the parent's actual
// ValidateFeatureCommand. It generates no entropy and admits no authority.
func (p *AssertionCreation) Validate(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.phase == nil {
		return webauthn.Invalid{Field: "assertion_creation"}
	}
	i, err := p.input.Intent()
	if err != nil {
		return err
	}
	return validateAssertion(c, plan, i.Context, p.digest, false, p.preauth)
}

// Validate requires the exact selected parent and immutable original verified
// transition. It does no IO, mutation or authentication.
func (p *AssertionFinalization) Validate(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.phase == nil {
		return webauthn.Invalid{Field: "assertion_finalization"}
	}
	return validateAssertion(c, plan, p.parentContext(), p.digest, true, p.preauth)
}

// Generate runs once after acknowledged new parent reservation and before Work
// opens, using the original primary database clock sample. Replay/recovery must
// not call it. Challenge custody remains unavailable until acknowledged Result.
func (p *AssertionCreation) Generate(ctx context.Context, now time.Time) error {
	if p == nil || p.phase == nil || p.phase.participantGenerated || p.phase.participantReleased {
		return webauthn.Invalid{Field: "assertion_generation"}
	}
	p.phase.participantGenerated = true
	r, ch, err := p.input.Generate(ctx, now)
	if err != nil {
		return err
	}
	p.phase.ceremony, p.phase.challenge = r, ch
	return nil
}

func bindAssertion(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command, p *phase, digest [32]byte, scope webauthn.CeremonyContext, finish, preauth, apply bool) error {
	if ctx == nil || p == nil || owner == nil {
		return webauthn.Invalid{Field: "assertion_work"}
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
	if err = validateAssertion(c, kernel.CommandPlan{Feature: &f, Lifecycle: &l}, scope, digest, finish, preauth); err != nil {
		return err
	}
	if !apply {
		if p.command != c || p.binding != b {
			return webauthn.Conflict{}
		}
		return nil
	}
	if p.command != (identity.Command{}) {
		return webauthn.Conflict{}
	}
	p.command, p.binding = c, b
	return nil
}

// Apply stages protocol creation and original parent-bound native effects in
// this exact parent's active Work. Existing native helpers own RP/handle and
// current-user constraints. Errors must abort every parent and protocol effect.
func (p *AssertionCreation) Apply(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) error {
	if p == nil || p.phase == nil || !p.phase.participantGenerated || p.phase.participantReleased || p.phase.applied {
		return webauthn.Invalid{Field: "assertion_creation"}
	}
	i, err := p.input.Intent()
	if err != nil {
		return err
	}
	if err = bindAssertion(ctx, w, owner, c, p.phase, p.digest, i.Context, false, p.preauth, true); err != nil {
		return err
	}
	if err = p.phase.current(ctx, w); err != nil {
		return err
	}
	if err = p.phase.applyCreation(ctx, w); err != nil {
		return err
	}
	if err = p.phase.persistEvidenceFor(ctx, w, owner); err != nil {
		return err
	}
	p.phase.applied = true
	return checkAssertion(ctx, w, owner, c, p.phase, p.digest, i.Context, false, p.preauth)
}

// Apply consumes the exact verified ceremony and stages its counter/backup/
// version CAS with the parent's metadata/session effects. It never starts or
// commits a second transaction or reports provisional verification.
func (p *AssertionFinalization) Apply(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) error {
	if p == nil || p.phase == nil || p.phase.participantReleased || p.phase.applied {
		return webauthn.Invalid{Field: "assertion_finalization"}
	}
	if err := bindAssertion(ctx, w, owner, c, p.phase, p.digest, p.parentContext(), true, p.preauth, true); err != nil {
		return err
	}
	if err := p.phase.current(ctx, w); err != nil {
		return err
	}
	if err := p.phase.applyAssertion(ctx, w); err != nil {
		return err
	}
	if err := p.phase.persistEvidenceFor(ctx, w, owner); err != nil {
		return err
	}
	p.phase.applied = true
	return checkAssertion(ctx, w, owner, c, p.phase, p.digest, p.parentContext(), true, p.preauth)
}

func checkAssertion(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command, p *phase, digest [32]byte, scope webauthn.CeremonyContext, finish, preauth bool) error {
	if err := bindAssertion(ctx, w, owner, c, p, digest, scope, finish, preauth, false); err != nil {
		return err
	}
	if !p.applied {
		return webauthn.Denied{}
	}
	if err := p.current(ctx, w); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if !now.Before(p.ceremony.ExpiresAt) || now.Before(p.ceremony.ExpiresAt.Add(-5*time.Minute)) {
		return webauthn.Denied{}
	}
	return nil
}

// Check repeats current-user and absolute-expiry fences in the parent's final
// precommit invocation. Parent identity/factor/risk/session checks remain owned
// by that parent and original validity must not be renewed.
func (p *AssertionCreation) Check(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) error {
	if p == nil || p.phase == nil {
		return webauthn.Invalid{Field: "assertion_creation"}
	}
	i, err := p.input.Intent()
	if err != nil {
		return err
	}
	return checkAssertion(ctx, w, owner, c, p.phase, p.digest, i.Context, false, p.preauth)
}

// Check preserves original verified ceremony limits in final precommit. It
// cannot be invoked through foreign, returned, closed or expired Work handles.
func (p *AssertionFinalization) Check(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) error {
	if p == nil || p.phase == nil {
		return webauthn.Invalid{Field: "assertion_finalization"}
	}
	return checkAssertion(ctx, w, owner, c, p.phase, p.digest, p.parentContext(), true, p.preauth)
}

func assertionResult(p *phase, r identity.CommandResult, finish bool) error {
	if p == nil {
		return webauthn.Invalid{Field: "assertion_result"}
	}
	if r.Outcome == identity.CommitOutcomeUnknown || r.Outcome == identity.CommitOutcomeInProgress {
		return webauthn.UnknownCommit{CommandID: r.Binding.CommandID}
	}
	if r.Outcome != identity.CommitOutcomeCommitted || r.Validate() != nil {
		return webauthn.Unavailable{}
	}
	if !p.applied {
		return webauthn.Replay{CommandID: r.Binding.CommandID}
	}
	if r.Binding != p.binding || r.Feature == nil || r.Feature.Operation != assertionScopeOperation(finish, p.ceremony.Intent.Context) || r.Feature.BeforeVersion != 0 || r.Feature.AfterVersion != 1 {
		return webauthn.Unavailable{}
	}
	return nil
}

// Result transfers challenge custody only once for this newly applied,
// acknowledged final parent commit. Unknown/failure/replay release nothing and
// permanently discard unreleased entropy. The native parent must pass its
// actual coordinator receipt after commit, never a caller-created projection.
func (p *AssertionCreation) Result(r identity.CommandResult) (webauthn.CeremonyRecord, webauthn.Challenge, error) {
	if p == nil || p.phase == nil || p.phase.participantReleased {
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, webauthn.Invalid{Field: "assertion_result"}
	}
	p.phase.participantReleased = true
	if err := assertionResult(p.phase, r, false); err != nil {
		p.Discard()
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, err
	}
	challenge := p.phase.challenge
	p.phase.challenge = webauthn.Challenge{}
	return p.phase.ceremony, challenge, nil
}

// Result returns finalized protocol credential state only once to the real
// root verifier. It is not identity authentication. Unknown/replay never issue
// verification, and the parent must supply its actual final committed receipt.
func (p *AssertionFinalization) Result(r identity.CommandResult) (webauthn.Credential, error) {
	if p == nil || p.phase == nil || p.phase.participantReleased {
		return webauthn.Credential{}, webauthn.Invalid{Field: "assertion_result"}
	}
	p.phase.participantReleased = true
	if err := assertionResult(p.phase, r, true); err != nil {
		return webauthn.Credential{}, err
	}
	return p.phase.assertion.After, nil
}

// Discard clears all unreleased challenge aliases and is idempotent. The
// parent must defer it across abandonment, cancellation, errors and panics.
func (p *AssertionCreation) Discard() {
	if p != nil && p.phase != nil {
		p.phase.participantReleased = true
		p.phase.challenge.Discard()
		p.phase.challenge = webauthn.Challenge{}
	}
}

// RecoverAssertion runs only in the original parent's genuine recovery
// invocation. The parent combines this with its metadata/session/effect owners.
// Absence is noncommit evidence; any effect under a still-pending journal is
// unknown, never reconstructed authentication or permission to replay effects.
func (s *Store) RecoverAssertion(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	if !s.usable() || ctx == nil {
		return kernel.RecoveryUnknown, webauthn.Invalid{Field: "assertion_recovery"}
	}
	b, f, l, err := w.FeatureScope(owner)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	self := b.ActorKind == authorization.SubjectUser && b.UserID != "" && string(b.ActorID) == string(b.UserID) && b.AnonymousFlowID == ""
	serviceCreation := f.Operation == assertionOperation(false) && b.ActorKind == authorization.SubjectServiceAccount && b.UserID != "" && b.ActorID != "" && string(b.ActorID) != string(b.UserID) && b.AnonymousFlowID == ""
	anonymousOperation := assertionOperation(false)
	anonymousOperation.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
	anonymousCreation := f.Operation == anonymousOperation && b.ActorKind == authorization.SubjectServiceAccount && b.UserID == "" && b.ActorID != "" && b.AnonymousFlowID != ""
	identified := (f.Operation == assertionOperation(false) || f.Operation == assertionOperation(true)) && (self || serviceCreation)
	if f.Contributor != registrationDescriptor() || (!identified && !anonymousCreation) || l.BeforeVersion != 0 || l.AfterVersion != 1 {
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

// Format redacts all retained ceremony, original command and challenge state.
func (AssertionCreation) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("webauthnpostgres.AssertionCreation(redacted)"))
}

// Format redacts provisional verification and correlated original command state.
func (AssertionFinalization) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("webauthnpostgres.AssertionFinalization(redacted)"))
}

// MarshalJSON rejects accidental export of invocation and challenge custody.
func (AssertionCreation) MarshalJSON() ([]byte, error) {
	return nil, webauthn.Invalid{Field: "assertion_participant"}
}

// MarshalJSON rejects accidental export of provisional verifier custody.
func (AssertionFinalization) MarshalJSON() ([]byte, error) {
	return nil, webauthn.Invalid{Field: "assertion_participant"}
}
