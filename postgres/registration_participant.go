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

const registrationField = "webauthn.registration.intent"

// RegistrationCreation is one serial-use native protocol participant borrowed
// by the selected passkey register-options owner. Copies must not be used
// concurrently. It never reserves, begins, commits or retains Work. The parent
// must independently admit current session/fresh proof for enrollment, or the
// original pre-auth/signup authority for signup, plus applicable factor/risk
// policy and identity mapping in that same Work. Zero values deny; no goroutine
// is owned.
type RegistrationCreation struct {
	phase  *phase
	input  webauthn.CeremonyCreation
	digest [32]byte
}

// RegistrationFinalization retains only a real verifier-issued transition for
// one serial-use register-verify invocation. It cannot mint VerifiedRegistration
// or authenticate an identity. The root verifier may return its result only
// after the parent's Store reports acknowledged final commit. Zero values deny.
type RegistrationFinalization struct {
	phase  *phase
	digest [32]byte
}

// RegistrationCreation borrows the existing protocol store and opaque creation.
// Only authenticated resident-required ES256/Ed25519 enrollment is selected.
// Creation must come from the real root service configured with that profile.
// The caller owns pool lifetime and must Discard on all abandoned/failure paths.
func (s *Store) RegistrationCreation(input webauthn.CeremonyCreation) (*RegistrationCreation, error) {
	i, err := input.Intent()
	if !s.usable() || err != nil || i.Kind != "create" || !i.ResidentKeyRequired || len(i.UserHandle) != 32 || !registrationContext(i.Context) || !registrationAlgorithms(i.Algorithms) {
		return nil, webauthn.Invalid{Field: "registration_creation"}
	}
	digest, err := registrationDigest(i)
	if err != nil {
		return nil, err
	}
	return &RegistrationCreation{phase: &phase{store: s}, input: input, digest: digest}, nil
}

// RegistrationFinalization accepts only opaque cryptographically verified
// registration, never caller-assembled Credential or RegistrationMutation.
// It does not commit independently or expose a provisional verified result.
func (s *Store) RegistrationFinalization(input webauthn.RegistrationTransition) (*RegistrationFinalization, error) {
	m, err := input.Mutation()
	if !s.usable() || err != nil || m.Ceremony.Intent.Kind != "create" || !m.Ceremony.Intent.ResidentKeyRequired || !registrationContext(m.Context) || !registrationAlgorithm(m.Credential.Algorithm, m.Ceremony.Intent.Algorithms) || m.Credential.TenantID != m.Context.TenantID || m.Credential.UserID != m.Context.UserID || m.Credential.Version != 1 {
		return nil, webauthn.Invalid{Field: "registration_finalization"}
	}
	digest, err := registrationDigest(m)
	if err != nil {
		return nil, err
	}
	return &RegistrationFinalization{phase: &phase{store: s, registration: &m, ceremony: m.Ceremony}, digest: digest}, nil
}

func registrationAlgorithms(selected []webauthn.Algorithm) bool {
	if selected == nil {
		return true
	}
	if len(selected) == 0 || len(selected) > 2 {
		return false
	}
	for index, algorithm := range selected {
		if algorithm != webauthn.ES256 && algorithm != webauthn.EdDSA || index > 0 && algorithm == selected[0] {
			return false
		}
	}
	return true
}

// The root verifier owns exact COSE key/signature verification. Participants
// select only its ES256/Ed25519 passkey profile and never reinterpret nil's
// legacy ES256 default or normalize the original digest/recovery input.
func registrationAlgorithm(algorithm int32, selected []webauthn.Algorithm) bool {
	if !registrationAlgorithms(selected) {
		return false
	}
	if selected == nil {
		return algorithm == int32(webauthn.ES256)
	}
	for _, allowed := range selected {
		if algorithm == int32(allowed) {
			return true
		}
	}
	return false
}
func registrationContext(c webauthn.CeremonyContext) bool {
	_, err := identity.ParseCommandID(string(c.CommandID))
	return err == nil && c.AnonymousFlowID == "" && c.TenantID != "" && c.UserID != "" && string(c.ActorID) == string(c.UserID)
}
func registrationDigest(v any) ([32]byte, error) {
	wire, err := json.Marshal(v)
	if err != nil || len(wire) > 262144 {
		return [32]byte{}, webauthn.Invalid{Field: "registration_intent"}
	}
	defer clear(wire)
	return sha256.Sum256(wire), nil
}
func registrationFields(digest [32]byte) ([]identity.FeatureField, error) {
	if digest == ([32]byte{}) {
		return nil, webauthn.Invalid{Field: "registration_participant"}
	}
	return []identity.FeatureField{{Name: registrationField, Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: bytes.Clone(digest[:])}}}, nil
}

// Fields binds every original protocol input, including RP/origin/UV profile,
// exclusions and user handle, into the parent's existing canonical command.
// The returned owned digest is not proof or permission and must not be logged.
func (p *RegistrationCreation) Fields() ([]identity.FeatureField, error) {
	if p == nil || p.phase == nil {
		return nil, webauthn.Invalid{Field: "registration_creation"}
	}
	return registrationFields(p.digest)
}

// Fields fixes the verified ceremony, credential and response identity without
// retaining raw browser responses in the parent command or native effect record.
func (p *RegistrationFinalization) Fields() ([]identity.FeatureField, error) {
	if p == nil || p.phase == nil {
		return nil, webauthn.Invalid{Field: "registration_finalization"}
	}
	return registrationFields(p.digest)
}

func registrationOperation(finish bool) identity.FeatureOperation {
	id := "identity.passkey.register-options"
	if finish {
		id = "identity.passkey.register-verify"
	}
	return identity.FeatureOperation{Owner: "passkey", OperationID: id, SchemaID: id + ".native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}
func registrationDescriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}
}
func registrationScopeOperation(finish bool, signupFlow string) identity.FeatureOperation {
	op := registrationOperation(finish)
	if signupFlow != "" {
		op.SchemaID = op.OperationID + ".signup-v1"
		op.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
	}
	return op
}
func validateRegistration(c identity.Command, p kernel.CommandPlan, scope webauthn.CeremonyContext, digest [32]byte, finish bool, signupFlow string) error {
	s, ok := c.Feature()
	if !ok || s.Operation != registrationScopeOperation(finish, signupFlow) || p.Feature == nil || p.Feature.Operation != s.Operation || p.Feature.Contributor != registrationDescriptor() || p.Lifecycle == nil || p.Lifecycle.BeforeVersion != 0 || p.Lifecycle.AfterVersion != 1 {
		return webauthn.Invalid{Field: "registration_parent"}
	}
	b := s.Binding
	if b.CommandID != scope.CommandID || b.TenantID != scope.TenantID || b.ActorID != scope.ActorID || b.CorrelationID != scope.CorrelationID {
		return webauthn.Denied{}
	}
	if signupFlow == "" {
		if b.UserID != scope.UserID || b.ActorKind != authorization.SubjectUser || b.AnonymousFlowID != "" {
			return webauthn.Denied{}
		}
	} else if b.UserID != "" || b.ActorKind != authorization.SubjectServiceAccount || b.AnonymousFlowID != signupFlow {
		return webauthn.Denied{}
	}
	found := false
	prospective := false
	for _, field := range s.Fields {
		if signupFlow != "" && field.Name == "registration.user" {
			if prospective || field.Value.Kind != identity.FeatureText || field.Value.Text != string(scope.UserID) {
				return webauthn.Invalid{Field: "registration_user"}
			}
			prospective = true
		}
		if !strings.HasPrefix(field.Name, "webauthn.") {
			continue
		}
		if found || field.Name != registrationField || field.Value.Kind != identity.FeatureBytes || !bytes.Equal(field.Value.Bytes, digest[:]) {
			return webauthn.Invalid{Field: "registration_intent"}
		}
		found = true
	}
	if !found || signupFlow != "" && !prospective {
		return webauthn.Invalid{Field: "registration_intent"}
	}
	return nil
}

// Validate is pure bounded original-intent validation for the parent's native
// ValidateFeatureCommand. It admits no authority and does not generate entropy.
func (p *RegistrationCreation) Validate(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.phase == nil {
		return webauthn.Invalid{Field: "registration_creation"}
	}
	i, err := p.input.Intent()
	if err != nil {
		return err
	}
	return validateRegistration(c, plan, i.Context, p.digest, false, p.phase.signupFlow)
}

// Validate requires the exact selected parent, immutable verifier transition
// and original command. It performs no IO or durable mutation.
func (p *RegistrationFinalization) Validate(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.phase == nil {
		return webauthn.Invalid{Field: "registration_finalization"}
	}
	return validateRegistration(c, plan, p.phase.registration.Context, p.digest, true, p.phase.signupFlow)
}

// Generate must run after acknowledged parent reservation and before Work opens.
// now is the original primary database sample. It generates once; retries and
// recovery must not call it. Challenge custody stays unavailable until Result.
func (p *RegistrationCreation) Generate(ctx context.Context, now time.Time) error {
	if p == nil || p.phase == nil || p.phase.participantGenerated || p.phase.participantReleased {
		return webauthn.Invalid{Field: "registration_generation"}
	}
	p.phase.participantGenerated = true
	r, ch, err := p.input.Generate(ctx, now)
	if err != nil {
		return err
	}
	p.phase.ceremony, p.phase.challenge = r, ch
	return nil
}

func bindRegistration(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command, p *phase, digest [32]byte, scope webauthn.CeremonyContext, finish bool, apply bool) error {
	if ctx == nil || p == nil || owner == nil {
		return webauthn.Invalid{Field: "registration_work"}
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
	if err = validateRegistration(c, kernel.CommandPlan{Feature: &f, Lifecycle: &l}, scope, digest, finish, p.signupFlow); err != nil {
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

// Apply stages the actual protocol ceremony, RP-wide stable-handle binding and
// original protocol effects in the parent's Work. There is no nested transaction
// or callback. Errors must abort Work, including every parent-owned effect.
func (p *RegistrationCreation) Apply(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) error {
	if p == nil || p.phase == nil || !p.phase.participantGenerated || p.phase.participantReleased || p.phase.applied {
		return webauthn.Invalid{Field: "registration_creation"}
	}
	i, err := p.input.Intent()
	if err != nil {
		return err
	}
	if err = bindRegistration(ctx, w, owner, c, p.phase, p.digest, i.Context, false, true); err != nil {
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
	return checkRegistration(ctx, w, owner, c, p.phase, p.digest, i.Context, false)
}

// Apply atomically consumes the original ceremony and inserts the actual
// verified credential alongside the parent's identity mapping and proof use.
// It never reports authentication or a finalized credential before SQL commit.
func (p *RegistrationFinalization) Apply(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) error {
	if p == nil || p.phase == nil || p.phase.participantReleased || p.phase.applied {
		return webauthn.Invalid{Field: "registration_finalization"}
	}
	if err := bindRegistration(ctx, w, owner, c, p.phase, p.digest, p.phase.registration.Context, true, true); err != nil {
		return err
	}
	if err := p.phase.current(ctx, w); err != nil {
		return err
	}
	if err := p.phase.applyRegistration(ctx, w); err != nil {
		return err
	}
	if err := p.phase.persistEvidenceFor(ctx, w, owner); err != nil {
		return err
	}
	p.phase.applied = true
	return checkRegistration(ctx, w, owner, c, p.phase, p.digest, p.phase.registration.Context, true)
}

func checkRegistration(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command, p *phase, digest [32]byte, scope webauthn.CeremonyContext, finish bool) error {
	if err := bindRegistration(ctx, w, owner, c, p, digest, scope, finish, false); err != nil {
		return err
	}
	if !p.applied {
		return webauthn.Denied{}
	}
	if err := p.current(ctx, w); err != nil {
		return err
	}
	if p.signupFlow != "" {
		if err := p.checkSignupCeremony(ctx, w, finish); err != nil {
			return err
		}
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

// Check repeats the selected protocol current-user or original pending-signup
// scope and absolute-expiry fences in the parent's final precommit invocation.
// Parent session/proof/pre-auth/risk fences remain required as applicable.
func (p *RegistrationCreation) Check(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) error {
	if p == nil || p.phase == nil {
		return webauthn.Invalid{Field: "registration_creation"}
	}
	i, err := p.input.Intent()
	if err != nil {
		return err
	}
	return checkRegistration(ctx, w, owner, c, p.phase, p.digest, i.Context, false)
}

// Check preserves original verified ceremony limits without refreshing them.
func (p *RegistrationFinalization) Check(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) error {
	if p == nil || p.phase == nil {
		return webauthn.Invalid{Field: "registration_finalization"}
	}
	return checkRegistration(ctx, w, owner, c, p.phase, p.digest, p.phase.registration.Context, true)
}

func registrationResult(p *phase, r identity.CommandResult, finish bool) error {
	if p == nil {
		return webauthn.Invalid{Field: "registration_result"}
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
	if r.Binding != p.binding || r.Feature == nil || r.Feature.Operation != registrationScopeOperation(finish, p.signupFlow) || r.Feature.BeforeVersion != 0 || r.Feature.AfterVersion != 1 {
		return webauthn.Unavailable{}
	}
	return nil
}

// Result transfers challenge custody only for this newly applied acknowledged
// parent commit. Unknown, failure and replay return no output; failure discards
// entropy permanently. The parent must pass its actual coordinator receipt.
func (p *RegistrationCreation) Result(r identity.CommandResult) (webauthn.CeremonyRecord, webauthn.Challenge, error) {
	if p == nil || p.phase == nil || p.phase.participantReleased {
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, webauthn.Invalid{Field: "registration_result"}
	}
	p.phase.participantReleased = true
	if err := registrationResult(p.phase, r, false); err != nil {
		p.Discard()
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, err
	}
	challenge := p.phase.challenge
	p.phase.challenge = webauthn.Challenge{}
	return p.phase.ceremony, challenge, nil
}

// Result returns an owned finalized credential for the real root verifier, not
// an identity grant. Replay and unknown commit never reissue verification.
func (p *RegistrationFinalization) Result(r identity.CommandResult) (webauthn.Credential, error) {
	if p == nil || p.phase == nil || p.phase.participantReleased {
		return webauthn.Credential{}, webauthn.Invalid{Field: "registration_result"}
	}
	p.phase.participantReleased = true
	if err := registrationResult(p.phase, r, true); err != nil {
		return webauthn.Credential{}, err
	}
	return p.phase.registration.Credential, nil
}

// Discard clears all unreleased challenge aliases. It is idempotent and must
// run when reservation/apply/commit/delivery is abandoned, including panics.
func (p *RegistrationCreation) Discard() {
	if p != nil && p.phase != nil {
		p.phase.participantReleased = true
		p.phase.challenge.Discard()
		p.phase.challenge = webauthn.Challenge{}
	}
}

// RecoverRegistration participates only in the original parent journal's
// recovery invocation. Absence is not-committed evidence; any protocol effect
// with a pending journal remains unknown, never reconstructed authentication.
// The parent combines this with all its own proof/mapping/effect participants.
func (s *Store) RecoverRegistration(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	if !s.usable() || ctx == nil {
		return kernel.RecoveryUnknown, webauthn.Invalid{Field: "registration_recovery"}
	}
	b, f, _, err := w.FeatureScope(owner)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	native := (f.Operation == registrationOperation(false) || f.Operation == registrationOperation(true)) && b.ActorKind == authorization.SubjectUser && b.UserID != "" && string(b.ActorID) == string(b.UserID) && b.AnonymousFlowID == ""
	signup := (f.Operation == registrationScopeOperation(false, "signup") || f.Operation == registrationScopeOperation(true, "signup")) && b.ActorKind == authorization.SubjectServiceAccount && b.ActorID != "" && b.UserID == "" && b.AnonymousFlowID != ""
	if f.Contributor != registrationDescriptor() || !native && !signup {
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

// Format redacts all participant, ceremony and correlated command state.
func (RegistrationCreation) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("webauthnpostgres.RegistrationCreation(redacted)"))
}

// Format redacts the retained verified transition and command state.
func (RegistrationFinalization) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("webauthnpostgres.RegistrationFinalization(redacted)"))
}

// MarshalJSON rejects accidental export of invocation and challenge custody.
func (RegistrationCreation) MarshalJSON() ([]byte, error) {
	return nil, webauthn.Invalid{Field: "registration_participant"}
}

// MarshalJSON rejects accidental export of provisional verification custody.
func (RegistrationFinalization) MarshalJSON() ([]byte, error) {
	return nil, webauthn.Invalid{Field: "registration_participant"}
}
