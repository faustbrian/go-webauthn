package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	webauthn "github.com/faustbrian/go-webauthn"
)

const removalAssertionField = "webauthn.removal-assertion.intent"

func removalAssertionOperation(finish bool) identity.FeatureOperation {
	schema := "identity.passkey.delete.options-v1"
	if finish {
		schema = "identity.passkey.delete.assertion-v1"
	}
	return identity.FeatureOperation{Owner: "passkey", OperationID: "identity.passkey.delete", SchemaID: schema, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// RemovalAssertionCreation selects identified self-human UV options for the
// native delete owner. It grants no session, target, recovery or policy authority.
// The parent must bind those original inputs, defer Discard and finalize its sole
// Work before returning the participant's Result to the genuine root service.
func (s *Store) RemovalAssertionCreation(input webauthn.CeremonyCreation) (*AssertionCreation, error) {
	p, err := s.assertionCreation(input, false)
	if err == nil {
		p.removal = true
	}
	return p, err
}

// RemovalAssertionFinalization consumes one genuine identified root transition
// and erases an exact owned protocol credential inside the native parent's Work.
// It owns neither a coordinator nor authentication/session/recovery authority.
// Copies share serial-use custody, including the one acknowledged Result. The
// parent owns current session, target/reference/mapping, remaining usable key,
// MFA, directory, policy and risk admission and must propagate every error.
// Zero values deny; no goroutine or borrowed-pool lifetime is owned.
type RemovalAssertionFinalization struct{ state *removalAssertionState }

type removalAssertionState struct {
	source  *phase
	removal *CredentialRemoval
	digest  [32]byte
	same    bool
}

// RemovalAssertionFinalization accepts only verifier-issued transition custody.
// RemovalRequest.Version is the original target version, not a caller-rebased
// successor. For the same credential, only the verified source After supplies
// the removal CAS version. Parent lifecycle versions are entirely independent.
func (s *Store) RemovalAssertionFinalization(input webauthn.AssertionTransition, target RemovalRequest) (*RemovalAssertionFinalization, error) {
	a, err := s.assertionFinalization(input, false)
	if err != nil {
		return nil, err
	}
	r, err := s.CredentialRemoval(target)
	if err != nil {
		return nil, err
	}
	m := a.phase.assertion
	if target.Context != m.Context || target.RPID != m.Before.RPID || target.RPID != m.After.RPID || m.Ceremony.ID == string(m.Context.CommandID) || m.Ceremony.ExpiresAt.IsZero() {
		return nil, webauthn.Denied{}
	}
	same := bytes.Equal(target.CredentialID, m.Before.ID)
	if same {
		if target.Version != m.Before.Version || m.After.Version == math.MaxUint64 {
			return nil, webauthn.Conflict{}
		}
		r.state.request.Version = m.After.Version
	}
	digest, err := assertionDigest(struct {
		Assertion webauthn.AssertionMutation
		Removal   RemovalRequest
	}{*m, target})
	if err != nil {
		return nil, err
	}
	return &RemovalAssertionFinalization{state: &removalAssertionState{source: a.phase, removal: r, digest: digest, same: same}}, nil
}

func (p *RemovalAssertionFinalization) usable() bool {
	return p != nil && p.state != nil && p.state.source != nil && p.state.removal != nil && p.state.removal.state != nil
}

// Fields fixes the genuine source response/ceremony/before/after and original
// target scope/version in one owned digest. It is not authorization or proof.
func (p *RemovalAssertionFinalization) Fields() ([]identity.FeatureField, error) {
	if !p.usable() {
		return nil, webauthn.Invalid{Field: "removal_assertion"}
	}
	return []identity.FeatureField{{Name: removalAssertionField, Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: bytes.Clone(p.state.digest[:])}}}, nil
}

// Validate requires the exact self-user delete-assertion schema, native owner,
// original input digest and canonical positive reference N-to-N+1 lifecycle.
// It performs bounded pure admission, not IO or current authority evaluation.
func (p *RemovalAssertionFinalization) Validate(c identity.Command, plan kernel.CommandPlan) error {
	if !p.usable() {
		return webauthn.Invalid{Field: "removal_assertion"}
	}
	return validateAssertion(c, plan, p.state.source.assertion.Context, p.state.digest, true, false, false, true)
}

func (p *RemovalAssertionFinalization) bind(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command, apply bool) error {
	if !p.usable() || p.state.source.participantReleased {
		return webauthn.Invalid{Field: "removal_assertion"}
	}
	s := p.state
	if err := bindAssertion(ctx, w, owner, c, s.source, s.digest, s.source.assertion.Context, true, false, false, true, apply); err != nil {
		return err
	}
	if apply {
		s.removal.state.command, s.removal.state.binding = c, s.source.binding
	}
	return nil
}

// sourceCurrent distinguishes removal options from signin/rename/enrollment
// ceremonies. The original options row is locked before consumption; neither
// another action's valid signature nor retained effects can substitute for it.
func (p *RemovalAssertionFinalization) sourceCurrent(ctx context.Context, w kernel.Work, applied bool) error {
	s := p.state.source
	m := s.assertion
	wire, err := json.Marshal(m.Ceremony)
	if err != nil {
		return webauthn.Denied{}
	}
	rows, err := w.Query(ctx, `SELECT 1 FROM webauthn.ceremonies c JOIN webauthn.effects e ON e.command_id=c.ceremony_id WHERE c.ceremony_id=$1 AND c.tenant_id=$2 AND c.user_id=$3 AND c.rp_id=$4 AND c.record=$5::jsonb AND c.authorization_expires_at IS NULL AND ((NOT $6::boolean AND c.consumed_by IS NULL) OR ($6::boolean AND c.consumed_by=$7)) AND e.purpose='identity.passkey.delete' AND e.tenant_id=c.tenant_id AND e.user_id=c.user_id AND e.actor_id=c.user_id AND e.ceremony_id=c.ceremony_id AND e.ceremony=c.record AND e.before_credential IS NULL AND e.after_credential IS NULL AND e.removal_before_credential IS NULL AND e.removal_after_credential IS NULL AND e.anonymous_flow_id IS NULL AND e.enrollment_stage IS NULL FOR UPDATE OF c FOR SHARE OF e`, m.Ceremony.ID, string(m.Context.TenantID), string(m.Context.UserID), m.Ceremony.Intent.RPID, string(wire), applied, string(m.Context.CommandID))
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

// Apply consumes the original removal ceremony, advances its verified source,
// erases the target and retains both snapshots in one parent-linked effect row.
// Every step uses the existing Work; any rejection must abort the whole parent.
func (p *RemovalAssertionFinalization) Apply(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) error {
	if !p.usable() || p.state.source.applied {
		return webauthn.Invalid{Field: "removal_assertion"}
	}
	if err := p.bind(ctx, w, owner, c, true); err != nil {
		return err
	}
	s := p.state
	if err := s.source.current(ctx, w); err != nil {
		return err
	}
	if err := p.sourceCurrent(ctx, w, false); err != nil {
		return err
	}
	if err := s.source.applyAssertion(ctx, w); err != nil {
		return err
	}
	if err := s.removal.applyRemoval(ctx, w); err != nil {
		return err
	}
	if err := s.source.persistEvidenceFor(ctx, w, owner); err != nil {
		return err
	}
	b, fp, _, err := w.FeatureCommandIdentity(owner)
	if err != nil || b != s.source.binding {
		return webauthn.Invalid{Field: "removal_assertion_custody"}
	}
	s.removal.state.fingerprint = fp
	n, err := w.Exec(ctx, `UPDATE webauthn.effects SET removal_before_credential=$1::jsonb,removal_after_credential=$2::jsonb WHERE command_id=$3 AND fingerprint=$4 AND removal_before_credential IS NULL AND removal_after_credential IS NULL`, string(s.removal.state.before), string(s.removal.state.after), string(b.CommandID), fp[:])
	if err != nil {
		return err
	}
	if n != 1 {
		return webauthn.Conflict{}
	}
	s.source.applied, s.removal.state.applied = true, true
	return p.Check(ctx, w, owner, c)
}

// Check repeats original absolute expiry/current-subject/ceremony and exact
// successor/effect fences during final precommit. The same-key terminal version
// replaces only this profile's source live-key fence; all other profiles retain
// checkAssertionCredential unchanged. A distinct source must remain exact/live.
func (p *RemovalAssertionFinalization) Check(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) error {
	if err := p.bind(ctx, w, owner, c, false); err != nil {
		return err
	}
	s := p.state
	if !s.source.applied || !s.removal.state.applied {
		return webauthn.Denied{}
	}
	if err := s.source.current(ctx, w); err != nil {
		return err
	}
	if err := p.sourceCurrent(ctx, w, true); err != nil {
		return err
	}
	if !s.same {
		if err := s.source.checkAssertionCredential(ctx, w); err != nil {
			return err
		}
	}
	r := s.removal.state
	m := s.source.assertion
	before, err := json.Marshal(m.Before)
	if err != nil {
		return webauthn.Denied{}
	}
	after, err := json.Marshal(m.After)
	if err != nil {
		return webauthn.Denied{}
	}
	rows, err := w.Query(ctx, `SELECT 1 FROM webauthn.credentials c JOIN webauthn.user_handles h ON h.rp_id=c.rp_id AND h.user_handle=c.user_handle AND h.tenant_id=c.tenant_id AND h.user_id=c.user_id JOIN webauthn.relying_parties rp ON rp.rp_id=c.rp_id AND rp.tenant_id=c.tenant_id JOIN webauthn.effects e ON e.command_id=$1 WHERE c.rp_id=$2 AND c.credential_id=$3 AND c.tenant_id=$4 AND c.user_id=$5 AND c.version=$6::numeric AND c.record=$7::jsonb AND e.tenant_id=c.tenant_id AND e.user_id=c.user_id AND e.actor_id=$8 AND e.purpose=$9 AND e.record_id=$10 AND e.fingerprint=$11 AND e.ceremony_id=$12 AND e.ceremony=(SELECT record FROM webauthn.ceremonies WHERE ceremony_id=$12) AND e.before_credential=$13::jsonb AND e.after_credential=$14::jsonb AND e.removal_before_credential=$15::jsonb AND e.removal_after_credential=c.record AND e.anonymous_flow_id IS NULL AND e.enrollment_stage IS NULL`, string(r.binding.CommandID), r.request.RPID, r.request.CredentialID, string(r.binding.TenantID), string(r.binding.UserID), strconv.FormatUint(r.request.Version+1, 10), string(r.after), string(r.binding.ActorID), r.binding.OperationID, r.binding.RecordID, r.fingerprint[:], m.Ceremony.ID, string(before), string(after), string(r.before))
	if err != nil {
		return err
	}
	if !rows.Next() {
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		return webauthn.Denied{}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if !now.Before(s.source.ceremony.ExpiresAt) || now.Before(s.source.ceremony.ExpiresAt.Add(-5*time.Minute)) {
		return webauthn.Denied{}
	}
	return ctx.Err()
}

// Result releases exactly the root verifier's After once, only following the
// actual acknowledged final parent commit. It is historical protocol evidence,
// not a usable credential admission: the same-key target is already terminal.
// Unknown, aborted and replayed commands never reconstruct verification.
func (p *RemovalAssertionFinalization) Result(r identity.CommandResult) (webauthn.Credential, error) {
	if !p.usable() || p.state.source.participantReleased {
		return webauthn.Credential{}, webauthn.Invalid{Field: "removal_assertion_result"}
	}
	p.state.source.participantReleased = true
	if err := assertionResult(p.state.source, r, true, false, true); err != nil {
		return webauthn.Credential{}, err
	}
	return p.state.source.assertion.After, nil
}

// RecoverRemovalAssertion admits only the original removal-options/completion
// parent recovery invocation. Missing protocol evidence proves noncommit; any
// effect beneath a pending journal remains unknown. The parent must combine its
// other owners. Recovery never consumes a ceremony, renews expiry or reissues a
// credential, challenge or verification result.
func (s *Store) RecoverRemovalAssertion(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	if !s.usable() || ctx == nil {
		return kernel.RecoveryUnknown, webauthn.Invalid{Field: "removal_assertion_recovery"}
	}
	b, f, l, err := w.FeatureScope(owner)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	finish := f.Operation == removalAssertionOperation(true)
	if f.Contributor != registrationDescriptor() || !(finish || f.Operation == removalAssertionOperation(false)) || b.ActorKind != authorization.SubjectUser || b.UserID == "" || string(b.ActorID) != string(b.UserID) || b.AnonymousFlowID != "" || !assertionLifecycle(&l, finish, false, true) {
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

// Format redacts retained cryptographic and original-command custody.
func (RemovalAssertionFinalization) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("webauthnpostgres.RemovalAssertionFinalization(redacted)"))
}

// MarshalJSON prevents accidental export of provisional participant state.
func (RemovalAssertionFinalization) MarshalJSON() ([]byte, error) {
	return nil, webauthn.Invalid{Field: "removal_assertion"}
}
