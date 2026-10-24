package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	webauthn "github.com/faustbrian/go-webauthn"
)

const removalField = "webauthn.removal.intent"
const removalEvent = "identity.passkey.remove_credential"

// RemovalRequest fixes the original trusted self-user scope, RP, raw credential
// ID and optimistic protocol version. Version is independent of the parent's
// passkey-reference and metadata versions. CredentialID is copied on admission.
// This input is not fresh proof or authorization to delete a passkey.
type RemovalRequest struct {
	Context      webauthn.CeremonyContext
	RPID         string
	CredentialID []byte
	Version      uint64
}

// Format hides correlated scope and credential identifiers.
func (RemovalRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("webauthnpostgres.RemovalRequest(redacted)"))
}

// CredentialRemoval is a serial-use protocol participant in the native delete
// parent's sole Work. Copies share invocation state. It owns no transaction,
// goroutine, proof, ceremony, session or passkey authority. The parent must admit
// those actual owners, apply this participant, and call Check before committing.
// Every returned error must propagate and abort the parent's complete Work.
// Zero values deny; no credential or authentication result is released.
type CredentialRemoval struct{ state *removalState }
type removalState struct {
	store         *Store
	request       RemovalRequest
	digest        [32]byte
	command       identity.Command
	binding       identity.CommandBinding
	before, after []byte
	fingerprint   [32]byte
	applied       bool
}

// CredentialRemoval admits one bounded immutable removal input without IO.
// The pool is borrowed; the caller retains its lifetime and all parent policy.
func (s *Store) CredentialRemoval(input RemovalRequest) (*CredentialRemoval, error) {
	if !s.usable() || !registrationContext(input.Context) || input.Context.CorrelationID == "" || input.RPID == "" || len(input.RPID) > 253 || strings.TrimSpace(input.RPID) != input.RPID || len(input.CredentialID) == 0 || len(input.CredentialID) > 1024 || input.Version == 0 || input.Version == math.MaxUint64 {
		return nil, webauthn.Invalid{Field: "credential_removal"}
	}
	input.CredentialID = bytes.Clone(input.CredentialID)
	digest, err := registrationDigest(input)
	if err != nil {
		return nil, err
	}
	return &CredentialRemoval{state: &removalState{store: s, request: input, digest: digest}}, nil
}

func removalOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "passkey", OperationID: "identity.passkey.delete", SchemaID: "identity.passkey.delete.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// Fields binds every original protocol input into the parent's canonical
// command. The owned digest is neither authorization nor authentication proof.
func (p *CredentialRemoval) Fields() ([]identity.FeatureField, error) {
	if p == nil || p.state == nil {
		return nil, webauthn.Invalid{Field: "credential_removal"}
	}
	return []identity.FeatureField{{Name: removalField, Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: bytes.Clone(p.state.digest[:])}}}, nil
}

// Validate checks exact native operation, original self-user binding and the
// canonical removal lifecycle. It performs no IO or current-authority admission.
func (p *CredentialRemoval) Validate(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.state == nil {
		return webauthn.Invalid{Field: "credential_removal"}
	}
	s, ok := c.Feature()
	if !ok || s.Operation != removalOperation() || plan.Feature == nil || plan.Feature.Operation != s.Operation || plan.Feature.Contributor != registrationDescriptor() || plan.Lifecycle == nil || plan.Lifecycle.EventType != removalEvent || plan.Lifecycle.BeforeVersion == 0 || plan.Lifecycle.BeforeVersion == math.MaxUint64 || plan.Lifecycle.AfterVersion != plan.Lifecycle.BeforeVersion+1 {
		return webauthn.Invalid{Field: "removal_parent"}
	}
	b, scope := s.Binding, p.state.request.Context
	if !registrationContext(scope) || b.CommandID != scope.CommandID || b.TenantID != scope.TenantID || b.UserID != scope.UserID || b.ActorID != scope.ActorID || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(b.UserID) || b.AnonymousFlowID != "" || b.CorrelationID != scope.CorrelationID {
		return webauthn.Denied{}
	}
	found := false
	for _, field := range s.Fields {
		if !strings.HasPrefix(field.Name, "webauthn.") {
			continue
		}
		if found || field.Name != removalField || field.Value.Kind != identity.FeatureBytes || !bytes.Equal(field.Value.Bytes, p.state.digest[:]) {
			return webauthn.Invalid{Field: "removal_intent"}
		}
		found = true
	}
	if !found {
		return webauthn.Invalid{Field: "removal_intent"}
	}
	return nil
}

func (p *CredentialRemoval) bind(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command, apply bool) error {
	if p == nil || p.state == nil || ctx == nil || owner == nil {
		return webauthn.Invalid{Field: "removal_work"}
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
	if apply {
		if p.state.command != (identity.Command{}) {
			return webauthn.Conflict{}
		}
		p.state.command, p.state.binding = c, b
	} else if p.state.command != c || p.state.binding != b {
		return webauthn.Conflict{}
	}
	return nil
}

// Apply locks the exact active protocol row and replaces only its key/version
// with a terminal denied successor. RP-wide ID and handle reservations remain.
// All protocol effects and parent effects roll back through the sole Work.
func (p *CredentialRemoval) Apply(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) error {
	if p == nil || p.state == nil || p.state.applied {
		return webauthn.Invalid{Field: "credential_removal"}
	}
	if err := p.bind(ctx, w, owner, c, true); err != nil {
		return err
	}
	if err := p.applyRemoval(ctx, w); err != nil {
		return err
	}
	s := p.state
	b, fp, _, err := w.FeatureCommandIdentity(owner)
	if err != nil || b != s.binding {
		return webauthn.Invalid{Field: "removal_custody"}
	}
	s.fingerprint = fp
	// Removal has no ceremony. JSON null and empty ceremony_id occupy the
	// existing protocol effect slots without inventing a ceremony or journal.
	n, err := w.Exec(ctx, `INSERT INTO webauthn.effects(command_id,tenant_id,user_id,actor_id,purpose,record_id,fingerprint,ceremony_id,ceremony,before_credential,after_credential) VALUES($1,$2,$3,$4,$5,$6,$7,'','null'::jsonb,$8::jsonb,$9::jsonb) ON CONFLICT DO NOTHING`, string(b.CommandID), string(b.TenantID), string(b.UserID), string(b.ActorID), b.OperationID, b.RecordID, fp[:], string(s.before), string(s.after))
	if err != nil {
		return err
	}
	if n != 1 {
		return webauthn.Conflict{}
	}
	s.applied = true
	return p.Check(ctx, w, owner, c)
}

// Both password-proof deletion and the explicit compound UV profile use this
// same terminal CAS. The caller supplies the genuine verified successor when
// the assertion itself advances the removed row; effect ownership stays outside.
func (p *CredentialRemoval) applyRemoval(ctx context.Context, w kernel.Work) error {
	s := p.state
	r := s.request
	if err := (&phase{binding: s.binding}).current(ctx, w); err != nil {
		return err
	}
	rows, err := w.Query(ctx, `SELECT c.record,c.user_handle FROM webauthn.credentials c JOIN webauthn.user_handles h ON h.rp_id=c.rp_id AND h.user_handle=c.user_handle AND h.tenant_id=c.tenant_id AND h.user_id=c.user_id JOIN webauthn.relying_parties r ON r.rp_id=c.rp_id AND r.tenant_id=c.tenant_id WHERE c.rp_id=$1 AND c.credential_id=$2 AND c.tenant_id=$3 AND c.user_id=$4 AND c.version=$5::numeric FOR UPDATE OF c FOR SHARE OF h,r`, r.RPID, r.CredentialID, string(r.Context.TenantID), string(r.Context.UserID), strconv.FormatUint(r.Version, 10))
	if err != nil {
		return err
	}
	if !rows.Next() {
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		return webauthn.Conflict{}
	}
	var handle []byte
	err = rows.Scan(&s.before, &handle)
	if rows.Next() {
		err = webauthn.Unavailable{}
	}
	rowErr := rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if rowErr != nil {
		return rowErr
	}
	var before webauthn.Credential
	if len(s.before) > 32768 || json.Unmarshal(s.before, &before) != nil || before.TenantID != r.Context.TenantID || before.UserID != r.Context.UserID || before.RPID != r.RPID || !bytes.Equal(before.ID, r.CredentialID) || len(before.UserHandle) != 32 || !bytes.Equal(before.UserHandle, handle) || len(before.PublicKey) == 0 || before.Version != r.Version {
		return webauthn.Denied{}
	}
	// The existing schema retains a public-verification record, not an active
	// bit understood only by new binaries. Erasing its COSE key makes old and
	// current root verifiers deny at parseCBOR; the successor version/record CAS
	// also fences already loaded assertions. Keep RP-wide identity reserved so
	// registration's existing INSERT cannot resurrect the removed credential.
	after := before
	after.PublicKey = nil
	after.Version++
	s.after, err = json.Marshal(after)
	if err != nil {
		return webauthn.Unavailable{}
	}
	n, err := w.Exec(ctx, `UPDATE webauthn.credentials SET version=$1::numeric,record=$2::jsonb WHERE rp_id=$3 AND credential_id=$4 AND tenant_id=$5 AND user_id=$6 AND version=$7::numeric AND record=$8::jsonb`, strconv.FormatUint(after.Version, 10), string(s.after), r.RPID, r.CredentialID, string(r.Context.TenantID), string(r.Context.UserID), strconv.FormatUint(r.Version, 10), string(s.before))
	if err != nil {
		return err
	}
	if n != 1 {
		return webauthn.Conflict{}
	}
	return nil
}

// Check repeats exact successor and active-subject/mapping fences in the
// parent's final precommit invocation. Another staged mutation cannot replace
// this denied successor while leaving a successful removal receipt.
func (p *CredentialRemoval) Check(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) error {
	if err := p.bind(ctx, w, owner, c, false); err != nil {
		return err
	}
	s := p.state
	if !s.applied {
		return webauthn.Denied{}
	}
	if err := (&phase{binding: s.binding}).current(ctx, w); err != nil {
		return err
	}
	r := s.request
	rows, err := w.Query(ctx, `SELECT 1 FROM webauthn.credentials c JOIN webauthn.user_handles h ON h.rp_id=c.rp_id AND h.user_handle=c.user_handle AND h.tenant_id=c.tenant_id AND h.user_id=c.user_id JOIN webauthn.relying_parties r ON r.rp_id=c.rp_id AND r.tenant_id=c.tenant_id WHERE c.rp_id=$1 AND c.credential_id=$2 AND c.tenant_id=$3 AND c.user_id=$4 AND c.version=$5::numeric AND c.record=$6::jsonb AND EXISTS(SELECT 1 FROM webauthn.effects e WHERE e.command_id=$7 AND e.tenant_id=$3 AND e.user_id=$4 AND e.actor_id=$8 AND e.purpose=$9 AND e.record_id=$10 AND e.fingerprint=$11 AND e.ceremony_id='' AND e.ceremony='null'::jsonb AND e.before_credential=$12::jsonb AND e.after_credential=$6::jsonb AND e.anonymous_flow_id IS NULL)`, r.RPID, r.CredentialID, string(r.Context.TenantID), string(r.Context.UserID), strconv.FormatUint(r.Version+1, 10), string(s.after), string(s.binding.CommandID), string(s.binding.ActorID), s.binding.OperationID, s.binding.RecordID, s.fingerprint[:], string(s.before))
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

// Recover delegates to retained original-command evidence; it cannot execute
// removal, fabricate a committed receipt or renew proof/current authority.
func (p *CredentialRemoval) Recover(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	if p == nil || p.state == nil {
		return kernel.RecoveryUnknown, webauthn.Invalid{Field: "removal_recovery"}
	}
	return p.state.store.RecoverRemoval(ctx, w, owner)
}

// RecoverRemoval participates only in the parent's original journal recovery.
// Effects are inseparable from removal and must be retained for at least the
// parent journal's lifetime. Absence proves this command did not remove; any
// retained effect beside a pending journal remains Unknown. Today's credential
// state never establishes historical commit or grants reexecution authority.
func (s *Store) RecoverRemoval(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	if !s.usable() || ctx == nil {
		return kernel.RecoveryUnknown, webauthn.Invalid{Field: "removal_recovery"}
	}
	b, f, l, err := w.FeatureScope(owner)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	if f.Contributor != registrationDescriptor() || f.Operation != removalOperation() || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(b.UserID) || b.AnonymousFlowID != "" || l.EventType != removalEvent || l.BeforeVersion == 0 || l.BeforeVersion == math.MaxUint64 || l.AfterVersion != l.BeforeVersion+1 {
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

// Format hides original input and invocation state.
func (CredentialRemoval) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("webauthnpostgres.CredentialRemoval(redacted)"))
}

// MarshalJSON prevents accidental export of provisional invocation state.
func (CredentialRemoval) MarshalJSON() ([]byte, error) {
	return nil, webauthn.Invalid{Field: "removal_participant"}
}

// A verified transition must still name the exact live successor at commit;
// retaining old assertion effects is never permission to restore an erased key.
func (p *phase) checkAssertionCredential(ctx context.Context, w kernel.Work) error {
	if p.assertion == nil {
		return nil
	}
	c := p.assertion.After
	wire, err := json.Marshal(c)
	if err != nil || len(c.PublicKey) == 0 {
		return webauthn.Denied{}
	}
	rows, err := w.Query(ctx, `SELECT 1 FROM webauthn.credentials WHERE rp_id=$1 AND credential_id=$2 AND tenant_id=$3 AND user_id=$4 AND user_handle=$5 AND version=$6::numeric AND record=$7::jsonb`, c.RPID, c.ID, string(c.TenantID), string(c.UserID), c.UserHandle, strconv.FormatUint(c.Version, 10), string(wire))
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
