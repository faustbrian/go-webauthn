package postgres

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	webauthn "github.com/faustbrian/go-webauthn"
)

// All mutable fields are invocation-local, owned by one serial service call.
// There is no map of pending work, private transaction or secondary journal.
type phase struct {
	store         *Store
	command       identity.Command
	binding       identity.CommandBinding
	plan          kernel.CommandPlan
	coordinator   *kernel.Coordinator
	before, after uint64
	creation      *webauthn.CeremonyCreation
	registration  *webauthn.RegistrationMutation
	assertion     *webauthn.AssertionMutation
	ceremony      webauthn.CeremonyRecord
	challenge     webauthn.Challenge
	applied       bool
}

var _ kernel.FeatureExecutionContributor = (*phase)(nil)
var _ kernel.FeatureCommitContributor = (*phase)(nil)

func (*phase) Descriptor() kernel.ContributorDescriptor { return descriptor() }
func (*phase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{operation("begin-create"), operation("begin-get"), operation("register"), operation("assert"), operation("begin-get-discoverable"), operation("assert-discoverable")}
}
func (p *phase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.store == nil || c != p.command {
		return identity.InvalidInputError{Field: "webauthn_command"}
	}
	spec, ok := c.Feature()
	if !ok || spec.Binding != p.binding || len(spec.Fields) != 1 || spec.Fields[0].Name != "transition.digest" || spec.Fields[0].Value.Kind != identity.FeatureBytes || len(spec.Fields[0].Value.Bytes) != 32 || plan.Feature == nil || plan.Feature.Contributor != descriptor() || plan.Feature.Operation != spec.Operation || plan.SubjectType != "webauthn" || plan.Lifecycle == nil || plan.Lifecycle.EventType != p.binding.OperationID+".v1" || plan.Lifecycle.BeforeVersion != p.before || plan.Lifecycle.AfterVersion != p.after || len(plan.Audits) != 1 || plan.Audits[0].EventType != p.binding.OperationID || plan.Audits[0].RetentionClass != "protected" || plan.Capability != nil || plan.OTP != nil || plan.RiskEvidence != nil || plan.CommandCounters != nil || plan.Delivery != nil || plan.CapabilityIssuance != nil {
		return identity.InvalidInputError{Field: "webauthn_plan"}
	}
	if p.creation == nil && p.registration == nil && p.assertion == nil {
		return identity.InvalidInputError{Field: "webauthn_transition"}
	}
	return nil
}
func (p *phase) current(ctx context.Context, w kernel.Work) error {
	user := p.binding.UserID
	if p.binding.AnonymousFlowID != "" {
		if p.creation != nil {
			return nil
		}
		if p.assertion == nil {
			return identity.ForbiddenError{}
		}
		user = p.assertion.Before.UserID
	}
	query := `SELECT status FROM identity.users WHERE tenant_id=$1 AND user_id=$2 FOR SHARE`
	args := []any{string(p.binding.TenantID), string(user)}
	if p.binding.AnonymousFlowID != "" {
		// DiscoverableStore's mapping is current authority, not metadata. Lock
		// it through commit so a non-key tenant/user reassignment cannot race
		// the verified credential snapshot; the final fence rechecks it too.
		query = `SELECT u.status FROM identity.users u JOIN webauthn.user_handles h ON h.tenant_id=u.tenant_id AND h.user_id=u.user_id JOIN webauthn.relying_parties r ON r.rp_id=h.rp_id AND r.tenant_id=u.tenant_id WHERE u.tenant_id=$1 AND u.user_id=$2 AND h.rp_id=$3 AND h.user_handle=$4 FOR SHARE OF u,h,r`
		args = append(args, p.assertion.Before.RPID, p.assertion.Before.UserHandle)
	}
	rows, e := w.Query(ctx, query, args...)
	if e != nil {
		return e
	}
	var status string
	if !rows.Next() {
		rows.Close()
		return identity.ForbiddenError{}
	}
	e = rows.Scan(&status)
	if rows.Next() {
		e = identity.UnavailableError{}
	}
	rowerr := rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	if rowerr != nil {
		return rowerr
	}
	if status != "active" {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *phase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if e := w.RequireFeatureCommand(ctx, p, c); e != nil {
		return identity.FeatureReceipt{}, e
	}
	if e := p.current(ctx, w); e != nil {
		return identity.FeatureReceipt{}, e
	}
	var e error
	switch {
	case p.creation != nil:
		e = p.applyCreation(ctx, w)
	case p.registration != nil:
		e = p.applyRegistration(ctx, w)
	case p.assertion != nil:
		e = p.applyAssertion(ctx, w)
	default:
		e = identity.ForbiddenError{}
	}
	if e != nil {
		return identity.FeatureReceipt{}, e
	}
	if e = p.persistEvidence(ctx, w); e != nil {
		return identity.FeatureReceipt{}, e
	}
	p.applied = true
	return identity.FeatureReceipt{Operation: p.plan.Feature.Operation, BeforeVersion: p.before, AfterVersion: p.after}, nil
}
func (p *phase) applyCreation(ctx context.Context, w kernel.Work) error {
	r := p.ceremony
	i := r.Intent
	if r.ID != string(p.binding.CommandID) || r.Version != 1 || r.ChallengeDigest == ([32]byte{}) {
		return identity.InvalidInputError{Field: "webauthn_generation"}
	}
	if _, e := w.Exec(ctx, `INSERT INTO webauthn.relying_parties(rp_id,tenant_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, i.RPID, string(i.Context.TenantID)); e != nil {
		return e
	}
	rows, e := w.Query(ctx, `SELECT tenant_id FROM webauthn.relying_parties WHERE rp_id=$1 FOR UPDATE`, i.RPID)
	if e != nil {
		return e
	}
	var tenant string
	if !rows.Next() {
		rows.Close()
		return identity.UnavailableError{}
	}
	e = rows.Scan(&tenant)
	if rows.Next() {
		e = identity.UnavailableError{}
	}
	rowerr := rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	if rowerr != nil {
		return rowerr
	}
	if tenant != string(i.Context.TenantID) {
		return identity.ForbiddenError{}
	}
	if i.Kind != "get-discoverable" {
		if _, e = w.Exec(ctx, `INSERT INTO webauthn.user_handles(rp_id,user_handle,tenant_id,user_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, i.RPID, i.UserHandle, string(i.Context.TenantID), string(i.Context.UserID)); e != nil {
			return e
		}
		rows, e = w.Query(ctx, `SELECT tenant_id,user_id FROM webauthn.user_handles WHERE rp_id=$1 AND user_handle=$2`, i.RPID, i.UserHandle)
		if e != nil {
			return e
		}
		var user string
		if !rows.Next() {
			rows.Close()
			return identity.ConflictError{}
		}
		e = rows.Scan(&tenant, &user)
		if rows.Next() {
			e = identity.UnavailableError{}
		}
		rowerr = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		if rowerr != nil {
			return rowerr
		}
		if tenant != string(i.Context.TenantID) || user != string(i.Context.UserID) {
			return identity.ConflictError{}
		}
	}
	wire, e := json.Marshal(r)
	if e != nil {
		return identity.InvalidInputError{Field: "ceremony"}
	}
	n, e := w.Exec(ctx, `INSERT INTO webauthn.ceremonies(ceremony_id,rp_id,tenant_id,user_id,kind,challenge_digest,expires_at,version,record,anonymous_flow_id) VALUES($1,$2,$3,NULLIF($4,''),$5,$6,$7,1,$8::jsonb,NULLIF($9,'')) ON CONFLICT DO NOTHING`, r.ID, i.RPID, string(i.Context.TenantID), string(i.Context.UserID), i.Kind, r.ChallengeDigest[:], r.ExpiresAt, string(wire), i.Context.AnonymousFlowID)
	if e != nil {
		return e
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}
func (p *phase) consume(ctx context.Context, w kernel.Work) error {
	r := p.ceremony
	wire, e := json.Marshal(r)
	if e != nil {
		return identity.InvalidInputError{Field: "ceremony"}
	}
	n, e := w.Exec(ctx, `UPDATE webauthn.ceremonies SET consumed_by=$1 WHERE ceremony_id=$2 AND tenant_id=$3 AND COALESCE(user_id,'')=$4 AND rp_id=$5 AND consumed_by IS NULL AND expires_at>clock_timestamp() AND version=1 AND record=$6::jsonb AND COALESCE(anonymous_flow_id,'')=$7`, string(p.binding.CommandID), r.ID, string(p.binding.TenantID), string(p.binding.UserID), r.Intent.RPID, string(wire), p.binding.AnonymousFlowID)
	if e != nil {
		return e
	}
	if n != 1 {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *phase) applyRegistration(ctx context.Context, w kernel.Work) error {
	if e := p.consume(ctx, w); e != nil {
		return e
	}
	c := p.registration.Credential
	wire, e := json.Marshal(c)
	if e != nil {
		return identity.InvalidInputError{Field: "credential"}
	}
	n, e := w.Exec(ctx, `INSERT INTO webauthn.credentials(rp_id,credential_id,tenant_id,user_id,user_handle,version,record) VALUES($1,$2,$3,$4,$5,1,$6::jsonb) ON CONFLICT DO NOTHING`, c.RPID, c.ID, string(c.TenantID), string(c.UserID), c.UserHandle, string(wire))
	if e != nil {
		return e
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}
func (p *phase) applyAssertion(ctx context.Context, w kernel.Work) error {
	if e := p.consume(ctx, w); e != nil {
		return e
	}
	m := p.assertion
	before, e := json.Marshal(m.Before)
	if e != nil {
		return identity.InvalidInputError{Field: "credential"}
	}
	after, e := json.Marshal(m.After)
	if e != nil {
		return identity.InvalidInputError{Field: "credential"}
	}
	n, e := w.Exec(ctx, `UPDATE webauthn.credentials c SET version=$1::numeric,record=$2::jsonb WHERE rp_id=$3 AND credential_id=$4 AND tenant_id=$5 AND user_id=$6 AND version=$7::numeric AND record=$8::jsonb AND user_handle=$9 AND EXISTS(SELECT 1 FROM webauthn.user_handles h WHERE h.rp_id=c.rp_id AND h.user_handle=c.user_handle AND h.tenant_id=c.tenant_id AND h.user_id=c.user_id)`, strconv.FormatUint(m.After.Version, 10), string(after), m.Before.RPID, m.Before.ID, string(m.Context.TenantID), string(m.Before.UserID), strconv.FormatUint(m.Before.Version, 10), string(before), m.Before.UserHandle)
	if e != nil {
		return e
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}
func (p *phase) persistEvidence(ctx context.Context, w kernel.Work) error {
	b, fp, _, e := w.FeatureCommandIdentity(p)
	if e != nil || b != p.binding {
		return identity.InvalidInputError{Field: "webauthn_custody"}
	}
	ceremony, e := json.Marshal(p.ceremony)
	if e != nil {
		return identity.InvalidInputError{Field: "ceremony"}
	}
	var before, after []byte
	if p.registration != nil {
		after, e = json.Marshal(p.registration.Credential)
	}
	if p.assertion != nil {
		before, e = json.Marshal(p.assertion.Before)
		if e == nil {
			after, e = json.Marshal(p.assertion.After)
		}
	}
	if e != nil {
		return identity.InvalidInputError{Field: "credential"}
	}
	var beforeValue, afterValue any
	if before != nil {
		beforeValue = string(before)
	}
	if after != nil {
		afterValue = string(after)
	}
	n, e := w.Exec(ctx, `INSERT INTO webauthn.effects(command_id,tenant_id,user_id,actor_id,purpose,record_id,fingerprint,ceremony_id,ceremony,before_credential,after_credential,anonymous_flow_id) VALUES($1,$2,NULLIF($3,''),$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb,$11::jsonb,NULLIF($12,'')) ON CONFLICT DO NOTHING`, string(b.CommandID), string(b.TenantID), string(b.UserID), string(b.ActorID), b.OperationID, b.RecordID, fp[:], p.ceremony.ID, string(ceremony), beforeValue, afterValue, b.AnonymousFlowID)
	if e != nil {
		return e
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}
func (p *phase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command {
		return identity.InvalidInputError{Field: "webauthn_command"}
	}
	if _, _, _, e := w.FeatureScope(p); e != nil {
		return e
	}
	if e := p.current(ctx, w); e != nil {
		return e
	}
	now, e := w.DatabaseTime(ctx)
	if e != nil {
		return e
	}
	if !now.Before(p.ceremony.ExpiresAt) || now.Before(p.ceremony.ExpiresAt.Add(-5*time.Minute)) {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *phase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, _, _, e := w.FeatureScope(p)
	if e != nil {
		return kernel.RecoveryUnknown, e
	}
	rows, e := w.Query(ctx, `SELECT tenant_id,user_id,actor_id,purpose,record_id FROM webauthn.effects WHERE command_id=$1`, string(b.CommandID))
	if e != nil {
		return kernel.RecoveryUnknown, e
	}
	defer rows.Close()
	if !rows.Next() {
		if e = rows.Err(); e != nil {
			return kernel.RecoveryUnknown, e
		}
		return kernel.RecoveryNotCommitted, nil
	}
	// Shared pending journal plus any committed native effect is an atomicity
	// conflict, never permission to reconstruct success from current state.
	return kernel.RecoveryUnknown, nil
}
