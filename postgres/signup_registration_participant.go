package postgres

import (
	"context"
	"encoding/json"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	webauthn "github.com/faustbrian/go-webauthn"
)

func signupRegistrationContext(c webauthn.CeremonyContext, flow string) bool {
	_, err := identity.ParseCommandID(string(c.CommandID))
	if err != nil || c.AnonymousFlowID != "" || c.TenantID == "" || c.UserID == "" || c.ActorID == "" || len(flow) == 0 || len(flow) > 128 {
		return false
	}
	for _, b := range []byte(flow) {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' || b == '_' || b == '.' || b == ':') {
			return false
		}
	}
	return true
}

func signupRegistrationDigest(flow string, intent any) ([32]byte, error) {
	return registrationDigest(struct {
		Profile string
		Flow    string
		Intent  any
	}{"passkey.registration.signup-v1", flow, intent})
}

// SignupRegistrationCreation borrows real root-issued resident-required
// ES256/Ed25519 creation for the exact anonymous register-options .signup-v1 parent. flow is
// the original trusted session pre-auth flow, not a new authenticated subject.
// The root context holds the preallocated prospective user and configured
// service actor; parent UserID must stay empty and registration.user must bind
// that prospective ID. The parent owns risk, expiry, remember and signup policy.
// Options create no identity, stable user handle, credential or session.
// Custody, serial use, Generate, Discard and Result match RegistrationCreation.
func (s *Store) SignupRegistrationCreation(input webauthn.CeremonyCreation, flow string) (*RegistrationCreation, error) {
	i, err := input.Intent()
	if !s.usable() || err != nil || i.Kind != "create" || !i.ResidentKeyRequired || len(i.UserHandle) != 32 || !signupRegistrationContext(i.Context, flow) || !registrationAlgorithms(i.Algorithms) {
		return nil, webauthn.Invalid{Field: "signup_registration_creation"}
	}
	digest, err := signupRegistrationDigest(flow, i)
	if err != nil {
		return nil, err
	}
	return &RegistrationCreation{phase: &phase{store: s, signupFlow: flow}, input: input, digest: digest}, nil
}

// SignupRegistrationFinalization accepts only the root verifier's opaque UV
// registration transition for the exact original anonymous .signup-v1 parent.
// The parent must create the prospective active identity in the same Work before
// Apply; this participant creates neither that identity nor MFA/session effects.
// Apply consumes only the ceremony stored with this original flow/prospective
// ID, promotes its association once, then binds the existing RP-wide handle and
// credential. Any failure must abort all parent effects. Check repeats the exact
// stored-flow and current-active-user fences; Result requires acknowledged
// commit and never exposes provisional authentication or signup authority.
func (s *Store) SignupRegistrationFinalization(input webauthn.RegistrationTransition, flow string) (*RegistrationFinalization, error) {
	m, err := input.Mutation()
	i := m.Ceremony.Intent
	if !s.usable() || err != nil || i.Kind != "create" || !i.ResidentKeyRequired || len(i.UserHandle) != 32 || !signupRegistrationContext(m.Context, flow) || !signupRegistrationContext(i.Context, flow) || i.Context.TenantID != m.Context.TenantID || i.Context.UserID != m.Context.UserID || i.Context.ActorID != m.Context.ActorID || !registrationAlgorithm(m.Credential.Algorithm, i.Algorithms) || m.Credential.TenantID != m.Context.TenantID || m.Credential.UserID != m.Context.UserID || m.Credential.Version != 1 || m.Credential.RPID != i.RPID {
		return nil, webauthn.Invalid{Field: "signup_registration_finalization"}
	}
	digest, err := signupRegistrationDigest(flow, m)
	if err != nil {
		return nil, err
	}
	return &RegistrationFinalization{phase: &phase{store: s, signupFlow: flow, registration: &m, ceremony: m.Ceremony}, digest: digest}, nil
}

// Retaining the root record unchanged keeps its challenge digest valid. SQL's
// separate pending namespace avoids weakening existing identity foreign keys;
// the one-way verified consumption installs the real FK-backed association.
func (p *phase) checkSignupCeremony(ctx context.Context, w kernel.Work, finish bool) error {
	r := p.ceremony
	wire, err := json.Marshal(r)
	if err != nil {
		return webauthn.Invalid{Field: "signup_ceremony"}
	}
	query := `SELECT 1 FROM webauthn.ceremonies WHERE ceremony_id=$1 AND tenant_id=$2 AND rp_id=$3 AND record=$4::jsonb AND signup_flow_id=$5 AND anonymous_flow_id IS NULL AND user_id IS NULL AND signup_user_id=$6 AND consumed_by IS NULL FOR SHARE`
	args := []any{r.ID, string(r.Intent.Context.TenantID), r.Intent.RPID, string(wire), p.signupFlow, string(r.Intent.Context.UserID)}
	if finish {
		query = `SELECT 1 FROM webauthn.ceremonies WHERE ceremony_id=$1 AND tenant_id=$2 AND rp_id=$3 AND record=$4::jsonb AND signup_flow_id=$5 AND anonymous_flow_id IS NULL AND user_id=$6 AND signup_user_id IS NULL AND consumed_by=$7 FOR SHARE`
		args = append(args, string(p.binding.CommandID))
	}
	rows, err := w.Query(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		return webauthn.Denied{}
	}
	return rows.Err()
}
