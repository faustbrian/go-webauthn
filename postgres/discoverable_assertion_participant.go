package postgres

import (
	"bytes"

	identity "github.com/faustbrian/go-identity"
	webauthn "github.com/faustbrian/go-webauthn"
)

func discoverableAssertionContext(c webauthn.CeremonyContext) bool {
	_, err := identity.ParseCommandID(string(c.CommandID))
	return err == nil && c.TenantID != "" && c.UserID == "" && c.AnonymousFlowID != "" && c.ActorID != ""
}

func discoverableAssertionIntent(i webauthn.CeremonyIntent) bool {
	return i.Kind == "get-discoverable" && discoverableAssertionContext(i.Context) && len(i.UserHandle) == 0 && len(i.AllowedCredentials) == 0 && !i.ResidentKeyRequired && registrationAlgorithms(i.Algorithms)
}

// DiscoverableAssertionCreation selects account-independent resident discovery
// inside the native passkey parent's one Work. The parent must bind its original
// trusted service actor and genuine anonymous session flow, with no target user.
// No credential allowlist, user handle or account admission is accepted here;
// original browser, risk, identifier and session policy remain parent-owned.
// Custody, Generate/Discard and final-commit Result rules match AssertionCreation.
func (s *Store) DiscoverableAssertionCreation(input webauthn.CeremonyCreation) (*AssertionCreation, error) {
	i, err := input.Intent()
	if !s.usable() || err != nil || !discoverableAssertionIntent(i) {
		return nil, webauthn.Invalid{Field: "discoverable_assertion_creation"}
	}
	digest, err := assertionDigest(i)
	if err != nil {
		return nil, err
	}
	return &AssertionCreation{phase: &phase{store: s, creation: &input}, input: input, digest: digest, preauth: true}, nil
}

// DiscoverableAssertionFinalization accepts only the root verifier's opaque
// signed resident assertion. Its verified Before.UserID, never a caller-selected
// target, binds the final self-human parent. The original anonymous protocol
// context, service actor and flow stay unchanged in the transition and digest.
// This participant does not match an identifier, admit risk, authenticate an
// identity or issue a session; the native parent owns those current decisions.
func (s *Store) DiscoverableAssertionFinalization(input webauthn.AssertionTransition) (*AssertionFinalization, error) {
	m, err := input.Mutation()
	if !s.usable() || err != nil || !discoverableAssertionIntent(m.Ceremony.Intent) || !discoverableAssertionContext(m.Context) || m.Ceremony.Intent.Context.TenantID != m.Context.TenantID || m.Ceremony.Intent.Context.ActorID != m.Context.ActorID || m.Ceremony.Intent.Context.AnonymousFlowID != m.Context.AnonymousFlowID || m.Before.UserID == "" || m.After.UserID != m.Before.UserID || m.Before.TenantID != m.Context.TenantID || m.After.TenantID != m.Context.TenantID || m.Before.RPID != m.Ceremony.Intent.RPID || m.After.RPID != m.Before.RPID || m.Before.Algorithm != int32(webauthn.ES256) || m.After.Algorithm != int32(webauthn.ES256) || len(m.Before.UserHandle) != 32 || !bytes.Equal(m.Before.UserHandle, m.After.UserHandle) {
		return nil, webauthn.Invalid{Field: "discoverable_assertion_finalization"}
	}
	digest, err := assertionDigest(m)
	if err != nil {
		return nil, err
	}
	return &AssertionFinalization{phase: &phase{store: s, assertion: &m, ceremony: m.Ceremony}, digest: digest, preauth: true}, nil
}

// Only the parent-binding relation is projected after opaque verification.
// The actual protocol context retained in phase.assertion is never rewritten.
func (p *AssertionFinalization) parentContext() webauthn.CeremonyContext {
	scope := p.phase.assertion.Context
	if p.phase.assertion.Ceremony.Intent.Kind == "get-discoverable" {
		scope.UserID = p.phase.assertion.Before.UserID
		scope.AnonymousFlowID = ""
	}
	return scope
}

func assertionScopeOperation(finish bool, scope webauthn.CeremonyContext) identity.FeatureOperation {
	op := assertionOperation(finish)
	if !finish && scope.UserID == "" && scope.AnonymousFlowID != "" {
		op.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
	}
	return op
}
