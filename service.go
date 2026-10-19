package webauthn

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"slices"
	"time"

	identity "github.com/faustbrian/go-identity"
)

type service struct {
	config Config
	store  Store
}

// New validates and snapshots explicit configuration without IO or callbacks.
// No protocol capability is available without a nonnil durable Store. The caller
// owns store lifetime, identity authorization and tenant-to-RP selection.
func New(c Config, d Dependencies) (Service, error) {
	if d.Store == nil || nilStore(d.Store) || !safeID(string(c.TenantID)) || c.ChallengeKey.key == nil || c.MaximumDuration <= 0 || c.MaximumDuration > time.Minute || c.RelyingParty.Version == 0 || len(c.RelyingParty.Name) == 0 || len(c.RelyingParty.Name) > 128 || len(c.RelyingParty.Origins) == 0 || len(c.RelyingParty.Origins) > 32 || c.Extensions.CredentialProtection > 3 || c.Extensions.EnforceCredentialProtection && c.Extensions.CredentialProtection == 0 {
		return nil, Invalid{Field: "configuration"}
	}
	seen := map[string]bool{}
	for _, o := range c.RelyingParty.Origins {
		if seen[o] || !validOrigin(o, c.RelyingParty.ID, c.DevelopmentLocalhostHTTP) {
			return nil, Invalid{Field: "origin"}
		}
		seen[o] = true
	}
	c.RelyingParty.Origins = slices.Clone(c.RelyingParty.Origins)
	return &service{config: c, store: d.Store}, nil
}

// NewDiscoverable selects usernameless assertions only with the explicit durable
// resolution contract. It otherwise has the same bounded configuration as New.
func NewDiscoverable(c Config, d Dependencies) (DiscoverableService, error) {
	if _, ok := d.Store.(DiscoverableStore); !ok {
		return nil, Invalid{Field: "discoverable_store"}
	}
	s, err := New(c, d)
	if err != nil {
		return nil, err
	}
	return s.(*service), nil
}
func nilStore(v Store) bool {
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Func, reflect.Interface, reflect.Slice, reflect.Chan:
		return r.IsNil()
	}
	return false
}
func safeID(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, b := range []byte(s) {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' || b == '_' || b == '.' || b == ':') {
			return false
		}
	}
	return true
}
func (s *service) validContext(c CeremonyContext) bool {
	_, e := identity.ParseCommandID(string(c.CommandID))
	return e == nil && c.TenantID == s.config.TenantID && c.AnonymousFlowID == "" && safeID(string(c.UserID)) && safeID(string(c.ActorID)) && safeID(c.CorrelationID)
}
func (s *service) validDiscoverableContext(c CeremonyContext) bool {
	_, e := identity.ParseCommandID(string(c.CommandID))
	return e == nil && c.TenantID == s.config.TenantID && c.UserID == "" && safeID(c.AnonymousFlowID) && safeID(string(c.ActorID)) && safeID(c.CorrelationID)
}
func (s *service) origin(origin string) bool {
	return slices.Contains(s.config.RelyingParty.Origins, origin)
}
func validIDs(ids [][]byte) bool {
	if len(ids) > 100 {
		return false
	}
	for i, id := range ids {
		if len(id) == 0 || len(id) > 1024 {
			return false
		}
		for _, prev := range ids[:i] {
			if bytes.Equal(id, prev) {
				return false
			}
		}
	}
	return true
}
func (s *service) create(ctx context.Context, c CeremonyContext, handle []byte, origin, kind string, ids [][]byte, resident bool) (*optionsState, error) {
	valid := s.validContext(c) && len(handle) == 32
	if kind == "get-discoverable" {
		_, available := s.store.(DiscoverableStore)
		valid = available && s.validDiscoverableContext(c) && len(handle) == 0 && len(ids) == 0
	}
	if ctx == nil || !valid || !s.origin(origin) || !validIDs(ids) || kind == "get" && len(ids) == 0 {
		return nil, Invalid{Field: "ceremony"}
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	i := CeremonyIntent{Context: c, Kind: kind, RPID: s.config.RelyingParty.ID, RPVersion: s.config.RelyingParty.Version, Origin: origin, UserHandle: bytes.Clone(handle), AllowedCredentials: cloneIDs(ids), Extensions: s.config.Extensions, ResidentKeyRequired: resident}
	state := &creationState{intent: i, key: s.config.ChallengeKey.key()}
	r, ch, outcome, e := s.store.CreateCeremony(ctx, CeremonyCreation{access: func() *creationState { return state }})
	if e != nil || outcome != identity.CommitOutcomeCommitted {
		ch.Discard()
		return nil, storeOutcome(c, outcome, e)
	}
	if !sameIntent(r.Intent, i) || r.ID != string(c.CommandID) || r.Version != 1 || r.ChallengeDigest == ([32]byte{}) || r.ExpiresAt.IsZero() {
		ch.Discard()
		return nil, Unavailable{}
	}
	if ch.access != nil {
		st := ch.access()
		st.mu.Lock()
		digest := challengeDigest(s.config.ChallengeKey.key(), r, st.bytes)
		valid := len(st.bytes) == 32 && hmac.Equal(digest[:], r.ChallengeDigest[:])
		st.mu.Unlock()
		if !valid {
			ch.Discard()
			return nil, Unavailable{}
		}
	}
	return &optionsState{record: cloneCeremony(r), challenge: ch, rpName: s.config.RelyingParty.Name}, nil
}
func (s *service) BeginRegistration(ctx context.Context, r BeginRegistrationRequest) (RegistrationOptions, error) {
	o, e := s.create(ctx, r.Context, r.UserHandle, r.Origin, "create", r.ExcludedCredentials, r.ResidentKeyRequired)
	return RegistrationOptions{state: o}, e
}
func (s *service) BeginAssertion(ctx context.Context, r BeginAssertionRequest) (AssertionOptions, error) {
	o, e := s.create(ctx, r.Context, r.UserHandle, r.Origin, "get", r.AllowedCredentials, false)
	return AssertionOptions{state: o}, e
}
func (s *service) BeginDiscoverableAssertion(ctx context.Context, r BeginDiscoverableAssertionRequest) (AssertionOptions, error) {
	o, e := s.create(ctx, r.Context, nil, r.Origin, "get-discoverable", nil, false)
	return AssertionOptions{state: o}, e
}

func (s *service) load(ctx context.Context, c CeremonyContext, id, origin, kind string, version uint64) (CeremonyRecord, error) {
	valid := s.validContext(c)
	if kind == "get-discoverable" {
		valid = s.validDiscoverableContext(c)
	}
	if !valid || !safeID(id) || !s.origin(origin) || version == 0 {
		return CeremonyRecord{}, Invalid{Field: "ceremony"}
	}
	r, e := s.store.LoadCeremony(ctx, Lookup{Context: c, RPID: s.config.RelyingParty.ID, CeremonyID: id})
	if e != nil {
		return CeremonyRecord{}, Denied{}
	}
	validShape := len(r.Intent.UserHandle) == 32
	if kind == "get-discoverable" {
		validShape = len(r.Intent.UserHandle) == 0 && len(r.Intent.AllowedCredentials) == 0 && !r.Intent.ResidentKeyRequired
	}
	if r.ID != id || r.Version != version || r.Intent.Kind != kind || r.Intent.Context.TenantID != c.TenantID || r.Intent.Context.UserID != c.UserID || r.Intent.Context.AnonymousFlowID != c.AnonymousFlowID || r.Intent.Context.ActorID != c.ActorID || r.Intent.RPID != s.config.RelyingParty.ID || r.Intent.RPVersion != s.config.RelyingParty.Version || r.Intent.Origin != origin || r.Intent.Extensions != s.config.Extensions || !validShape || !validIDs(r.Intent.AllowedCredentials) || r.ChallengeDigest == ([32]byte{}) || r.ExpiresAt.IsZero() {
		return CeremonyRecord{}, Denied{}
	}
	return cloneCeremony(r), nil
}
func (s *service) client(wire []byte, r CeremonyRecord, kind string) error {
	if e := validateJSON(wire, 16<<10); e != nil {
		return e
	}
	var c clientData
	if json.Unmarshal(wire, &c) != nil || c.Type != "webauthn."+kind || c.Origin != r.Intent.Origin || c.CrossOrigin || len(c.TopOrigin) != 0 {
		return Denied{}
	}
	b, e := decodeBase64(c.Challenge, 32)
	if e != nil || len(b) != 32 {
		return Denied{}
	}
	d := challengeDigest(s.config.ChallengeKey.key(), r, b)
	clear(b)
	if !hmac.Equal(d[:], r.ChallengeDigest[:]) {
		return Denied{}
	}
	return nil
}

func (s *service) VerifyRegistration(ctx context.Context, r VerifyRegistrationRequest) (VerifiedRegistration, error) {
	if ctx == nil {
		return VerifiedRegistration{}, Invalid{Field: "context"}
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	ceremony, e := s.load(ctx, r.Context, r.CeremonyID, r.Origin, "create", r.ExpectedVersion)
	if e != nil {
		return VerifiedRegistration{}, e
	}
	b, id, client, e := parseResponse(r.Response)
	if e != nil {
		return VerifiedRegistration{}, e
	}
	if e = s.client(client, ceremony, "create"); e != nil {
		return VerifiedRegistration{}, e
	}
	for _, excluded := range ceremony.Intent.AllowedCredentials {
		if bytes.Equal(id, excluded) {
			return VerifiedRegistration{}, Denied{}
		}
	}
	att, e := decodeBase64(b.Response.AttestationObject, 64<<10)
	if e != nil {
		return VerifiedRegistration{}, e
	}
	credential, e := registrationCredential(att, id, ceremony, b.Extensions)
	if e != nil {
		return VerifiedRegistration{}, e
	}
	mutation := RegistrationMutation{Context: r.Context, Ceremony: ceremony, Credential: credential, ResponseDigest: sha256.Sum256(r.Response)}
	stored, outcome, e := s.store.FinalizeRegistration(ctx, RegistrationTransition{state: &registrationState{mutation: mutation}})
	if e != nil || outcome != identity.CommitOutcomeCommitted {
		return VerifiedRegistration{}, storeOutcome(r.Context, outcome, e)
	}
	if !sameCredential(stored, credential) {
		return VerifiedRegistration{}, Unavailable{}
	}
	final := cloneCredential(stored)
	verifiedContext := verificationContext(r.Context, ceremony, RegistrationOperation)
	return VerifiedRegistration{credential: func() Credential { return cloneCredential(final) }, context: func() VerificationContext { return verifiedContext }}, nil
}
func (s *service) VerifyAssertion(ctx context.Context, r VerifyAssertionRequest) (VerifiedAssertion, error) {
	return s.verifyAssertion(ctx, r, false)
}
func (s *service) VerifyDiscoverableAssertion(ctx context.Context, r VerifyDiscoverableAssertionRequest) (VerifiedAssertion, error) {
	return s.verifyAssertion(ctx, VerifyAssertionRequest{Context: r.Context, CeremonyID: r.CeremonyID, Origin: r.Origin, Response: r.Response, ExpectedVersion: r.ExpectedVersion}, true)
}
func (s *service) verifyAssertion(ctx context.Context, r VerifyAssertionRequest, discoverable bool) (VerifiedAssertion, error) {
	if ctx == nil || !discoverable && r.ExpectedCredentialVersion == 0 {
		return VerifiedAssertion{}, Invalid{Field: "assertion"}
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	kind := "get"
	if discoverable {
		kind = "get-discoverable"
	}
	ceremony, e := s.load(ctx, r.Context, r.CeremonyID, r.Origin, kind, r.ExpectedVersion)
	if e != nil {
		return VerifiedAssertion{}, e
	}
	b, id, client, e := parseResponse(r.Response)
	if e != nil {
		return VerifiedAssertion{}, e
	}
	if e = s.client(client, ceremony, "get"); e != nil {
		return VerifiedAssertion{}, e
	}
	allowed := false
	for _, a := range ceremony.Intent.AllowedCredentials {
		allowed = allowed || bytes.Equal(id, a)
	}
	if !allowed && !discoverable {
		return VerifiedAssertion{}, Denied{}
	}
	q := Lookup{Context: r.Context, RPID: s.config.RelyingParty.ID, CeremonyID: r.CeremonyID}
	var before Credential
	if discoverable {
		store, ok := s.store.(DiscoverableStore)
		if !ok || b.Response.UserHandle == nil {
			return VerifiedAssertion{}, Denied{}
		}
		handle, err := decodeBase64(*b.Response.UserHandle, 32)
		if err != nil || len(handle) != 32 {
			return VerifiedAssertion{}, Denied{}
		}
		before, e = store.LoadDiscoverableCredential(ctx, q, id, handle)
		if !bytes.Equal(before.UserHandle, handle) || !safeID(string(before.UserID)) || before.Version == 0 {
			return VerifiedAssertion{}, Denied{}
		}
	} else {
		before, e = s.store.LoadCredential(ctx, q, id)
	}
	if e != nil || before.TenantID != r.Context.TenantID || !discoverable && before.UserID != r.Context.UserID || before.RPID != ceremony.Intent.RPID || !bytes.Equal(before.ID, id) || !discoverable && (!bytes.Equal(before.UserHandle, ceremony.Intent.UserHandle) || before.Version != r.ExpectedCredentialVersion) || before.Algorithm != -7 || before.BackupState && !before.BackupEligible {
		return VerifiedAssertion{}, Denied{}
	}
	after, risk, e := assertionCredential(b, client, ceremony, before)
	if e != nil {
		return VerifiedAssertion{}, e
	}
	mutation := AssertionMutation{Context: r.Context, Ceremony: ceremony, Before: cloneCredential(before), After: after, ResponseDigest: sha256.Sum256(r.Response), CounterRisk: risk}
	stored, outcome, e := s.store.FinalizeAssertion(ctx, AssertionTransition{state: &assertionState{mutation: mutation}})
	if e != nil || outcome != identity.CommitOutcomeCommitted {
		return VerifiedAssertion{}, storeOutcome(r.Context, outcome, e)
	}
	if !sameCredential(stored, after) {
		return VerifiedAssertion{}, Unavailable{}
	}
	final := cloneCredential(stored)
	op := AssertionOperation
	if discoverable {
		op = DiscoverableAssertionOperation
	}
	verifiedContext := verificationContext(r.Context, ceremony, op)
	return VerifiedAssertion{credential: func() Credential { return cloneCredential(final) }, counterRisk: risk, context: func() VerificationContext { return verifiedContext }}, nil
}
func verificationContext(c CeremonyContext, r CeremonyRecord, op Operation) VerificationContext {
	return VerificationContext{Command: c, CeremonyID: r.ID, Operation: op, RPID: r.Intent.RPID, RPVersion: r.Intent.RPVersion, Origin: r.Intent.Origin, ExpiresAt: r.ExpiresAt, UserPresent: true, UserVerified: true}
}
func storeOutcome(c CeremonyContext, o identity.CommitOutcome, e error) error {
	if o == identity.CommitOutcomeUnknown || o == identity.CommitOutcomeInProgress {
		return UnknownCommit{CommandID: c.CommandID}
	}
	switch e.(type) {
	case Denied, Invalid, Conflict, Replay:
		return e
	}
	if o == identity.CommitOutcomeConflict {
		return Conflict{}
	}
	return Unavailable{}
}
func (s *service) Recover(ctx context.Context, r RecoveryRequest) (identity.CommitOutcome, error) {
	valid := s.validContext(r.Context)
	if r.Operation == BeginDiscoverableAssertionOperation || r.Operation == DiscoverableAssertionOperation {
		valid = s.validDiscoverableContext(r.Context)
	}
	begin := r.Operation == BeginRegistrationOperation || r.Operation == BeginAssertionOperation || r.Operation == BeginDiscoverableAssertionOperation
	if ctx == nil || !valid || r.Operation < BeginRegistrationOperation || r.Operation > DiscoverableAssertionOperation || (begin && len(r.CredentialID) != 0) || (!begin && (len(r.CredentialID) == 0 || len(r.CredentialID) > 1024)) {
		return identity.CommitOutcomeInvalid, Invalid{Field: "recovery"}
	}
	r.CredentialID = bytes.Clone(r.CredentialID)
	ctx, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	return s.store.Recover(ctx, r)
}
func sameIntent(a, b CeremonyIntent) bool {
	return a.Context == b.Context && a.Kind == b.Kind && a.RPID == b.RPID && a.RPVersion == b.RPVersion && a.Origin == b.Origin && a.Extensions == b.Extensions && a.ResidentKeyRequired == b.ResidentKeyRequired && bytes.Equal(a.UserHandle, b.UserHandle) && slices.EqualFunc(a.AllowedCredentials, b.AllowedCredentials, bytes.Equal)
}
func sameCredential(a, b Credential) bool {
	if a.TenantID != b.TenantID || a.UserID != b.UserID || a.RPID != b.RPID || a.Algorithm != b.Algorithm || a.AAGUID != b.AAGUID || a.Counter != b.Counter || a.BackupEligible != b.BackupEligible || a.BackupState != b.BackupState || a.Version != b.Version || !bytes.Equal(a.ID, b.ID) || !bytes.Equal(a.UserHandle, b.UserHandle) || !bytes.Equal(a.PublicKey, b.PublicKey) {
		return false
	}
	return reflect.DeepEqual(a.Extensions, b.Extensions)
}
