package webauthn

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"sync"
	"time"
)

type challengeState struct {
	mu    sync.Mutex
	bytes []byte
}
type creationState struct {
	intent CeremonyIntent
	key    [32]byte
}
type registrationState struct{ mutation RegistrationMutation }
type assertionState struct{ mutation AssertionMutation }
type optionsState struct {
	record    CeremonyRecord
	challenge Challenge
	rpName    string
}

// Discard invalidates every alias and clears unrevealed bytes, including on
// unknown commit paths. It performs no IO and is safe beside Transfer.
func (c Challenge) Discard() {
	if c.access == nil {
		return
	}
	s := c.access()
	s.mu.Lock()
	clear(s.bytes)
	s.bytes = nil
	s.mu.Unlock()
}

// Transfer invalidates every challenge alias before calling deliver. Borrowed
// bytes are cleared afterward, including errors and panics. Delivery failure
// does not undo a committed ceremony and never permits re-reveal on retry.
func (c Challenge) Transfer(ctx context.Context, deliver func(context.Context, []byte) error) (err error) {
	if ctx == nil || deliver == nil || c.access == nil {
		return Invalid{Field: "challenge"}
	}
	if ctx.Err() != nil {
		return Unavailable{}
	}
	state := c.access()
	state.mu.Lock()
	b := state.bytes
	state.bytes = nil
	state.mu.Unlock()
	if len(b) != 32 {
		return Denied{}
	}
	defer func() {
		clear(b)
		if recover() != nil {
			err = Unavailable{}
		}
	}()
	if err = deliver(ctx, b); err != nil {
		return Unavailable{}
	}
	return nil
}

// Intent returns an owned copy of every original caller-controlled input.
func (c CeremonyCreation) Intent() (CeremonyIntent, error) {
	if c.access == nil {
		return CeremonyIntent{}, Invalid{Field: "ceremony_creation"}
	}
	return cloneIntent(c.access().intent), nil
}

// Generate creates original challenge output with crypto/rand outside SQL.
// Adapters call this only after acknowledged command reservation. now is a
// primary-authority clock sample. The digest binds complete ceremony scope.
func (c CeremonyCreation) Generate(ctx context.Context, now time.Time) (CeremonyRecord, Challenge, error) {
	if ctx == nil || ctx.Err() != nil || c.access == nil || now.IsZero() {
		return CeremonyRecord{}, Challenge{}, Invalid{Field: "ceremony_creation"}
	}
	state := c.access()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return CeremonyRecord{}, Challenge{}, Unavailable{}
	}
	r := CeremonyRecord{Intent: cloneIntent(state.intent), ID: string(state.intent.Context.CommandID), ExpiresAt: now.UTC().Truncate(time.Microsecond).Add(5 * time.Minute), Version: 1}
	r.ChallengeDigest = challengeDigest(state.key, r, b)
	owned := &challengeState{bytes: b}
	return r, Challenge{access: func() *challengeState { return owned }}, nil
}

// Mutation returns an owned provisional native projection. Zero transitions
// cannot be reconstructed from public fields; only the verifier issues them.
func (t RegistrationTransition) Mutation() (RegistrationMutation, error) {
	if t.state == nil {
		return RegistrationMutation{}, Invalid{Field: "registration_transition"}
	}
	m := t.state.mutation
	m.Ceremony = cloneCeremony(m.Ceremony)
	m.Credential = cloneCredential(m.Credential)
	return m, nil
}

// Mutation returns the original verified optimistic transition, never a rebase.
func (t AssertionTransition) Mutation() (AssertionMutation, error) {
	if t.state == nil {
		return AssertionMutation{}, Invalid{Field: "assertion_transition"}
	}
	m := t.state.mutation
	m.Ceremony = cloneCeremony(m.Ceremony)
	m.Before = cloneCredential(m.Before)
	m.After = cloneCredential(m.After)
	return m, nil
}

// Credential returns owned finalized metadata and false for the invalid zero.
func (v VerifiedRegistration) Credential() (Credential, bool) {
	if v.credential == nil {
		return Credential{}, false
	}
	return v.credential(), true
}

// Context returns original immutable ceremony/command facts, not fresh authority.
func (v VerifiedRegistration) Context() (VerificationContext, bool) {
	if v.context == nil {
		return VerificationContext{}, false
	}
	return v.context(), true
}

// Context returns original immutable ceremony/command facts, not fresh authority.
func (v VerifiedAssertion) Context() (VerificationContext, bool) {
	if v.context == nil {
		return VerificationContext{}, false
	}
	return v.context(), true
}

// Credential returns owned finalized metadata and false for the invalid zero.
func (v VerifiedAssertion) Credential() (Credential, bool) {
	if v.credential == nil {
		return Credential{}, false
	}
	return v.credential(), true
}

// CounterRisk reports a selected backup-credential counter warning only after
// successful finalization. False also represents an invalid zero result.
func (v VerifiedAssertion) CounterRisk() bool { return v.credential != nil && v.counterRisk }

// Ceremony returns safe original metadata, including for a committed retry
// whose reveal-once challenge is unavailable. It does not expose challenge data.
func (o RegistrationOptions) Ceremony() (CeremonyRecord, bool) {
	if o.state == nil {
		return CeremonyRecord{}, false
	}
	return cloneCeremony(o.state.record), true
}

// Ceremony returns safe original assertion metadata, never authentication.
func (o AssertionOptions) Ceremony() (CeremonyRecord, bool) {
	if o.state == nil {
		return CeremonyRecord{}, false
	}
	return cloneCeremony(o.state.record), true
}

// TransferJSON delivers bounded browser creation options exactly once. The
// callback owns any explicit copy and must not log its challenge-bearing input.
func (o RegistrationOptions) TransferJSON(ctx context.Context, deliver func(context.Context, []byte) error) error {
	if o.state == nil {
		return Invalid{Field: "options"}
	}
	return o.state.transfer(ctx, deliver, true)
}

// TransferJSON delivers bounded browser assertion options exactly once.
func (o AssertionOptions) TransferJSON(ctx context.Context, deliver func(context.Context, []byte) error) error {
	if o.state == nil {
		return Invalid{Field: "options"}
	}
	return o.state.transfer(ctx, deliver, false)
}
func (o *optionsState) transfer(ctx context.Context, deliver func(context.Context, []byte) error, registration bool) error {
	if deliver == nil {
		return Invalid{Field: "delivery"}
	}
	return o.challenge.Transfer(ctx, func(ctx context.Context, b []byte) error {
		options := map[string]any{"challenge": base64.RawURLEncoding.EncodeToString(b), "timeout": 300000, "userVerification": "required"}
		if registration {
			options["rp"] = map[string]string{"id": o.record.Intent.RPID, "name": o.rpName}
			h := base64.RawURLEncoding.EncodeToString(o.record.Intent.UserHandle)
			options["user"] = map[string]string{"id": h, "name": h, "displayName": h}
			options["pubKeyCredParams"] = []map[string]any{{"type": "public-key", "alg": -7}}
			options["attestation"] = "none"
			options["authenticatorSelection"] = map[string]any{"userVerification": "required", "residentKey": "discouraged"}
			exclude := make([]map[string]string, len(o.record.Intent.AllowedCredentials))
			for i, id := range o.record.Intent.AllowedCredentials {
				exclude[i] = map[string]string{"type": "public-key", "id": base64.RawURLEncoding.EncodeToString(id)}
			}
			options["excludeCredentials"] = exclude
		} else {
			options["rpId"] = o.record.Intent.RPID
			allow := make([]map[string]string, len(o.record.Intent.AllowedCredentials))
			for i, id := range o.record.Intent.AllowedCredentials {
				allow[i] = map[string]string{"type": "public-key", "id": base64.RawURLEncoding.EncodeToString(id)}
			}
			options["allowCredentials"] = allow
		}
		ext := map[string]any{}
		// WebAuthn CR20260526 §10.4 and CTAP2.1 §12.1 define these inputs
		// only for registration. Browsers reject credProps on get(), and an
		// assertion must not request a new credential-protection policy.
		if registration && o.record.Intent.Extensions.CredentialProperties {
			ext["credProps"] = true
		}
		if p := o.record.Intent.Extensions.CredentialProtection; registration && p != 0 {
			ext["credentialProtectionPolicy"] = []string{"", "userVerificationOptional", "userVerificationOptionalWithCredentialIDList", "userVerificationRequired"}[p]
			ext["enforceCredentialProtectionPolicy"] = o.record.Intent.Extensions.EnforceCredentialProtection
		}
		if len(ext) > 0 {
			options["extensions"] = ext
		}
		wire, err := json.Marshal(map[string]any{"publicKey": options})
		if err != nil {
			return Unavailable{}
		}
		defer clear(wire)
		return deliver(ctx, wire)
	})
}

func challengeDigest(key [32]byte, r CeremonyRecord, challenge []byte) [32]byte {
	h := hmac.New(sha256.New, key[:])
	_, _ = h.Write([]byte("webauthn-challenge-v1"))
	for _, v := range []string{string(r.Intent.Context.TenantID), string(r.Intent.Context.UserID), r.Intent.Kind, r.Intent.RPID, r.Intent.Origin, r.ID} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(v)))
		_, _ = h.Write(n[:])
		_, _ = h.Write([]byte(v))
	}
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], r.Intent.RPVersion)
	_, _ = h.Write(n[:])
	binary.BigEndian.PutUint64(n[:], uint64(r.ExpiresAt.UnixMicro()))
	_, _ = h.Write(n[:])
	_, _ = h.Write(challenge)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
func cloneIntent(i CeremonyIntent) CeremonyIntent {
	i.UserHandle = bytes.Clone(i.UserHandle)
	i.AllowedCredentials = cloneIDs(i.AllowedCredentials)
	return i
}
func cloneCeremony(r CeremonyRecord) CeremonyRecord { r.Intent = cloneIntent(r.Intent); return r }
func cloneIDs(ids [][]byte) [][]byte {
	out := make([][]byte, len(ids))
	for i, id := range ids {
		out[i] = bytes.Clone(id)
	}
	return out
}
func cloneExtensions(e ExtensionOutputSet) ExtensionOutputSet {
	if e.CredentialProperties != nil {
		v := *e.CredentialProperties
		e.CredentialProperties = &v
	}
	if e.CredentialProtection != nil {
		v := *e.CredentialProtection
		e.CredentialProtection = &v
	}
	return e
}
func cloneCredential(c Credential) Credential {
	c.ID = bytes.Clone(c.ID)
	c.UserHandle = bytes.Clone(c.UserHandle)
	c.PublicKey = bytes.Clone(c.PublicKey)
	c.Extensions = cloneExtensions(c.Extensions)
	return c
}
