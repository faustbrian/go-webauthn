// Package webauthn implements a bounded WebAuthn Level 3 none-attestation,
// ES256 or explicitly selected Ed25519 protocol profile. It does not authorize
// identity enrollment or issue sessions. Trusted workflows authorize context first.
package webauthn

import (
	"context"
	"fmt"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// Invalid is a redacted structural/configuration error. Field is a static name.
type Invalid struct{ Field string }

func (Invalid) Error() string { return "webauthn: invalid input" }

// Denied intentionally does not distinguish missing, expired or wrong-scope state.
type Denied struct{}

func (Denied) Error() string { return "webauthn: denied" }

// Conflict identifies optimistic, idempotency or RP-wide uniqueness conflicts.
type Conflict struct{}

func (Conflict) Error() string { return "webauthn: conflict" }

// Replay reports historical commitment without issuing fresh verification or
// challenge custody. Recover returns the original safe command outcome.
type Replay struct{ CommandID identity.CommandID }

func (Replay) Error() string { return "webauthn: operation already committed" }

// Unavailable is a redacted dependency failure, never evidence of rollback.
type Unavailable struct{}

func (Unavailable) Error() string { return "webauthn: unavailable" }

// UnknownCommit requires recovery of this exact original command, not a new ID.
type UnknownCommit struct{ CommandID identity.CommandID }

func (UnknownCommit) Error() string { return "webauthn: command outcome unknown" }

// CeremonyContext comes from an already authorized trusted workflow, never Host,
// forwarded headers or a browser body. It is not proof of identity or a session.
// Use a fresh identity.NewCommandID for each operation and retain it on retries.
type CeremonyContext struct {
	CommandID identity.CommandID
	TenantID  identity.TenantID
	UserID    identity.UserID
	// AnonymousFlowID selects a trusted pre-authentication transaction only for
	// discoverable assertions. It is mutually exclusive with UserID.
	AnonymousFlowID string `json:",omitempty"`
	ActorID         identity.ActorID
	CorrelationID   string
}

func (CeremonyContext) Format(s fmt.State, _ rune) { redact(s) }

// RelyingParty is fixed before processing browser input. Version changes when
// any RP/origin/extension policy changes; old ceremonies cannot be reinterpreted.
// TenantID is selected before RP lookup. Shared-RP mappings are not yet selected.
type RelyingParty struct {
	ID      string
	Name    string
	Origins []string
	Version uint64
}

// ExtensionRequestSet selects creation-only credProps and credProtect. Zero
// requests neither. CredentialProtection is 0 (absent) or FIDO values 1, 2 or 3.
// Assertions retain this frozen policy but emit no creation-only inputs.
type ExtensionRequestSet struct {
	CredentialProperties        bool
	CredentialProtection        uint8
	EnforceCredentialProtection bool
}

// CredentialPropertiesOutput is an untrusted browser claim, never signed
// authenticator authority and never sufficient to authorize a policy decision.
type CredentialPropertiesOutput struct {
	ResidentKey bool
	Authority   ExtensionAuthority
}

// CredentialProtectionOutput records creation authenticator data. Registration
// with none attestation provides no device provenance. Assertions preserve this
// metadata, never promoting unsolicited output into fresh enrollment authority.
type CredentialProtectionOutput struct {
	Policy    uint8
	Authority ExtensionAuthority
}

// ExtensionAuthority prevents retained browser/none-attestation claims from
// being promoted to fresh signed authenticator evidence by downstream callers.
type ExtensionAuthority uint8

const (
	// BrowserReported is unsigned client-extension output, never authorization.
	BrowserReported ExtensionAuthority = iota + 1
	// UnattestedAuthenticator is structurally accepted registration authData
	// under none attestation, without authenticator provenance/signature trust.
	UnattestedAuthenticator
)

// ExtensionOutputSet retains only explicitly requested typed outputs. Unknown
// and unselected extensions are discarded without persistence or advertisement.
type ExtensionOutputSet struct {
	CredentialProperties *CredentialPropertiesOutput
	CredentialProtection *CredentialProtectionOutput
}

// Algorithm identifies one supported COSE signature algorithm and exact key
// profile. Other COSE values, including other EdDSA curves, are unsupported.
type Algorithm int32

const (
	// ES256 selects ECDSA P-256 with SHA-256 (COSE alg=-7, kty=2, crv=1).
	ES256 Algorithm = -7
	// EdDSA selects only Ed25519 (COSE alg=-8, kty=1, crv=6), not Ed448.
	EdDSA Algorithm = -8
)

// Config selects one trusted tenant and one RP. This finite profile always
// requires UP and UV, none attestation, and a five-minute 32-byte challenge.
// ChallengeKey is a nonzero deployment-owned HMAC key; keep it stable while
// ceremonies exist. The service copies it and never serializes it.
type Config struct {
	TenantID     identity.TenantID
	RelyingParty RelyingParty
	Extensions   ExtensionRequestSet
	// Algorithms is an ordered, copied allowlist used for both ceremonies.
	// Nil preserves the legacy ES256-only profile and stored ceremony bytes.
	// An explicit list must be nonempty, unique and limited to ES256/EdDSA.
	// Changing it invalidates in-flight ceremonies; also advance RP.Version.
	Algorithms               []Algorithm
	ChallengeKey             ChallengeDigestKey
	DevelopmentLocalhostHTTP bool
	MaximumDuration          time.Duration
}

func (Config) Format(s fmt.State, _ rune)   { redact(s) }
func (Config) MarshalJSON() ([]byte, error) { return nil, Invalid{Field: "configuration"} }

// ChallengeDigestKey is immutable opaque deployment-key custody. Its closure
// representation also protects keys inside unexported enclosing fmt wrappers.
// The caller retains responsibility for its original input copy. Zero is invalid.
type ChallengeDigestKey struct{ key func() [32]byte }

func (ChallengeDigestKey) Format(s fmt.State, _ rune)   { redact(s) }
func (ChallengeDigestKey) MarshalJSON() ([]byte, error) { return nil, Invalid{Field: "challenge_key"} }

// NewChallengeDigestKey copies a nonzero exact 32-byte key without IO.
func NewChallengeDigestKey(input []byte) (ChallengeDigestKey, error) {
	if len(input) != 32 {
		return ChallengeDigestKey{}, Invalid{Field: "challenge_key"}
	}
	var key [32]byte
	copy(key[:], input)
	if key == ([32]byte{}) {
		return ChallengeDigestKey{}, Invalid{Field: "challenge_key"}
	}
	return ChallengeDigestKey{key: func() [32]byte { return key }}, nil
}

// Dependencies are borrowed, concurrent-safe dependencies; the service never
// closes them. Store must be a durable participant, not an application map.
type Dependencies struct{ Store Store }

// CeremonyIntent is the complete safe generated-state request. Challenge bytes
// are deliberately absent. Consumers must not log opaque handles or user data.
// Policy fields are frozen by the service, not recovered from browser input.
type CeremonyIntent struct {
	Context            CeremonyContext
	Kind               string
	RPID               string
	RPVersion          uint64
	Origin             string
	UserHandle         []byte
	AllowedCredentials [][]byte
	Extensions         ExtensionRequestSet
	// ResidentKeyRequired selects resident-required creation, never a claim
	// that an unsigned browser extension proves authenticator residency.
	ResidentKeyRequired bool `json:",omitempty"`
	// Algorithms freezes the exact explicit profile. Absent means legacy ES256,
	// never the current service's expanded policy. Omission preserves old rows.
	Algorithms []Algorithm `json:",omitempty"`
}

func (CeremonyIntent) Format(s fmt.State, _ rune) { redact(s) }

// CeremonyRecord contains only a scoped keyed challenge digest at rest. Versions
// start at 1. Store queries bind tenant/RP/ceremony and subject or pre-auth flow.
type CeremonyRecord struct {
	Intent          CeremonyIntent
	ID              string
	ChallengeDigest [32]byte
	ExpiresAt       time.Time
	Version         uint64
}

func (CeremonyRecord) Format(s fmt.State, _ rune) { redact(s) }

// Challenge is opaque reveal-once custody. Only Transfer exposes bytes to a
// synchronous browser-delivery callback outside database work. Copies share
// lifetime; diagnostics and serialization never expose bytes. Zero is invalid.
type Challenge struct{ access func() *challengeState }

func (Challenge) Format(s fmt.State, _ rune)   { redact(s) }
func (Challenge) MarshalJSON() ([]byte, error) { return nil, Invalid{Field: "challenge"} }

// CeremonyCreation is issued only by Service. Its immutable intent can be read
// by a durable adapter; Generate runs only after acknowledged command ownership,
// outside SQL. Generated challenge is an output, not a caller-supplied input.
// Raw challenge custody must never enter retained preparation or journal data.
type CeremonyCreation struct{ access func() *creationState }

func (CeremonyCreation) Format(s fmt.State, _ rune) { redact(s) }

// Credential is public verification metadata, never authentication evidence.
// Byte slices are owned snapshots. Version is positive and monotonically grows.
// Credential IDs/user-handle mappings are unique across the whole RP, not tenant.
type Credential struct {
	TenantID       identity.TenantID
	UserID         identity.UserID
	RPID           string
	ID             []byte
	UserHandle     []byte
	PublicKey      []byte
	Algorithm      int32
	AAGUID         [16]byte
	Counter        uint32
	BackupEligible bool
	BackupState    bool
	Extensions     ExtensionOutputSet
	Version        uint64
}

func (Credential) Format(s fmt.State, _ rune) { redact(s) }

// Lookup carries exact trusted tenant/RP/ceremony and subject or pre-auth flow.
type Lookup struct {
	Context    CeremonyContext
	RPID       string
	CeremonyID string
}

func (Lookup) Format(s fmt.State, _ rune) { redact(s) }

// RegistrationTransition is immutable protocol-verifier output. Only Service
// can create it. It is provisional and not an authenticated result; native
// adapters consume the ceremony and create Credential in one coordinated commit.
type RegistrationTransition struct{ state *registrationState }

func (RegistrationTransition) Format(s fmt.State, _ rune) { redact(s) }

// AssertionTransition is immutable verified-signature input to atomic storage.
// Store must compare the original versions, not rebase a stale assertion.
type AssertionTransition struct{ state *assertionState }

func (AssertionTransition) Format(s fmt.State, _ rune) { redact(s) }

// RegistrationMutation is a copied native-adapter projection, not authority to
// construct a RegistrationTransition or bypass the public verifier.
type RegistrationMutation struct {
	Context        CeremonyContext
	Ceremony       CeremonyRecord
	Credential     Credential
	ResponseDigest [32]byte
}

func (RegistrationMutation) Format(s fmt.State, _ rune) { redact(s) }

// AssertionMutation fixes the exact verified before/after credential state.
// CounterRisk is bounded risk evidence for backup-eligible counter regressions;
// it is not an automatic clone verdict. Counter never decreases.
type AssertionMutation struct {
	Context        CeremonyContext
	Ceremony       CeremonyRecord
	Before         Credential
	After          Credential
	ResponseDigest [32]byte
	CounterRisk    bool
}

func (AssertionMutation) Format(s fmt.State, _ rune) { redact(s) }

// Store is the storage-neutral complete ceremony/credential participant seam.
// No method exposes a concrete coordinator, transaction, or identity.UnitOfWork.
// Create may call Generate only after reservation is acknowledged and outside
// SQL. It reveals challenge custody only for acknowledged first commit; retries
// return original safe record and zero challenge. Finalize methods atomically
// consume the exact ceremony/version and insert or update credential, together
// with mandatory audit/lifecycle and the original command receipt. Unknown
// outcomes return no credential, no challenge and no verified result.
// All methods must support concurrent bounded calls and preserve tenant scope.
type Store interface {
	CreateCeremony(context.Context, CeremonyCreation) (CeremonyRecord, Challenge, identity.CommitOutcome, error)
	LoadCeremony(context.Context, Lookup) (CeremonyRecord, error)
	LoadCredential(context.Context, Lookup, []byte) (Credential, error)
	FinalizeRegistration(context.Context, RegistrationTransition) (Credential, identity.CommitOutcome, error)
	FinalizeAssertion(context.Context, AssertionTransition) (Credential, identity.CommitOutcome, error)
	Recover(context.Context, RecoveryRequest) (identity.CommitOutcome, error)
}

// DiscoverableStore is the optional durable resolution seam. Lookup must carry
// an anonymous context and the original ceremony. Resolve exactly RP, credential
// ID and mandatory handle, scope tenant without disambiguating RP uniqueness,
// and preserve original pre-transition state for exact retries. FinalizeAssertion
// must check the resolved active subject inside its atomic commit, consume the
// anonymous ceremony and CAS-update that same credential and handle mapping.
type DiscoverableStore interface {
	Store
	LoadDiscoverableCredential(context.Context, Lookup, []byte, []byte) (Credential, error)
}

// BeginRegistrationRequest fixes the opaque 32-byte RP-wide user handle and
// exact allowed origin. The trusted caller owns prior identity authorization.
// ResidentKeyRequired opts into resident-required browser creation; false keeps
// the existing discouraged profile. Neither none attestation nor credProps
// proves physical residency or authenticator provenance.
type BeginRegistrationRequest struct {
	Context             CeremonyContext
	UserHandle          []byte
	Origin              string
	ExcludedCredentials [][]byte
	ResidentKeyRequired bool
}

// BeginAssertionRequest selects an existing identified subject and a nonempty
// allowlist of at most 100 credentials. Use DiscoverableService for usernameless.
type BeginAssertionRequest struct {
	Context            CeremonyContext
	UserHandle         []byte
	Origin             string
	AllowedCredentials [][]byte
}

// BeginDiscoverableAssertionRequest requires an empty Context.UserID and a
// trusted bounded Context.AnonymousFlowID. No user handle or allowlist is known.
type BeginDiscoverableAssertionRequest struct {
	Context CeremonyContext
	Origin  string
}

// VerifyDiscoverableAssertionRequest retains the exact original pre-auth flow.
// Credential version is read from primary storage and atomically compared; the
// browser cannot choose a subject, handle mapping or expected credential version.
type VerifyDiscoverableAssertionRequest struct {
	Context         CeremonyContext
	CeremonyID      string
	Origin          string
	Response        []byte
	ExpectedVersion uint64
}

// RegistrationOptions contains JSON browser options plus opaque challenge
// custody. TransferJSON emits a fresh challenge only once after durable creation.
type RegistrationOptions struct{ state *optionsState }

func (RegistrationOptions) Format(s fmt.State, _ rune) { redact(s) }

// AssertionOptions contains identified-assertion browser options after commit.
type AssertionOptions struct{ state *optionsState }

func (AssertionOptions) Format(s fmt.State, _ rune) { redact(s) }

// VerifyRegistrationRequest is bounded raw browser JSON, not verified evidence.
// Context.CommandID is distinct from the creation command and stable on retry.
type VerifyRegistrationRequest struct {
	Context         CeremonyContext
	CeremonyID      string
	Origin          string
	Response        []byte
	ExpectedVersion uint64
}

// VerifyAssertionRequest additionally pins the observed credential version.
type VerifyAssertionRequest struct {
	Context                   CeremonyContext
	CeremonyID                string
	Origin                    string
	Response                  []byte
	ExpectedVersion           uint64
	ExpectedCredentialVersion uint64
}

// Operation is the closed recoverable native operation. Zero is invalid.
type Operation uint8

const (
	// BeginRegistrationOperation recovers original challenge creation metadata.
	BeginRegistrationOperation Operation = iota + 1
	// BeginAssertionOperation recovers original assertion creation metadata.
	BeginAssertionOperation
	// RegistrationOperation recovers original credential creation.
	RegistrationOperation
	// AssertionOperation recovers original counter/backup update.
	AssertionOperation
	// BeginDiscoverableAssertionOperation recovers anonymous ceremony creation.
	BeginDiscoverableAssertionOperation
	// DiscoverableAssertionOperation recovers anonymous credential finalization.
	DiscoverableAssertionOperation
)

// RecoveryRequest retains exact original command scope, including anonymous flow
// for discoverable operations. CredentialID is required only for completion.
// Recovery returns safe historical
// outcome, never a challenge, Verified result or renewed authentication proof.
type RecoveryRequest struct {
	Context      CeremonyContext
	Operation    Operation
	CredentialID []byte
}

func (RecoveryRequest) Format(s fmt.State, _ rune) { redact(s) }

// VerifiedRegistration can only be issued after successful durable finalization.
// It is WebAuthn protocol evidence, not a principal, session or enrollment grant.
type VerifiedRegistration struct {
	credential func() Credential
	context    func() VerificationContext
}

func (VerifiedRegistration) Format(s fmt.State, _ rune) { redact(s) }

// VerifiedAssertion can only be issued after signature checks and durable
// challenge consumption/counter/backup update. Copies cannot renew authority.
type VerifiedAssertion struct {
	credential  func() Credential
	counterRisk bool
	context     func() VerificationContext
}

func (VerifiedAssertion) Format(s fmt.State, _ rune) { redact(s) }

// VerificationContext preserves the exact original finalized ceremony and
// completion command. ExpiresAt is the original absolute ceremony ceiling,
// never a new validity lease. These are historical protocol facts; consumers
// still require their owning identity/current-authority and factor policy.
type VerificationContext struct {
	Command      CeremonyContext
	CeremonyID   string
	Operation    Operation
	RPID         string
	RPVersion    uint64
	Origin       string
	ExpiresAt    time.Time
	UserPresent  bool
	UserVerified bool
}

func (VerificationContext) Format(s fmt.State, _ rune) { redact(s) }

// Service owns the selected complete protocol path, never session or passkey UX.
type Service interface {
	BeginRegistration(context.Context, BeginRegistrationRequest) (RegistrationOptions, error)
	BeginAssertion(context.Context, BeginAssertionRequest) (AssertionOptions, error)
	VerifyRegistration(context.Context, VerifyRegistrationRequest) (VerifiedRegistration, error)
	VerifyAssertion(context.Context, VerifyAssertionRequest) (VerifiedAssertion, error)
	Recover(context.Context, RecoveryRequest) (identity.CommitOutcome, error)
}

// DiscoverableService adds resident-required registration/usernameless assertion
// without changing the identified Service or Store contracts. Results remain
// protocol facts, not identity enrollment grants, sessions or authorization.
type DiscoverableService interface {
	Service
	BeginDiscoverableAssertion(context.Context, BeginDiscoverableAssertionRequest) (AssertionOptions, error)
	VerifyDiscoverableAssertion(context.Context, VerifyDiscoverableAssertionRequest) (VerifiedAssertion, error)
}

func redact(s fmt.State) { _, _ = s.Write([]byte("webauthn(redacted)")) }
