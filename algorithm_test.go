package webauthn

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"slices"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// RFC 8032 §7.1 TEST 1 public key; this is published test material, not a
// credential. The complete source identity is recorded in protocol-sources.md.
func ed25519COSE(t *testing.T) []byte {
	t.Helper()
	key, err := hex.DecodeString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte{0xa4, 1, 1, 3, 0x27, 0x20, 6, 0x21, 0x58, 32}, key...)
}

func TestAlgorithmConfigurationSnapshotsExactSelection(t *testing.T) {
	key, _ := NewChallengeDigestKey(bytes.Repeat([]byte{9}, 32))
	c := Config{TenantID: "tenant", RelyingParty: RelyingParty{ID: "example.com", Name: "Example", Origins: []string{"https://example.com"}, Version: 1}, ChallengeKey: key, MaximumDuration: time.Second}
	// Construction owns only configuration validation: no store method is called.
	d := Dependencies{Store: struct{ Store }{}}
	for _, invalid := range [][]Algorithm{{}, {ES256, ES256}, {EdDSA, EdDSA}, {-257}, {0}, {ES256, EdDSA, ES256}} {
		c.Algorithms = invalid
		if s, err := New(c, d); err == nil || s != nil {
			t.Fatal("invalid algorithm policy accepted", invalid)
		}
	}
	for _, selected := range [][]Algorithm{nil, {ES256}, {EdDSA}, {EdDSA, ES256}} {
		c.Algorithms = slices.Clone(selected)
		s, err := New(c, d)
		if err != nil {
			t.Fatal(err)
		}
		if len(c.Algorithms) != 0 {
			c.Algorithms[0] = 0
		}
		if !slices.Equal(s.(*service).config.Algorithms, selected) {
			t.Fatal("caller mutation changed service algorithm authority")
		}
	}
}

func TestAlgorithmOptionsAndCeremonyAuthority(t *testing.T) {
	for _, selected := range [][]Algorithm{nil, {EdDSA}, {EdDSA, ES256}, {ES256}} {
		intent := CeremonyIntent{RPID: "example.com", Algorithms: slices.Clone(selected)}
		creation := CeremonyCreation{access: func() *creationState { return &creationState{intent: intent, key: [32]byte{1}} }}
		r, ch, err := creation.Generate(context.Background(), time.Unix(1700000000, 0))
		if err != nil {
			t.Fatal(err)
		}
		original := cloneCeremony(r)
		if len(r.Intent.Algorithms) != 0 {
			r.Intent.Algorithms[0] = 0
		}
		if !slices.Equal(intent.Algorithms, selected) || !slices.Equal(original.Intent.Algorithms, selected) {
			t.Fatal("ceremony snapshot aliases caller or another snapshot")
		}
		options := RegistrationOptions{state: &optionsState{record: original, challenge: ch}}
		if err = options.TransferJSON(context.Background(), func(_ context.Context, wire []byte) error {
			var doc struct {
				PublicKey struct {
					Params []struct {
						Type string    `json:"type"`
						Alg  Algorithm `json:"alg"`
					} `json:"pubKeyCredParams"`
				} `json:"publicKey"`
			}
			if json.Unmarshal(wire, &doc) != nil {
				t.Fatal("options JSON")
			}
			want := selected
			if want == nil {
				want = []Algorithm{ES256}
			}
			if len(doc.PublicKey.Params) != len(want) {
				t.Fatal("advertised profile widened")
			}
			for i, p := range doc.PublicKey.Params {
				if p.Type != "public-key" || p.Alg != want[i] {
					t.Fatal("algorithm order/profile lost")
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	r := CeremonyRecord{Intent: CeremonyIntent{RPID: "example.com"}, ID: "original", ExpiresAt: time.Unix(1700000000, 0)}
	wire, _ := json.Marshal(r)
	if bytes.Contains(wire, []byte("Algorithms")) {
		t.Fatal("legacy serialization changed")
	}
	legacy := challengeDigest([32]byte{1}, r, make([]byte, 32))
	if hex.EncodeToString(legacy[:]) != "d1870db574e6545dbe045165d5b0fb56b20588ca08878f9fb2d59fd98e20ec89" {
		t.Fatal("legacy v1 challenge fingerprint changed")
	}
	for _, profile := range [][]Algorithm{{ES256}, {ES256, EdDSA}, {EdDSA, ES256}} {
		r.Intent.Algorithms = profile
		digest := challengeDigest([32]byte{1}, r, make([]byte, 32))
		if legacy == digest {
			t.Fatal("algorithm policy does not bind original challenge")
		}
		legacy = digest
	}
}

type algorithmCeremonyStore struct {
	Store
	record CeremonyRecord
}

func (s algorithmCeremonyStore) LoadCeremony(context.Context, Lookup) (CeremonyRecord, error) {
	return cloneCeremony(s.record), nil
}

func TestDecodedEmptyPolicyCannotImpersonateLegacyCeremony(t *testing.T) {
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	c := CeremonyContext{CommandID: id, TenantID: "tenant", UserID: "user", ActorID: "actor", CorrelationID: "test"}
	r := CeremonyRecord{ID: string(id), Version: 1, ExpiresAt: time.Now().Add(time.Minute), ChallengeDigest: [32]byte{1}, Intent: CeremonyIntent{Context: c, Kind: "create", RPID: "example.com", RPVersion: 1, Origin: "https://example.com", UserHandle: make([]byte, 32)}}
	key, _ := NewChallengeDigestKey(bytes.Repeat([]byte{1}, 32))
	config := Config{TenantID: "tenant", RelyingParty: RelyingParty{ID: "example.com", Name: "Example", Origins: []string{"https://example.com"}, Version: 1}, ChallengeKey: key, MaximumDuration: time.Second}
	for _, raw := range []string{`{}`, `{"Algorithms":null}`, `{"Algorithms":[]}`, `{"Algorithms":[-8]}`, `{"Algorithms":[-7]}`, `{"Algorithms":[4294967288]}`} {
		stored := cloneCeremony(r)
		if err := json.Unmarshal([]byte(raw), &stored.Intent); err != nil {
			continue
		}
		s, err := New(config, Dependencies{Store: algorithmCeremonyStore{record: stored}})
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.(*service).load(context.Background(), c, string(id), r.Intent.Origin, "create", 1)
		legacy := raw == `{}` || raw == `{"Algorithms":null}`
		if (err == nil) != legacy {
			t.Fatal("stored policy reinterpreted as legacy", raw, err)
		}
	}
	malformed := cloneCeremony(r)
	malformed.Intent.Algorithms = []Algorithm{}
	if sameIntent(r.Intent, malformed.Intent) || allowsAlgorithm(malformed.Intent.Algorithms, ES256) {
		t.Fatal("explicit empty policy gained legacy authority")
	}
	if challengeDigest([32]byte{1}, r, make([]byte, 32)) == challengeDigest([32]byte{1}, malformed, make([]byte, 32)) {
		t.Fatal("empty policy failed to bind digest")
	}
}

func TestIndependentOpenSSLEd25519WebAuthnSignature(t *testing.T) {
	// OpenSSL 3.5.9 generated this public key/signature using pkeyutl -sign
	// -rawin over authData || SHA256(clientDataJSON). No private key is retained.
	public, _ := hex.DecodeString("8607a1b49fe012446fe783e027f0a91884b6860858b2179c0960a5a76dd997a6")
	signature, _ := hex.DecodeString("c17e2f0144253b58efdb939cf4597cf4649fb4ed1ce5574f7d65e8b4233d6aaf91bdfb978c8f4c8fbf346aa19eb1b994bafc9023f5528b41c61ed6ee20273d01")
	client := []byte(`{"type":"webauthn.get","challenge":"AA","origin":"https://login.example.com","crossOrigin":false}`)
	rp := sha256.Sum256([]byte("example.com"))
	auth := append(bytes.Clone(rp[:]), 5, 0, 0, 0, 1)
	b := browserResponse{}
	b.Response.AuthenticatorData = base64.RawURLEncoding.EncodeToString(auth)
	b.Response.Signature = base64.RawURLEncoding.EncodeToString(signature)
	c := Credential{Algorithm: -8, PublicKey: append([]byte{0xa4, 1, 1, 3, 0x27, 0x20, 6, 0x21, 0x58, 32}, public...), Version: 1}
	r := CeremonyRecord{Intent: CeremonyIntent{RPID: "example.com", Algorithms: []Algorithm{EdDSA}}}
	after, risk, err := assertionCredential(b, client, r, c)
	if err != nil || risk || after.Counter != 1 || after.Version != 2 {
		t.Fatal("independent OpenSSL signature rejected", err)
	}
}

func FuzzSelectedCOSEKeys(f *testing.F) {
	f.Add([]byte{0xa4, 1, 1, 3, 0x27, 0x20, 6, 0x21, 0x58, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{0xa0})
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 4096 {
			return
		}
		if m, err := parseCBOR(wire); err == nil {
			_, _, _ = coseKey(m)
		}
	})
}

func TestEd25519COSERejectsWrongAlgorithmTypeCurveAndLengths(t *testing.T) {
	for _, mutate := range []func(map[any]any){
		func(m map[any]any) { m[uint64(1)] = uint64(2) },
		func(m map[any]any) { m[uint64(3)] = int64(-7) },
		func(m map[any]any) { m[uint64(3)] = int64(-257) },
		func(m map[any]any) { m[uint64(3)] = uint64(4294967288) },
		func(m map[any]any) { m[int64(-1)] = uint64(4) },
		func(m map[any]any) { m[int64(-1)] = uint64(7) },
		func(m map[any]any) { m[int64(-2)] = make([]byte, 31) },
		func(m map[any]any) { m[int64(-2)] = make([]byte, 33) },
		func(m map[any]any) { m[int64(-2)] = "not bytes" },
		func(m map[any]any) { m[int64(-4)] = make([]byte, 32) },
		func(m map[any]any) { delete(m, uint64(3)) },
	} {
		m, _ := parseCBOR(ed25519COSE(t))
		mutate(m)
		if _, _, err := coseKey(m); err == nil {
			t.Fatal("malformed Ed25519 key accepted")
		}
	}
	// RFC 8032 §7.1 TEST 1: independently specified signature on an empty message.
	m, _ := parseCBOR(ed25519COSE(t))
	_, key, err := coseKey(m)
	sig, _ := hex.DecodeString("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
	if err != nil || !ed25519.Verify(key.(ed25519.PublicKey), nil, sig) {
		t.Fatal("RFC8032 oracle rejected", err)
	}
}

func TestEd25519AssertionVerifiesExactMessageAndCounterPolicy(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cose := append([]byte{0xa4, 1, 1, 3, 0x27, 0x20, 6, 0x21, 0x58, 32}, public...)
	before := Credential{Algorithm: -8, PublicKey: cose, Version: 1, Counter: 2, BackupEligible: true}
	r := CeremonyRecord{Intent: CeremonyIntent{RPID: "example.com", Algorithms: []Algorithm{EdDSA}}}
	client := []byte(`{"type":"webauthn.get", "exact":"received bytes"}`)
	rp := sha256.Sum256([]byte("example.com"))
	auth := append(bytes.Clone(rp[:]), 0x1d, 0, 0, 0, 1)
	hash := sha256.Sum256(client)
	signed := append(bytes.Clone(auth), hash[:]...)
	b := browserResponse{}
	b.Response.AuthenticatorData = base64.RawURLEncoding.EncodeToString(auth)
	b.Response.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, signed))
	after, risk, err := assertionCredential(b, client, r, before)
	if err != nil || !risk || after.Counter != 2 || !after.BackupState || after.Version != 2 {
		t.Fatal("Ed25519 assertion/counter state lost", err)
	}
	for _, mutate := range []func(*browserResponse, *Credential, *CeremonyRecord){
		func(b *browserResponse, _ *Credential, _ *CeremonyRecord) {
			digest := sha256.Sum256(signed)
			b.Response.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, digest[:]))
		},
		func(b *browserResponse, _ *Credential, _ *CeremonyRecord) {
			b.Response.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
		},
		func(b *browserResponse, _ *Credential, _ *CeremonyRecord) {
			b.Response.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, 63))
		},
		func(b *browserResponse, _ *Credential, _ *CeremonyRecord) {
			b.Response.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, 65))
		},
		func(_ *browserResponse, c *Credential, _ *CeremonyRecord) { c.Algorithm = -7 },
		func(_ *browserResponse, _ *Credential, r *CeremonyRecord) { r.Intent.Algorithms = nil },
	} {
		bad, credential, ceremony := b, cloneCredential(before), cloneCeremony(r)
		mutate(&bad, &credential, &ceremony)
		if _, _, err := assertionCredential(bad, client, ceremony, credential); err == nil {
			t.Fatal("invalid Ed25519 assertion accepted")
		}
	}
	if _, _, err := assertionCredential(b, append(bytes.Clone(client), ' '), r, before); err == nil {
		t.Fatal("client bytes not bound")
	}
}

func TestEd25519RegistrationAuthenticatorKey(t *testing.T) {
	rp := sha256.Sum256([]byte("example.com"))
	auth := append(bytes.Clone(rp[:]), 0x45, 0, 0, 0, 0)
	auth = append(auth, make([]byte, 16)...)
	auth = binary.BigEndian.AppendUint16(auth, 1)
	auth = append(auth, 42)
	cose := ed25519COSE(t)
	auth = append(auth, cose...)
	parsed, err := parseAuthenticator(auth, "example.com", true)
	if err != nil || !bytes.Equal(parsed.key, cose) {
		t.Fatal("valid Ed25519 COSE registration key rejected", err)
	}
}
