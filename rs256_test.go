package webauthn

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"
	"time"
)

// Public RSA modulus from RFC 7515 Appendix A.2.1. No private material is kept.
const rfc7515Modulus = "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"

func rsaCOSE(public *rsa.PublicKey) []byte {
	// COSE RSA: kty=3, alg=-257, n=-1, e=-2; definite-length byte strings.
	wire := []byte{0xa4, 1, 3, 3, 0x39, 1, 0, 0x20, 0x59}
	wire = binary.BigEndian.AppendUint16(wire, uint16(len(public.N.Bytes())))
	wire = append(wire, public.N.Bytes()...)
	return append(wire, 0x21, 0x43, 1, 0, 1)
}

func TestRS256ConfigurationAndOptions(t *testing.T) {
	key, _ := NewChallengeDigestKey(bytes.Repeat([]byte{4}, 32))
	cfg := Config{TenantID: "tenant", RelyingParty: RelyingParty{ID: "example.com", Name: "RSA", Origins: []string{"https://example.com"}, Version: 1}, ChallengeKey: key, MaximumDuration: time.Second}
	for _, selected := range [][]Algorithm{{-257}, {-7, -8, -257}, {-257, -8, -7}} {
		cfg.Algorithms = selected
		service, err := New(cfg, Dependencies{Store: struct{ Store }{}})
		if err != nil || service == nil {
			t.Fatalf("required explicit RS256 selection rejected: %v", err)
		}
		creation := CeremonyCreation{access: func() *creationState {
			return &creationState{intent: CeremonyIntent{RPID: "example.com", Algorithms: selected}, key: [32]byte{1}}
		}}
		record, challenge, err := creation.Generate(context.Background(), time.Unix(1700000000, 0))
		if err != nil {
			t.Fatal(err)
		}
		options := RegistrationOptions{state: &optionsState{record: record, challenge: challenge}}
		if err := options.TransferJSON(context.Background(), func(_ context.Context, wire []byte) error {
			var got struct {
				PublicKey struct {
					Params []struct {
						Algorithm Algorithm `json:"alg"`
					} `json:"pubKeyCredParams"`
				} `json:"publicKey"`
			}
			if json.Unmarshal(wire, &got) != nil || len(got.PublicKey.Params) != len(selected) {
				t.Fatal("RS256 options lost selected algorithms")
			}
			for i, p := range got.PublicKey.Params {
				if p.Algorithm != selected[i] {
					t.Fatal("RS256 options changed policy order")
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRS256OfficialCOSEPublicKey(t *testing.T) {
	n, err := base64.RawURLEncoding.DecodeString(rfc7515Modulus)
	if err != nil {
		t.Fatal(err)
	}
	wire := rsaCOSE(&rsa.PublicKey{N: new(big.Int).SetBytes(n), E: 65537})
	m, err := parseCBOR(wire)
	if err != nil {
		t.Fatal(err)
	}
	alg, public, err := coseKey(m)
	if err != nil {
		t.Fatalf("RFC7515 public key rejected: %v", err)
	}
	rsaPublic, ok := public.(*rsa.PublicKey)
	if alg != -257 || !ok || rsaPublic.E != 65537 || !bytes.Equal(rsaPublic.N.Bytes(), n) {
		t.Fatal("RSA public key changed")
	}
	for name, mutate := range map[string]func(map[any]any){
		"wrong-kty":         func(m map[any]any) { m[uint64(1)] = uint64(2) },
		"wrong-alg":         func(m map[any]any) { m[uint64(3)] = int64(-37) },
		"short-modulus":     func(m map[any]any) { m[int64(-1)] = n[1:] },
		"2047-bits":         func(m map[any]any) { v := bytes.Clone(n); v[0] = 0x7f; m[int64(-1)] = v },
		"oversized-modulus": func(m map[any]any) { m[int64(-1)] = bytes.Repeat([]byte{255}, 1025) },
		"leading-zero":      func(m map[any]any) { m[int64(-1)] = append([]byte{0}, n...) },
		"even-modulus":      func(m map[any]any) { v := bytes.Clone(n); v[len(v)-1] &^= 1; m[int64(-1)] = v },
		"wrong-exponent":    func(m map[any]any) { m[int64(-2)] = []byte{3} },
		"integer-exponent":  func(m map[any]any) { m[int64(-2)] = uint64(65537) },
		"private-member":    func(m map[any]any) { m[int64(-3)] = []byte{1} },
		"missing-exponent":  func(m map[any]any) { delete(m, int64(-2)) },
	} {
		t.Run(name, func(t *testing.T) {
			copy, _ := parseCBOR(wire)
			mutate(copy)
			if _, _, err := coseKey(copy); err == nil {
				t.Fatal("invalid RSA profile accepted")
			}
		})
	}
	// The public-key parser accepts the selected upper bound before any
	// signature work; an extra octet above it is rejected by the cases above.
	upper, _ := parseCBOR(rsaCOSE(&rsa.PublicKey{N: new(big.Int).SetBytes(bytes.Repeat([]byte{255}, 1024)), E: 65537}))
	if _, _, err := coseKey(upper); err != nil {
		t.Fatal("8192-bit public-key bound rejected", err)
	}
}

func TestRS256AssertionExactBytesAndCounterPolicy(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	before := Credential{Algorithm: -257, PublicKey: rsaCOSE(&private.PublicKey), Version: 1, Counter: 2, BackupEligible: true}
	ceremony := CeremonyRecord{Intent: CeremonyIntent{RPID: "example.com", Algorithms: []Algorithm{-257}}}
	client := []byte(`{"type":"webauthn.get", "exact":"received bytes"}`)
	rp := sha256.Sum256([]byte("example.com"))
	auth := append(bytes.Clone(rp[:]), 0x1d, 0, 0, 0, 1)
	hash := sha256.Sum256(client)
	signed := append(bytes.Clone(auth), hash[:]...)
	digest := sha256.Sum256(signed)
	signature, err := rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	b := browserResponse{}
	b.Response.AuthenticatorData = base64.RawURLEncoding.EncodeToString(auth)
	b.Response.Signature = base64.RawURLEncoding.EncodeToString(signature)
	after, risk, err := assertionCredential(b, client, ceremony, before)
	if err != nil || !risk || after.Counter != 2 || !after.BackupState || after.Version != 2 {
		t.Fatalf("RS256 assertion/counter state rejected: %v", err)
	}
	for name, mutate := range map[string]func(*browserResponse, *Credential, *CeremonyRecord){
		"changed-signature": func(b *browserResponse, _ *Credential, _ *CeremonyRecord) {
			v := bytes.Clone(signature)
			v[0] ^= 1
			b.Response.Signature = base64.RawURLEncoding.EncodeToString(v)
		},
		"short-signature": func(b *browserResponse, _ *Credential, _ *CeremonyRecord) {
			b.Response.Signature = base64.RawURLEncoding.EncodeToString(signature[1:])
		},
		"long-signature": func(b *browserResponse, _ *Credential, _ *CeremonyRecord) {
			b.Response.Signature = base64.RawURLEncoding.EncodeToString(append(bytes.Clone(signature), 0))
		},
		"wrong-credential-algorithm": func(_ *browserResponse, c *Credential, _ *CeremonyRecord) { c.Algorithm = -7 },
		"wrong-rp":                   func(_ *browserResponse, _ *Credential, r *CeremonyRecord) { r.Intent.RPID = "other.example.com" },
		"wrong-key": func(_ *browserResponse, c *Credential, _ *CeremonyRecord) {
			n, _ := base64.RawURLEncoding.DecodeString(rfc7515Modulus)
			c.PublicKey = rsaCOSE(&rsa.PublicKey{N: new(big.Int).SetBytes(n), E: 65537})
		},
		"unselected": func(_ *browserResponse, _ *Credential, r *CeremonyRecord) { r.Intent.Algorithms = nil },
		"pss": func(b *browserResponse, _ *Credential, _ *CeremonyRecord) {
			signature, err := rsa.SignPSS(rand.Reader, private, crypto.SHA256, digest[:], nil)
			if err != nil {
				t.Fatal(err)
			}
			b.Response.Signature = base64.RawURLEncoding.EncodeToString(signature)
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad, c, r := b, cloneCredential(before), cloneCeremony(ceremony)
			mutate(&bad, &c, &r)
			if _, _, err := assertionCredential(bad, client, r, c); err == nil {
				t.Fatal("invalid RS256 assertion accepted")
			}
		})
	}
	if _, _, err := assertionCredential(b, append(bytes.Clone(client), ' '), ceremony, before); err == nil {
		t.Fatal("exact client bytes not signed")
	}
	before.BackupEligible = false
	if _, _, err := assertionCredential(b, client, ceremony, before); err == nil {
		t.Fatal("backup flags or nonbackup counter rollback accepted")
	}
}

func TestRS256IndependentOpenSSLAssertion(t *testing.T) {
	wire, err := os.ReadFile("testdata/rs256/openssl.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Modulus       string `json:"modulus_hex"`
		Exponent      int    `json:"exponent"`
		Client        string `json:"client_data"`
		Authenticator string `json:"authenticator_data_hex"`
		Signature     string `json:"signature_hex"`
	}
	if err := json.Unmarshal(wire, &fixture); err != nil {
		t.Fatal(err)
	}
	n, nerr := hex.DecodeString(fixture.Modulus)
	auth, aerr := hex.DecodeString(fixture.Authenticator)
	sig, serr := hex.DecodeString(fixture.Signature)
	if nerr != nil || aerr != nil || serr != nil || len(n) != 384 || fixture.Exponent != 65537 || len(sig) != 384 {
		t.Fatal("invalid independent fixture")
	}
	before := Credential{Algorithm: int32(RS256), PublicKey: rsaCOSE(&rsa.PublicKey{N: new(big.Int).SetBytes(n), E: fixture.Exponent}), Version: 1}
	r := CeremonyRecord{Intent: CeremonyIntent{RPID: "example.com", Algorithms: []Algorithm{RS256}}}
	b := browserResponse{}
	b.Response.AuthenticatorData = base64.RawURLEncoding.EncodeToString(auth)
	b.Response.Signature = base64.RawURLEncoding.EncodeToString(sig)
	after, risk, err := assertionCredential(b, []byte(fixture.Client), r, before)
	if err != nil || risk || after.Counter != 1 || after.Version != 2 {
		t.Fatal("independent OpenSSL WebAuthn-format signature rejected", err)
	}
	if _, _, err := assertionCredential(b, append([]byte(fixture.Client), ' '), r, before); err == nil {
		t.Fatal("independent signed bytes not preserved")
	}
}
