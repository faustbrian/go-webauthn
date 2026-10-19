package webauthn

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"math"
	"math/big"
)

type authenticatorData struct {
	flags      byte
	counter    uint32
	id, key    []byte
	aaguid     [16]byte
	extensions map[any]any
}

func parseAuthenticator(wire []byte, rpid string, registration bool) (authenticatorData, error) {
	var a authenticatorData
	if len(wire) < 37 || len(wire) > 4096 {
		return a, Invalid{Field: "authenticator_data"}
	}
	rp := sha256.Sum256([]byte(rpid))
	if !bytes.Equal(wire[:32], rp[:]) {
		return a, Denied{}
	}
	a.flags = wire[32]
	a.counter = binary.BigEndian.Uint32(wire[33:37])
	// WebAuthn CR20260526 §7.1/7.2: this selected profile requires both UP and
	// UV; reserved bits are zero, BE is immutable and BS without BE is invalid.
	if a.flags&0x05 != 0x05 || a.flags&0x22 != 0 || a.flags&0x10 != 0 && a.flags&0x08 == 0 {
		return a, Denied{}
	}
	offset := 37
	if registration {
		if a.flags&0x40 == 0 || len(wire) < 55 {
			return a, Invalid{Field: "attested_credential"}
		}
		copy(a.aaguid[:], wire[37:53])
		n := int(binary.BigEndian.Uint16(wire[53:55]))
		offset = 55
		if n == 0 || n > 1024 || n > len(wire)-offset {
			return a, Invalid{Field: "credential_id"}
		}
		a.id = bytes.Clone(wire[offset : offset+n])
		offset += n
		r := cborReader{wire: wire[offset:]}
		v, e := r.read(0)
		if e != nil {
			return a, e
		}
		key, ok := v.(map[any]any)
		if !ok {
			return a, Invalid{Field: "cose_key"}
		}
		if _, e = es256Key(key); e != nil {
			return a, e
		}
		a.key = bytes.Clone(wire[offset : offset+r.offset])
		offset += r.offset
	} else if a.flags&0x40 != 0 {
		return a, Invalid{Field: "unexpected_attested_data"}
	}
	if a.flags&0x80 != 0 {
		ext, e := parseCBOR(wire[offset:])
		if e != nil {
			return a, e
		}
		a.extensions = ext
		offset = len(wire)
	}
	if offset != len(wire) {
		return a, Invalid{Field: "authenticator_trailing"}
	}
	return a, nil
}
func es256Key(m map[any]any) (*ecdsa.PublicKey, error) {
	// COSE EC2 requires kty=2, alg=-7, crv=1 and exactly 32-byte coordinates.
	// Private-key members and alternate algorithms cannot cross this boundary.
	if len(m) != 5 {
		return nil, Invalid{Field: "cose_key"}
	}
	kty, k := cborInteger(m[uint64(1)])
	alg, a := cborInteger(m[uint64(3)])
	crv, c := cborInteger(m[int64(-1)])
	x, xok := m[int64(-2)].([]byte)
	y, yok := m[int64(-3)].([]byte)
	if !k || !a || !c || kty != 2 || alg != -7 || crv != 1 || !xok || !yok || len(x) != 32 || len(y) != 32 {
		return nil, Invalid{Field: "cose_key"}
	}
	X, Y := new(big.Int).SetBytes(x), new(big.Int).SetBytes(y)
	curve := elliptic.P256()
	if !curve.IsOnCurve(X, Y) {
		return nil, Invalid{Field: "cose_point"}
	}
	return &ecdsa.PublicKey{Curve: curve, X: X, Y: Y}, nil
}
func registrationCredential(att, id []byte, r CeremonyRecord, clientExt map[string]json.RawMessage) (Credential, error) {
	var c Credential
	m, e := parseCBOR(att)
	if e != nil {
		return c, e
	}
	if len(m) != 3 {
		return c, Invalid{Field: "attestation"}
	}
	fmt, ok := m["fmt"].(string)
	statement, sok := m["attStmt"].(map[any]any)
	auth, aok := m["authData"].([]byte)
	if !ok || !sok || !aok {
		return c, Invalid{Field: "attestation"}
	}
	// Only none is selected. packed/fido-u2f are not interpreted as trusted
	// merely because they can be structurally decoded (WebAuthn baseline).
	if fmt != "none" || len(statement) != 0 {
		return c, Denied{}
	}
	a, e := parseAuthenticator(auth, r.Intent.RPID, true)
	if e != nil {
		return c, e
	}
	if !bytes.Equal(a.id, id) {
		return c, Denied{}
	}
	ext, e := selectedExtensions(r.Intent.Extensions, a.extensions, clientExt, true)
	if e != nil {
		return c, e
	}
	c = Credential{TenantID: r.Intent.Context.TenantID, UserID: r.Intent.Context.UserID, RPID: r.Intent.RPID, ID: bytes.Clone(id), UserHandle: bytes.Clone(r.Intent.UserHandle), PublicKey: a.key, Algorithm: -7, AAGUID: a.aaguid, Counter: a.counter, BackupEligible: a.flags&8 != 0, BackupState: a.flags&16 != 0, Extensions: ext, Version: 1}
	return c, nil
}
func assertionCredential(b browserResponse, client []byte, r CeremonyRecord, before Credential) (Credential, bool, error) {
	if before.Version == 0 || before.Version == math.MaxUint64 {
		return Credential{}, false, Denied{}
	}
	if b.Response.UserHandle != nil {
		h, e := decodeBase64(*b.Response.UserHandle, 64)
		if e != nil || !bytes.Equal(h, before.UserHandle) {
			return Credential{}, false, Denied{}
		}
	}
	auth, e := decodeBase64(b.Response.AuthenticatorData, 4096)
	if e != nil {
		return Credential{}, false, e
	}
	a, e := parseAuthenticator(auth, r.Intent.RPID, false)
	if e != nil {
		return Credential{}, false, e
	}
	if (a.flags&8 != 0) != before.BackupEligible {
		return Credential{}, false, Denied{}
	}
	m, e := parseCBOR(before.PublicKey)
	if e != nil {
		return Credential{}, false, e
	}
	key, e := es256Key(m)
	if e != nil {
		return Credential{}, false, e
	}
	sig, e := decodeBase64(b.Response.Signature, 80)
	if e != nil {
		return Credential{}, false, e
	}
	// §7.2 hashes the exact received clientDataJSON bytes, never reserialization.
	clientHash := sha256.Sum256(client)
	signed := make([]byte, 0, len(auth)+32)
	signed = append(signed, auth...)
	signed = append(signed, clientHash[:]...)
	hash := sha256.Sum256(signed)
	if !ecdsa.VerifyASN1(key, hash[:], sig) {
		return Credential{}, false, Denied{}
	}
	risk := before.BackupEligible && a.counter <= before.Counter
	if !before.BackupEligible && before.Counter > 0 && a.counter <= before.Counter {
		return Credential{}, false, Denied{}
	}
	after := cloneCredential(before)
	after.Counter = max(before.Counter, a.counter)
	after.BackupState = a.flags&16 != 0
	after.Version++
	// cloneCredential retains enrollment metadata unchanged: credProps and
	// credProtect are creation-only (WebAuthn §10.4 / CTAP2.1 §12.1), never
	// refreshed from even signed unsolicited assertion extension output.
	return after, risk, nil
}
func selectedExtensions(selected ExtensionRequestSet, auth map[any]any, client map[string]json.RawMessage, registration bool) (ExtensionOutputSet, error) {
	var out ExtensionOutputSet
	// Both selected extensions are creation-only (WebAuthn CR20260526 §10.4,
	// FIDO CTAP2.1 §12.1). Even signed unsolicited assertion data must not
	// replace enrollment metadata or acquire fresh extension authority.
	if !registration {
		return out, nil
	}
	if selected.CredentialProperties {
		if raw, ok := client["credProps"]; ok {
			var v struct {
				RK *bool `json:"rk"`
			}
			if len(raw) > 256 || json.Unmarshal(raw, &v) != nil || v.RK == nil {
				return out, Invalid{Field: "credprops"}
			}
			out.CredentialProperties = &CredentialPropertiesOutput{ResidentKey: *v.RK, Authority: BrowserReported}
		}
	}
	if selected.CredentialProtection != 0 {
		if value, ok := auth["credProtect"]; ok {
			n, ok := cborInteger(value)
			if !ok || n < 1 || n > 3 {
				return out, Invalid{Field: "credprotect"}
			}
			if selected.EnforceCredentialProtection && n < int64(selected.CredentialProtection) {
				return out, Denied{}
			}
			out.CredentialProtection = &CredentialProtectionOutput{Policy: uint8(n), Authority: UnattestedAuthenticator}
		} else if selected.EnforceCredentialProtection {
			return out, Denied{}
		}
	}
	return out, nil
}
