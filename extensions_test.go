package webauthn

import (
	"context"
	"encoding/json"
	"testing"
)

// The serializer is the unit contract here; durable creation/finalization is
// separately exercised by the real PostgreSQL and browser consumers.
func TestCreationExtensionsAreNotAssertionRequests(t *testing.T) {
	for _, registration := range []bool{true, false} {
		t.Run(map[bool]string{true: "creation", false: "assertion"}[registration], func(t *testing.T) {
			s := &challengeState{bytes: make([]byte, 32)}
			o := optionsState{record: CeremonyRecord{Intent: CeremonyIntent{RPID: "example.com", UserHandle: make([]byte, 32), Extensions: ExtensionRequestSet{CredentialProperties: true, CredentialProtection: 3, EnforceCredentialProtection: true}}}, challenge: Challenge{access: func() *challengeState { return s }}, rpName: "Example"}
			if e := o.transfer(context.Background(), func(_ context.Context, wire []byte) error {
				var options struct {
					PublicKey struct {
						Extensions map[string]any `json:"extensions"`
					} `json:"publicKey"`
				}
				if e := json.Unmarshal(wire, &options); e != nil {
					return e
				}
				ext := options.PublicKey.Extensions
				if !registration && len(ext) != 0 {
					t.Error("assertion advertises registration-only extensions")
				}
				if registration && (len(ext) != 3 || ext["credProps"] != true || ext["credentialProtectionPolicy"] != "userVerificationRequired" || ext["enforceCredentialProtectionPolicy"] != true) {
					t.Error("creation lost enforced selected extension policy")
				}
				return nil
			}, registration); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestAssertionCannotUpgradeRegistrationExtensionAuthority(t *testing.T) {
	selected := ExtensionRequestSet{CredentialProperties: true, CredentialProtection: 3, EnforceCredentialProtection: true}
	for _, value := range []any{uint64(3), "invalid-for-selected-registration"} {
		out, e := selectedExtensions(selected, map[any]any{"credProtect": value}, map[string]json.RawMessage{"credProps": json.RawMessage(`{"rk":true}`)}, false)
		if e != nil || out.CredentialProtection != nil || out.CredentialProperties != nil {
			t.Fatal("unsolicited assertion extension became fresh authority", e)
		}
	}
}
