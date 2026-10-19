package webauthn

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestResidentAndDiscoverableBrowserOptions(t *testing.T) {
	for _, resident := range []bool{false, true} {
		intent := CeremonyIntent{RPID: "example.com", UserHandle: bytes.Repeat([]byte{1}, 32), ResidentKeyRequired: resident}
		creation := CeremonyCreation{access: func() *creationState { return &creationState{intent: intent, key: [32]byte{1}} }}
		r, ch, e := creation.Generate(context.Background(), time.Now())
		if e != nil {
			t.Fatal(e)
		}
		options := RegistrationOptions{state: &optionsState{record: r, challenge: ch, rpName: "Example"}}
		e = options.TransferJSON(context.Background(), func(_ context.Context, wire []byte) error {
			var doc struct {
				PublicKey struct {
					AuthenticatorSelection struct {
						ResidentKey        string `json:"residentKey"`
						RequireResidentKey bool   `json:"requireResidentKey"`
						UserVerification   string `json:"userVerification"`
					} `json:"authenticatorSelection"`
				} `json:"publicKey"`
			}
			if json.Unmarshal(wire, &doc) != nil {
				t.Fatal("options JSON")
			}
			want := "discouraged"
			if resident {
				want = "required"
			}
			selection := doc.PublicKey.AuthenticatorSelection
			if selection.ResidentKey != want || selection.RequireResidentKey != resident || selection.UserVerification != "required" {
				t.Fatal("resident/UV policy lost")
			}
			return nil
		})
		if e != nil {
			t.Fatal(e)
		}
	}
	intent := CeremonyIntent{Kind: "get-discoverable", RPID: "example.com"}
	creation := CeremonyCreation{access: func() *creationState { return &creationState{intent: intent, key: [32]byte{1}} }}
	r, ch, e := creation.Generate(context.Background(), time.Now())
	if e != nil {
		t.Fatal(e)
	}
	options := AssertionOptions{state: &optionsState{record: r, challenge: ch}}
	if e = options.TransferJSON(context.Background(), func(_ context.Context, wire []byte) error {
		var doc struct {
			PublicKey map[string]json.RawMessage `json:"publicKey"`
		}
		if json.Unmarshal(wire, &doc) != nil {
			t.Fatal("options JSON")
		}
		if _, ok := doc.PublicKey["allowCredentials"]; ok {
			t.Fatal("usernameless options bound an allowlist")
		}
		if string(doc.PublicKey["userVerification"]) != `"required"` {
			t.Fatal("usernameless UV not required")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}

func TestAnonymousChallengeBindsPreAuthenticationFlow(t *testing.T) {
	r := CeremonyRecord{Intent: CeremonyIntent{Kind: "get-discoverable", RPID: "example.com"}, ID: "ceremony", ExpiresAt: time.Now()}
	r.Intent.Context.AnonymousFlowID = "flow-a"
	first := challengeDigest([32]byte{1}, r, bytes.Repeat([]byte{2}, 32))
	r.Intent.Context.AnonymousFlowID = "flow-b"
	second := challengeDigest([32]byte{1}, r, bytes.Repeat([]byte{2}, 32))
	if first == second {
		t.Fatal("pre-auth flow did not bind challenge")
	}
}
