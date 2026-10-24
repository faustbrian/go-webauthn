package postgres

import (
	"testing"

	webauthn "github.com/faustbrian/go-webauthn"
)

func TestParticipantAlgorithmProfiles(t *testing.T) {
	for _, tc := range []struct {
		name     string
		selected []webauthn.Algorithm
		want     bool
	}{
		{"default", nil, true},
		{"empty", []webauthn.Algorithm{}, false},
		{"ES256", []webauthn.Algorithm{webauthn.ES256}, true},
		{"Ed25519", []webauthn.Algorithm{webauthn.EdDSA}, true},
		{"mixed-ES256-first", []webauthn.Algorithm{webauthn.ES256, webauthn.EdDSA}, true},
		{"mixed-Ed25519-first", []webauthn.Algorithm{webauthn.EdDSA, webauthn.ES256}, true},
		{"RS256", []webauthn.Algorithm{-257}, false},
		{"mixed-RS256", []webauthn.Algorithm{webauthn.ES256, -257}, false},
		{"unknown", []webauthn.Algorithm{-999}, false},
		{"duplicate-ES256", []webauthn.Algorithm{webauthn.ES256, webauthn.ES256}, false},
		{"duplicate-Ed25519", []webauthn.Algorithm{webauthn.EdDSA, webauthn.EdDSA}, false},
		{"mixed-duplicate", []webauthn.Algorithm{webauthn.ES256, webauthn.EdDSA, webauthn.ES256}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := registrationAlgorithms(tc.selected); got != tc.want {
				t.Fatalf("profile accepted=%v, want %v", got, tc.want)
			}
			for _, algorithm := range []webauthn.Algorithm{webauthn.ES256, webauthn.EdDSA, -257, -999} {
				want := tc.want && tc.selected == nil && algorithm == webauthn.ES256
				if tc.want {
					for _, selected := range tc.selected {
						want = want || selected == algorithm
					}
				}
				if got := registrationAlgorithm(int32(algorithm), tc.selected); got != want {
					t.Fatalf("algorithm %d selected=%v, want %v", algorithm, got, want)
				}
			}
		})
	}
}
