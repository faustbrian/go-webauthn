package webauthn

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestChallengeCustodySurvivesHostileEnclosingFormatting(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789ABCDEF")
	if len(secret) != 32 {
		t.Fatal("fixture length")
	}
	state := &challengeState{bytes: bytes.Clone(secret)}
	challenge := Challenge{access: func() *challengeState { return state }}
	key, e := NewChallengeDigestKey(secret)
	if e != nil {
		t.Fatal(e)
	}
	wrapped := struct {
		hidden Challenge
		key    ChallengeDigestKey
	}{challenge, key}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%f", "%p"} {
		text := fmt.Sprintf(verb, wrapped)
		for _, pattern := range []string{string(secret), hex.EncodeToString(secret), fmt.Sprint(secret)} {
			if strings.Contains(text, pattern) {
				t.Fatal("enclosing format disclosed secret")
			}
		}
	}
	var deliveries atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			_ = challenge.Transfer(context.Background(), func(_ context.Context, b []byte) error {
				deliveries.Add(1)
				if !bytes.Equal(b, secret) {
					t.Error("delivery bytes changed")
				}
				return nil
			})
		})
	}
	wg.Wait()
	if deliveries.Load() != 1 || state.bytes != nil {
		t.Fatal("copies did not share reveal-once custody")
	}
}

func TestPinnedPSLAndOriginScope(t *testing.T) {
	for _, tc := range []struct {
		rp, origin  string
		local, want bool
	}{
		{"example.com", "https://login.example.com", false, true},
		{"example.com", "https://notexample.com", false, false},
		{"co.uk", "https://login.co.uk", false, false},
		{"github.io", "https://mine.github.io", false, false},
		{"xn--55qx5d.cn", "https://a.xn--55qx5d.cn", false, false},
		{"example.com", "https://example.com/", false, false},
		{"example.com", "https://example.com:443", false, false},
		{"example.com", "https://example.com:", false, false},
		{"example.com", "https://example.com:8443", false, true},
		{"example.com", "https://example.com:0443", false, false},
		{"localhost", "http://localhost:8080", true, true},
		{"localhost", "http://localhost:8080", false, false},
		{"localhost", "http://127.0.0.1:8080", true, false},
		{"localhost", "http://localhost", true, false},
		{"localhost", "http://localhost:80", true, false},
	} {
		t.Run(tc.rp+tc.origin, func(t *testing.T) {
			if got := validOrigin(tc.origin, tc.rp, tc.local); got != tc.want {
				t.Fatalf("origin policy got %t want %t", got, tc.want)
			}
		})
	}
}

func FuzzBoundedCBOR(f *testing.F) {
	for _, seed := range [][]byte{{0xa0}, {0xa1, 0x61, 'x', 0x01}, {0xa2, 0x01, 0x01, 0x01, 0x02}, {0x9f, 0xff}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 64<<10 {
			return
		}
		_, _ = parseCBOR(b)
	})
}
func FuzzBoundedJSON(f *testing.F) {
	for _, seed := range []string{`{}`, `{"x":1,"x":2}`, `{"x":[[]]}`, `null`, `{"response":{"userHandle":null}}`, `{"response":{"userHandle":"AA","userHandle":"AQ"}}`, `{"response":{"userHandle":[]}}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, b string) {
		if len(b) > 16<<10 {
			return
		}
		_ = validateJSON([]byte(b), 16<<10)
	})
}
