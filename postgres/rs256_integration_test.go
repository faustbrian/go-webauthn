//go:build integration

package postgres_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	webauthn "github.com/faustbrian/go-webauthn"
)

func rsaCOSEWire(key *rsa.PublicKey) []byte {
	wire := []byte{0xa4, 1, 3, 3, 0x39, 1, 0, 0x20, 0x59}
	wire = binary.BigEndian.AppendUint16(wire, uint16(len(key.N.Bytes())))
	wire = append(wire, key.N.Bytes()...)
	return append(wire, 0x21, 0x43, 1, 0, 1)
}

func rsaAssertionResponse(t *testing.T, key *rsa.PrivateKey, id, handle []byte, challenge string, flags byte, count uint32) []byte {
	t.Helper()
	client, auth := clientJSON("get", challenge), authData(flags, count)
	hash := sha256.Sum256(client)
	digest := sha256.Sum256(append(bytes.Clone(auth), hash[:]...))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(map[string]any{"id": b64(id), "rawId": b64(id), "type": "public-key", "response": map[string]string{"clientDataJSON": b64(client), "authenticatorData": b64(auth), "signature": b64(signature), "userHandle": b64(handle)}})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func rsaParticipantProfile() participantProfile {
	return participantProfile{algorithms: []webauthn.Algorithm{-257, webauthn.ES256, webauthn.EdDSA}, algorithm: -257}
}

func TestRS256RegistrationParticipationPostgres(t *testing.T) {
	testRegistrationParticipationPostgres(t, rsaParticipantProfile())
}

func TestRS256AssertionParticipationPostgres(t *testing.T) {
	testAssertionAlgorithmsPostgres(t, false, false, rsaParticipantProfile())
}

func TestRS256DiscoverableParticipationPostgres(t *testing.T) {
	testDiscoverableAssertionParticipationPostgres(t, rsaParticipantProfile())
}

func TestRS256NativeCounterBackupPolicy(t *testing.T) {
	ctx, pool, _, store := nativeFixture(t)
	key, _ := webauthn.NewChallengeDigestKey(bytes.Repeat([]byte{124}, 32))
	cfg := webauthn.Config{TenantID: "tenant-a", RelyingParty: webauthn.RelyingParty{ID: "example.com", Name: "RSA counters", Origins: []string{"https://login.example.com"}, Version: 1}, ChallengeKey: key, MaximumDuration: 10 * time.Second, Algorithms: []webauthn.Algorithm{webauthn.RS256}}
	svc, err := webauthn.New(cfg, webauthn.Dependencies{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	fresh := func() webauthn.CeremonyContext {
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		return webauthn.CeremonyContext{CommandID: id, TenantID: "tenant-a", UserID: "user-a", ActorID: "user-a", CorrelationID: "rsa-counter"}
	}
	profile := rsaParticipantProfile()
	private := profile.key(t)
	handle := bytes.Repeat([]byte{125}, 32)
	for index, tc := range []struct {
		name                              string
		stored, received                  uint32
		registrationFlags, assertionFlags byte
		allowed, risk                     bool
	}{
		{"backup-zero", 2, 0, 0x4d, 0x1d, true, true},
		{"backup-equal", 2, 2, 0x4d, 0x0d, true, true},
		{"backup-decreasing", 2, 1, 0x4d, 0x1d, true, true},
		{"backup-increasing", 2, 3, 0x4d, 0x1d, true, false},
		{"nonbackup-zero-zero", 0, 0, 0x45, 0x05, true, false},
		{"nonbackup-increasing", 2, 3, 0x45, 0x05, true, false},
		{"nonbackup-zero", 2, 0, 0x45, 0x05, false, false},
		{"nonbackup-equal", 2, 2, 0x45, 0x05, false, false},
		{"nonbackup-decreasing", 2, 1, 0x45, 0x05, false, false},
		{"backup-eligibility-changed", 2, 3, 0x4d, 0x05, false, false},
		{"backup-state-without-eligibility", 2, 3, 0x45, 0x15, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := bytes.Repeat([]byte{byte(140 + index)}, 32)
			options, err := svc.BeginRegistration(ctx, webauthn.BeginRegistrationRequest{Context: fresh(), Origin: cfg.RelyingParty.Origins[0], UserHandle: handle})
			if err != nil {
				t.Fatal(err)
			}
			r, _ := options.Ceremony()
			challenge := optionChallenge(t, ctx, options.TransferJSON)
			registered, err := svc.VerifyRegistration(ctx, webauthn.VerifyRegistrationRequest{Context: fresh(), CeremonyID: r.ID, Origin: r.Intent.Origin, ExpectedVersion: 1, Response: profile.registration(t, private, id, challenge, tc.registrationFlags, tc.stored)})
			if err != nil {
				t.Fatal(err)
			}
			before, ok := registered.Credential()
			if !ok {
				t.Fatal("missing committed RSA registration")
			}
			assertion, err := svc.BeginAssertion(ctx, webauthn.BeginAssertionRequest{Context: fresh(), Origin: r.Intent.Origin, UserHandle: handle, AllowedCredentials: [][]byte{id}})
			if err != nil {
				t.Fatal(err)
			}
			a, _ := assertion.Ceremony()
			ch := optionChallenge(t, ctx, assertion.TransferJSON)
			verified, err := svc.VerifyAssertion(ctx, webauthn.VerifyAssertionRequest{Context: fresh(), CeremonyID: a.ID, Origin: a.Intent.Origin, ExpectedVersion: 1, ExpectedCredentialVersion: before.Version, Response: profile.assertion(t, private, id, handle, ch, tc.assertionFlags, tc.received)})
			if (err == nil) != tc.allowed {
				t.Fatal("wrong RSA counter admission", err)
			}
			if _, ok := verified.Credential(); ok != tc.allowed {
				t.Fatal("denial disclosed verification or success omitted it")
			}
			stored, loadErr := store.LoadCredential(ctx, webauthn.Lookup{Context: fresh(), RPID: "example.com"}, id)
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			var consumed bool
			if err := pool.Raw().QueryRow(ctx, `SELECT consumed_by IS NOT NULL FROM webauthn.ceremonies WHERE ceremony_id=$1`, a.ID).Scan(&consumed); err != nil || consumed != tc.allowed {
				t.Fatal("RSA counter denial/commit consumed wrong ceremony state", err)
			}
			if tc.allowed {
				if stored.Version != before.Version+1 || stored.Counter != max(tc.stored, tc.received) || stored.BackupState != (tc.assertionFlags&16 != 0) || verified.CounterRisk() != tc.risk {
					t.Fatal("RSA counter/backup transition not persisted atomically")
				}
			} else if stored.Version != before.Version || stored.Counter != before.Counter || stored.BackupState != before.BackupState {
				t.Fatal("denied RSA counter mutated credential")
			}
		})
	}
}
