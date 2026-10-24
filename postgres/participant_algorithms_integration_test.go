//go:build integration

package postgres_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"slices"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	webauthn "github.com/faustbrian/go-webauthn"
)

// Reuse the complete native participant acceptance suites with genuine browser
// responses, not assembled verifier transitions. Default tests retain ES256.
type participantProfile struct {
	algorithms []webauthn.Algorithm
	algorithm  webauthn.Algorithm
}

func edParticipantProfile() participantProfile {
	return participantProfile{algorithms: []webauthn.Algorithm{webauthn.EdDSA}, algorithm: webauthn.EdDSA}
}

func mixedParticipantProfile() participantProfile {
	return participantProfile{algorithms: []webauthn.Algorithm{webauthn.EdDSA, webauthn.ES256}, algorithm: webauthn.EdDSA}
}

func (p participantProfile) key(t *testing.T) crypto.Signer {
	t.Helper()
	if p.algorithm == webauthn.EdDSA {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func (participantProfile) registration(t *testing.T, key crypto.Signer, id []byte, challenge string, flags byte, count uint32) []byte {
	t.Helper()
	if ed, ok := key.(ed25519.PrivateKey); ok {
		public := ed.Public().(ed25519.PublicKey)
		cose := append([]byte{0xa4, 1, 1, 3, 0x27, 0x20, 6, 0x21, 0x58, 32}, public...)
		return edRegistrationCOSECounter(t, cose, id, challenge, flags, count)
	}
	return registrationResponse(t, key.(*ecdsa.PrivateKey), id, challenge, flags, count)
}

func (participantProfile) assertion(t *testing.T, key crypto.Signer, id, handle []byte, challenge string, flags byte, count uint32) []byte {
	t.Helper()
	if ed, ok := key.(ed25519.PrivateKey); ok {
		return edAssertion(t, ed, id, handle, challenge, flags, count)
	}
	return assertionResponse(t, key.(*ecdsa.PrivateKey), id, handle, challenge, flags, count)
}

func TestEd25519RegistrationParticipationPostgres(t *testing.T) {
	testRegistrationParticipationPostgres(t, edParticipantProfile())
}

func TestMixedSignupRegistrationParticipationPostgres(t *testing.T) {
	testSignupRegistrationParticipationPostgres(t, mixedParticipantProfile())
}

func TestMixedES256RegistrationParticipationPostgres(t *testing.T) {
	p := mixedParticipantProfile()
	p.algorithm = webauthn.ES256
	testRegistrationParticipationPostgres(t, p)
}

func TestEd25519AssertionParticipationPostgres(t *testing.T) {
	testAssertionAlgorithmsPostgres(t, false, false, edParticipantProfile())
}

func TestMixedPreauthAssertionParticipationPostgres(t *testing.T) {
	testAssertionAlgorithmsPostgres(t, true, false, mixedParticipantProfile())
}

func TestMixedUpdateAssertionParticipationPostgres(t *testing.T) {
	testAssertionAlgorithmsPostgres(t, false, true, mixedParticipantProfile())
}

func TestMixedDiscoverableAssertionParticipationPostgres(t *testing.T) {
	testDiscoverableAssertionParticipationPostgres(t, mixedParticipantProfile())
}

func TestMixedEnrollmentParticipationPostgres(t *testing.T) {
	testEnrollmentParticipationPostgres(t, mixedParticipantProfile())
}

func TestMixedRemovalAssertionParticipationPostgres(t *testing.T) {
	testRemovalAssertionParticipationPostgres(t, mixedParticipantProfile())
}

func TestMixedRemovalRemainingNativeProvenancePostgres(t *testing.T) {
	testRemovalRemainingNativeProvenancePostgres(t, mixedParticipantProfile())
}

func TestParticipantAlgorithmBindingPostgres(t *testing.T) {
	ctx, pool, config, native := nativeFixture(t)
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE participation_metadata(command_id text PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	store := &registrationStore{Store: native, pool: pool, config: config}
	key, _ := webauthn.NewChallengeDigestKey(bytes.Repeat([]byte{111}, 32))
	cfg := webauthn.Config{TenantID: "tenant-a", RelyingParty: webauthn.RelyingParty{ID: "example.com", Name: "Algorithm binding", Origins: []string{"https://login.example.com"}, Version: 1}, ChallengeKey: key, MaximumDuration: 10 * time.Second}
	fresh := func() webauthn.CeremonyContext {
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		return webauthn.CeremonyContext{CommandID: id, TenantID: "tenant-a", UserID: "user-a", ActorID: "user-a", CorrelationID: "algorithm-binding"}
	}
	for index, selected := range [][]webauthn.Algorithm{nil, {webauthn.ES256}, {webauthn.EdDSA}, {webauthn.EdDSA, webauthn.ES256}, {webauthn.ES256, webauthn.EdDSA}} {
		cfg.Algorithms = selected
		svc, err := webauthn.New(cfg, webauthn.Dependencies{Store: store})
		if err != nil {
			t.Fatal(err)
		}
		opts, err := svc.BeginRegistration(ctx, webauthn.BeginRegistrationRequest{Context: fresh(), UserHandle: bytes.Repeat([]byte{112}, 32), Origin: cfg.RelyingParty.Origins[0], ResidentKeyRequired: true})
		if err != nil {
			t.Fatal("selected profile creation", index, err)
		}
		r, _ := opts.Ceremony()
		if !slices.Equal(r.Intent.Algorithms, selected) || (r.Intent.Algorithms == nil) != (selected == nil) {
			t.Fatal("algorithm order/default representation changed")
		}
		challenge := optionChallenge(t, ctx, opts.TransferJSON)
		id := bytes.Repeat([]byte{byte(113 + index)}, 32)
		profile := participantProfile{algorithm: webauthn.ES256}
		if len(selected) > 0 {
			profile.algorithm = selected[0]
		}
		private := profile.key(t)
		request := webauthn.VerifyRegistrationRequest{Context: fresh(), CeremonyID: r.ID, Origin: r.Intent.Origin, ExpectedVersion: 1, Response: profile.registration(t, private, id, challenge, 0x45, 0)}
		// A valid different configured profile cannot reinterpret the original
		// ceremony, including a reordered mixed list or nil vs explicit ES256.
		changed := cfg
		switch {
		case selected == nil:
			changed.Algorithms = []webauthn.Algorithm{webauthn.ES256}
		case len(selected) == 1 && selected[0] == webauthn.ES256:
			changed.Algorithms = nil
		case len(selected) == 2 && selected[0] == webauthn.ES256:
			changed.Algorithms = []webauthn.Algorithm{webauthn.EdDSA, webauthn.ES256}
		default:
			changed.Algorithms = []webauthn.Algorithm{webauthn.ES256, webauthn.EdDSA}
		}
		other, err := webauthn.New(changed, webauthn.Dependencies{Store: store})
		if err != nil {
			t.Fatal(err)
		}
		if result, err := other.VerifyRegistration(ctx, request); err == nil {
			t.Fatal("changed algorithm profile accepted original ceremony")
		} else if _, ok := result.Credential(); ok {
			t.Fatal("profile mismatch exposed a verified credential")
		}
		if len(selected) < 2 {
			wrong := participantProfile{algorithm: webauthn.EdDSA}
			if profile.algorithm == webauthn.EdDSA {
				wrong.algorithm = webauthn.ES256
			}
			bad := request
			bad.Response = wrong.registration(t, wrong.key(t), id, challenge, 0x45, 0)
			if _, err := svc.VerifyRegistration(ctx, bad); err == nil {
				t.Fatal("valid but unselected key accepted")
			}
		}
		var consumed bool
		if err := pool.Raw().QueryRow(ctx, `SELECT consumed_by IS NOT NULL FROM webauthn.ceremonies WHERE ceremony_id=$1`, r.ID).Scan(&consumed); err != nil || consumed {
			t.Fatal("denied key/profile consumed the ceremony", err)
		}
		verified, err := svc.VerifyRegistration(ctx, request)
		if err != nil {
			t.Fatal("original selected profile did not remain usable", err)
		}
		credential, ok := verified.Credential()
		if !ok || credential.Algorithm != int32(profile.algorithm) {
			t.Fatal("selected algorithm changed during finalization")
		}
		loaded, err := native.LoadCredential(ctx, webauthn.Lookup{Context: fresh(), RPID: r.Intent.RPID}, id)
		if err != nil || loaded.Algorithm != credential.Algorithm || !bytes.Equal(loaded.PublicKey, credential.PublicKey) {
			t.Fatal("stored algorithm/key did not retain verifier identity", err)
		}
	}
}

func TestParticipantAssertionAlgorithmBindingPostgres(t *testing.T) {
	ctx, pool, config, native := nativeFixture(t)
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE participation_metadata(command_id text PRIMARY KEY); CREATE TABLE assertion_participation_metadata(command_id text PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	key, _ := webauthn.NewChallengeDigestKey(bytes.Repeat([]byte{121}, 32))
	cfg := webauthn.Config{TenantID: "tenant-a", RelyingParty: webauthn.RelyingParty{ID: "example.com", Name: "Assertion algorithm binding", Origins: []string{"https://login.example.com"}, Version: 1}, ChallengeKey: key, MaximumDuration: 10 * time.Second, Algorithms: []webauthn.Algorithm{webauthn.EdDSA, webauthn.ES256}}
	registration, err := webauthn.New(cfg, webauthn.Dependencies{Store: &registrationStore{Store: native, pool: pool, config: config}})
	if err != nil {
		t.Fatal(err)
	}
	fresh := func() webauthn.CeremonyContext {
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		return webauthn.CeremonyContext{CommandID: id, TenantID: "tenant-a", UserID: "user-a", ActorID: "user-a", CorrelationID: "assertion-algorithm-binding"}
	}
	handle := bytes.Repeat([]byte{122}, 32)
	keys := map[webauthn.Algorithm]crypto.Signer{}
	ids := map[webauthn.Algorithm][]byte{}
	profile := participantProfile{}
	for index, algorithm := range []webauthn.Algorithm{webauthn.ES256, webauthn.EdDSA} {
		profile.algorithm = algorithm
		keys[algorithm], ids[algorithm] = profile.key(t), bytes.Repeat([]byte{byte(123 + index)}, 32)
		o, err := registration.BeginRegistration(ctx, webauthn.BeginRegistrationRequest{Context: fresh(), UserHandle: handle, Origin: cfg.RelyingParty.Origins[0], ResidentKeyRequired: true})
		if err != nil {
			t.Fatal(err)
		}
		r, _ := o.Ceremony()
		challenge := optionChallenge(t, ctx, o.TransferJSON)
		if _, err := registration.VerifyRegistration(ctx, webauthn.VerifyRegistrationRequest{Context: fresh(), CeremonyID: r.ID, Origin: r.Intent.Origin, ExpectedVersion: 1, Response: profile.registration(t, keys[algorithm], ids[algorithm], challenge, 0x45, 0)}); err != nil {
			t.Fatal(err)
		}
	}
	store := &assertionStore{Store: native, pool: pool, config: config}
	for _, selected := range [][]webauthn.Algorithm{nil, {webauthn.ES256}, {webauthn.EdDSA}, {webauthn.EdDSA, webauthn.ES256}, {webauthn.ES256, webauthn.EdDSA}} {
		cfg.Algorithms = selected
		svc, err := webauthn.New(cfg, webauthn.Dependencies{Store: store})
		if err != nil {
			t.Fatal(err)
		}
		o, err := svc.BeginAssertion(ctx, webauthn.BeginAssertionRequest{Context: fresh(), UserHandle: handle, Origin: cfg.RelyingParty.Origins[0], AllowedCredentials: [][]byte{ids[webauthn.ES256], ids[webauthn.EdDSA]}})
		if err != nil {
			t.Fatal(err)
		}
		r, _ := o.Ceremony()
		challenge := optionChallenge(t, ctx, o.TransferJSON)
		algorithm := webauthn.ES256
		if len(selected) > 0 {
			algorithm = selected[0]
		}
		request := func(algorithm webauthn.Algorithm) webauthn.VerifyAssertionRequest {
			c, err := native.LoadCredential(ctx, webauthn.Lookup{Context: fresh(), RPID: r.Intent.RPID}, ids[algorithm])
			if err != nil {
				t.Fatal(err)
			}
			return webauthn.VerifyAssertionRequest{Context: fresh(), CeremonyID: r.ID, Origin: r.Intent.Origin, ExpectedVersion: 1, ExpectedCredentialVersion: c.Version, Response: profile.assertion(t, keys[algorithm], ids[algorithm], handle, challenge, 0x05, c.Counter+1)}
		}
		if len(selected) < 2 {
			wrong := webauthn.EdDSA
			if algorithm == webauthn.EdDSA {
				wrong = webauthn.ES256
			}
			if _, err := svc.VerifyAssertion(ctx, request(wrong)); err == nil {
				t.Fatal("valid signed but unselected assertion accepted")
			}
		}
		changed := cfg
		changed.Algorithms = []webauthn.Algorithm{webauthn.EdDSA, webauthn.ES256}
		if slices.Equal(selected, changed.Algorithms) {
			changed.Algorithms = []webauthn.Algorithm{webauthn.ES256, webauthn.EdDSA}
		}
		other, err := webauthn.New(changed, webauthn.Dependencies{Store: store})
		if err != nil {
			t.Fatal(err)
		}
		good := request(algorithm)
		if _, err := other.VerifyAssertion(ctx, good); err == nil {
			t.Fatal("changed profile accepted the original assertion ceremony")
		}
		var consumed bool
		if err := pool.Raw().QueryRow(ctx, `SELECT consumed_by IS NOT NULL FROM webauthn.ceremonies WHERE ceremony_id=$1`, r.ID).Scan(&consumed); err != nil || consumed {
			t.Fatal("unselected assertion/profile consumed original ceremony", err)
		}
		v, err := svc.VerifyAssertion(ctx, good)
		if err != nil {
			t.Fatal("original profile assertion did not remain usable", err)
		}
		c, ok := v.Credential()
		if !ok || c.Algorithm != int32(algorithm) {
			t.Fatal("assertion finalization changed algorithm")
		}
	}
}
