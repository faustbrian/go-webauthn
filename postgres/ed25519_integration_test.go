//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"os"
	"slices"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	webauthn "github.com/faustbrian/go-webauthn"
	webauthnpg "github.com/faustbrian/go-webauthn/postgres"
	"github.com/jackc/pgx/v5"
)

func edRegistration(t *testing.T, public ed25519.PublicKey, id []byte, challenge string, flags byte) []byte {
	t.Helper()
	cose := append([]byte{0xa4, 1, 1, 3, 0x27, 0x20, 6, 0x21, 0x58, 32}, public...)
	return edRegistrationCOSE(t, cose, id, challenge, flags)
}

func edRegistrationCOSE(t *testing.T, cose, id []byte, challenge string, flags byte) []byte {
	t.Helper()
	auth := authData(flags|0x40, 0)
	auth = append(auth, make([]byte, 16)...)
	auth = binary.BigEndian.AppendUint16(auth, uint16(len(id)))
	auth = append(auth, id...)
	auth = append(auth, cose...)
	att := []byte{0xa3}
	att = append(att, cborText("fmt")...)
	att = append(att, cborText("none")...)
	att = append(att, cborText("attStmt")...)
	att = append(att, 0xa0)
	att = append(att, cborText("authData")...)
	att = append(att, cborBytes(auth)...)
	wire, err := json.Marshal(map[string]any{"id": b64(id), "rawId": b64(id), "type": "public-key", "response": map[string]string{"clientDataJSON": b64(clientJSON("create", challenge)), "attestationObject": b64(att)}})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func edAssertion(t *testing.T, key ed25519.PrivateKey, id, handle []byte, challenge string, flags byte, count uint32) []byte {
	t.Helper()
	client, auth := clientJSON("get", challenge), authData(flags, count)
	hash := sha256.Sum256(client)
	signed := append(bytes.Clone(auth), hash[:]...)
	wire, err := json.Marshal(map[string]any{"id": b64(id), "rawId": b64(id), "type": "public-key", "response": map[string]string{"clientDataJSON": b64(client), "authenticatorData": b64(auth), "signature": b64(ed25519.Sign(key, signed)), "userHandle": b64(handle)}})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestEd25519NativeIdentifiedAndDiscoverable(t *testing.T) {
	ctx, pool, coordinator, store := nativeFixture(t)
	key, _ := webauthn.NewChallengeDigestKey(bytes.Repeat([]byte{61}, 32))
	config := webauthn.Config{TenantID: "tenant-a", RelyingParty: webauthn.RelyingParty{ID: "example.com", Name: "Ed25519", Origins: []string{"https://login.example.com"}, Version: 1}, ChallengeKey: key, MaximumDuration: 10 * time.Second, Algorithms: []webauthn.Algorithm{webauthn.EdDSA, webauthn.ES256}}
	svc, err := webauthn.NewDiscoverable(config, webauthn.Dependencies{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	fresh := func(anonymous bool) webauthn.CeremonyContext {
		id, e := identity.NewCommandID()
		if e != nil {
			t.Fatal(e)
		}
		c := webauthn.CeremonyContext{CommandID: id, TenantID: "tenant-a", UserID: "user-a", ActorID: "actor-a", CorrelationID: "ed25519-test"}
		if anonymous {
			c.UserID = ""
			c.AnonymousFlowID = "ed25519-pre-auth"
		}
		return c
	}
	handle, id := bytes.Repeat([]byte{62}, 32), bytes.Repeat([]byte{63}, 32)
	t.Run("legacy ES256 authority is not broadened", func(t *testing.T) {
		legacyConfig := config
		legacyConfig.Algorithms = nil
		legacy, e := webauthn.New(legacyConfig, webauthn.Dependencies{Store: store})
		if e != nil {
			t.Fatal(e)
		}
		esKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		esID := bytes.Repeat([]byte{64}, 32)
		o, e := legacy.BeginRegistration(ctx, webauthn.BeginRegistrationRequest{Context: fresh(false), UserHandle: handle, Origin: config.RelyingParty.Origins[0]})
		if e != nil {
			t.Fatal(e)
		}
		r, _ := o.Ceremony()
		challenge := optionChallenge(t, ctx, o.TransferJSON)
		request := webauthn.VerifyRegistrationRequest{Context: fresh(false), CeremonyID: r.ID, Origin: r.Intent.Origin, ExpectedVersion: 1, Response: registrationResponse(t, esKey, esID, challenge, 0x45, 0)}
		if _, e := svc.VerifyRegistration(ctx, request); e == nil {
			t.Fatal("expanded profile reinterpreted legacy ceremony")
		}
		// The original service can still complete the untouched legacy row.
		v, e := legacy.VerifyRegistration(ctx, request)
		if e != nil {
			t.Fatal("legacy registration", e)
		}
		c, ok := v.Credential()
		if !ok || c.Algorithm != -7 {
			t.Fatal("legacy ES256 changed")
		}
		a, e := legacy.BeginAssertion(ctx, webauthn.BeginAssertionRequest{Context: fresh(false), UserHandle: handle, Origin: r.Intent.Origin, AllowedCredentials: [][]byte{esID}})
		if e != nil {
			t.Fatal(e)
		}
		ar, _ := a.Ceremony()
		ac := optionChallenge(t, ctx, a.TransferJSON)
		if _, e := legacy.VerifyAssertion(ctx, webauthn.VerifyAssertionRequest{Context: fresh(false), CeremonyID: ar.ID, Origin: r.Intent.Origin, ExpectedVersion: 1, ExpectedCredentialVersion: 1, Response: assertionResponse(t, esKey, esID, handle, ac, 5, 1)}); e != nil {
			t.Fatal("legacy assertion", e)
		}
	})
	t.Run("valid unselected registration key leaves ceremony usable", func(t *testing.T) {
		selected := config
		selected.Algorithms = []webauthn.Algorithm{webauthn.EdDSA}
		strict, e := webauthn.New(selected, webauthn.Dependencies{Store: store})
		if e != nil {
			t.Fatal(e)
		}
		o, e := strict.BeginRegistration(ctx, webauthn.BeginRegistrationRequest{Context: fresh(false), UserHandle: handle, Origin: selected.RelyingParty.Origins[0]})
		if e != nil {
			t.Fatal(e)
		}
		r, _ := o.Ceremony()
		challenge := optionChallenge(t, ctx, o.TransferJSON)
		candidateID := bytes.Repeat([]byte{69}, 32)
		esKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		request := webauthn.VerifyRegistrationRequest{Context: fresh(false), CeremonyID: r.ID, Origin: r.Intent.Origin, ExpectedVersion: 1, Response: registrationResponse(t, esKey, candidateID, challenge, 0x45, 0)}
		if _, e := strict.VerifyRegistration(ctx, request); e == nil {
			t.Fatal("structurally valid but unselected ES256 key accepted")
		}
		var unconsumed bool
		var count int
		if e := pool.Raw().QueryRow(ctx, `SELECT consumed_by IS NULL FROM webauthn.ceremonies WHERE ceremony_id=$1`, r.ID).Scan(&unconsumed); e != nil || !unconsumed {
			t.Fatal("unselected algorithm consumed ceremony", e)
		}
		if e := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM webauthn.credentials WHERE rp_id='example.com' AND credential_id=$1`, candidateID).Scan(&count); e != nil || count != 0 {
			t.Fatal("unselected algorithm persisted credential", e)
		}
		public, _, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		request.Response = edRegistration(t, public, candidateID, challenge, 0x45)
		verified, e := strict.VerifyRegistration(ctx, request)
		if e != nil {
			t.Fatal("selected key could not complete original ceremony", e)
		}
		credential, ok := verified.Credential()
		if !ok || credential.Algorithm != int32(webauthn.EdDSA) {
			t.Fatal("selected registration result missing")
		}
	})
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	options, err := svc.BeginRegistration(ctx, webauthn.BeginRegistrationRequest{Context: fresh(false), UserHandle: handle, Origin: config.RelyingParty.Origins[0], ResidentKeyRequired: true})
	if err != nil {
		t.Fatal(err)
	}
	ceremony, _ := options.Ceremony()
	challenge := optionChallenge(t, ctx, options.TransferJSON)
	request := webauthn.VerifyRegistrationRequest{Context: fresh(false), CeremonyID: ceremony.ID, Origin: ceremony.Intent.Origin, Response: edRegistration(t, public, id, challenge, 0x0d), ExpectedVersion: 1}
	assertUntouched := func(ceremony string, version uint64) {
		t.Helper()
		var unconsumed bool
		if e := pool.Raw().QueryRow(ctx, `SELECT consumed_by IS NULL FROM webauthn.ceremonies WHERE ceremony_id=$1`, ceremony).Scan(&unconsumed); e != nil || !unconsumed {
			t.Fatal("denial/rollback consumed challenge", e)
		}
		if version != 0 {
			var actual uint64
			if e := pool.Raw().QueryRow(ctx, `SELECT version FROM webauthn.credentials WHERE rp_id='example.com' AND credential_id=$1`, id).Scan(&actual); e != nil || actual != version {
				t.Fatal("denial/rollback changed credential", e)
			}
		}
	}
	for _, selection := range [][]webauthn.Algorithm{nil, {webauthn.ES256}, {webauthn.EdDSA}, {webauthn.ES256, webauthn.EdDSA}} {
		changed := config
		changed.Algorithms = selection
		other, e := webauthn.New(changed, webauthn.Dependencies{Store: store})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = other.VerifyRegistration(ctx, request); e == nil {
			t.Fatal("changed policy reinterpreted original ceremony")
		}
		assertUntouched(ceremony.ID, 0)
	}
	// The exact explicit policy survives durable round-trip, and caller-owned
	// option snapshots cannot retarget it.
	if !slices.Equal(ceremony.Intent.Algorithms, config.Algorithms) {
		t.Fatal("algorithm policy not persisted")
	}
	ceremony.Intent.Algorithms[0] = webauthn.ES256
	for _, invalid := range []struct {
		name string
		key  []byte
	}{
		{"wrong-kty", append([]byte{0xa4, 1, 2, 3, 0x27, 0x20, 6, 0x21, 0x58, 32}, public...)},
		{"wrong-alg", append([]byte{0xa4, 1, 1, 3, 0x26, 0x20, 6, 0x21, 0x58, 32}, public...)},
		{"wrong-curve", append([]byte{0xa4, 1, 1, 3, 0x27, 0x20, 7, 0x21, 0x58, 32}, public...)},
		{"short-key", append([]byte{0xa4, 1, 1, 3, 0x27, 0x20, 6, 0x21, 0x58, 31}, public[:31]...)},
		{"long-key", append(append([]byte{0xa4, 1, 1, 3, 0x27, 0x20, 6, 0x21, 0x58, 33}, public...), 0)},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			bad := request
			bad.Response = edRegistrationCOSE(t, invalid.key, id, challenge, 0x0d)
			if _, e := svc.VerifyRegistration(ctx, bad); e == nil {
				t.Fatal("malformed COSE registered")
			}
			assertUntouched(request.CeremonyID, 0)
		})
	}
	registration, err := svc.VerifyRegistration(ctx, request)
	if err != nil {
		t.Fatal("Ed25519 registration", err)
	}
	credential, ok := registration.Credential()
	if !ok || credential.Algorithm != -8 || !bytes.Equal(credential.PublicKey[10:], public) {
		t.Fatal("Ed25519 durable credential bytes/algorithm lost")
	}
	var replay webauthn.Replay
	if v, e := svc.VerifyRegistration(ctx, request); !errors.As(e, &replay) {
		t.Fatal("registration replay", e)
	} else if _, ok := v.Credential(); ok {
		t.Fatal("replay renewed verification")
	}
	for _, anonymous := range []bool{false, true} {
		name := "identified"
		if anonymous {
			name = "discoverable"
		}
		t.Run(name, func(t *testing.T) {
			for _, scenario := range []string{"foreign-tenant", "foreign-user-or-flow", "stale-version", "bad-signature", "withdrawn", "rollback", "success", "unknown-committed"} {
				t.Run(scenario, func(t *testing.T) {
					var record webauthn.CeremonyRecord
					var challenge string
					if anonymous {
						o, e := svc.BeginDiscoverableAssertion(ctx, webauthn.BeginDiscoverableAssertionRequest{Context: fresh(true), Origin: request.Origin})
						if e != nil {
							t.Fatal(e)
						}
						record, _ = o.Ceremony()
						challenge = optionChallenge(t, ctx, o.TransferJSON)
					} else {
						o, e := svc.BeginAssertion(ctx, webauthn.BeginAssertionRequest{Context: fresh(false), UserHandle: handle, Origin: request.Origin, AllowedCredentials: [][]byte{id}})
						if e != nil {
							t.Fatal(e)
						}
						record, _ = o.Ceremony()
						challenge = optionChallenge(t, ctx, o.TransferJSON)
					}
					c := fresh(anonymous)
					wire := edAssertion(t, private, id, handle, challenge, 0x1d, credential.Counter+1)
					expectedCredentialVersion := credential.Version
					version := uint64(1)
					switch scenario {
					case "foreign-tenant":
						c.TenantID = "tenant-b"
					case "foreign-user-or-flow":
						if anonymous {
							c.AnonymousFlowID = "other-flow"
						} else {
							c.UserID = "user-b"
						}
					case "stale-version":
						version = 2
					case "bad-signature":
						wire = mutateClient(t, wire, func(m map[string]any) { m["signed-bytes"] = "changed" })
					case "withdrawn":
						if _, e := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='suspended' WHERE user_id='user-a'`); e != nil {
							t.Fatal(e)
						}
					case "rollback":
						if _, e := pool.Raw().Exec(ctx, `CREATE FUNCTION public.ed25519_rollback() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Ed25519 rollback'; END $$; CREATE CONSTRAINT TRIGGER ed25519_rollback AFTER INSERT ON webauthn.effects DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.ed25519_rollback();`); e != nil {
							t.Fatal(e)
						}
					}
					service := svc
					var cut *commitCut
					if scenario == "unknown-committed" {
						cut = &commitCut{}
						cutPool, e := database.New(ctx, database.Config{DSN: os.Getenv("WEBAUTHN_TEST_DSN"), MaxConns: 2, SessionInit: func(ctx context.Context, connection *pgx.Conn) error {
							_, e := connection.Exec(ctx, `SET search_path=public`)
							return e
						}, Configure: func(c *database.PoolConfig) error {
							dial := c.ConnConfig.DialFunc
							c.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
								connection, e := dial(ctx, network, address)
								if e != nil {
									return nil, e
								}
								return &commitCutConn{Conn: connection, cut: cut}, nil
							}
							return nil
						}})
						if e != nil {
							t.Fatal(e)
						}
						defer cutPool.Close(context.Background())
						cutStore, e := webauthnpg.New(cutPool, webauthnpg.Config{Coordinator: coordinator, PolicyID: "webauthn-test", PolicyVersion: 1})
						if e != nil {
							t.Fatal(e)
						}
						service, e = webauthn.NewDiscoverable(config, webauthn.Dependencies{Store: cutStore})
						if e != nil {
							t.Fatal(e)
						}
						cut.remaining.Store(2)
					}
					verify := func(s webauthn.DiscoverableService) (webauthn.VerifiedAssertion, error) {
						if anonymous {
							return s.VerifyDiscoverableAssertion(ctx, webauthn.VerifyDiscoverableAssertionRequest{Context: c, CeremonyID: record.ID, Origin: request.Origin, Response: wire, ExpectedVersion: version})
						}
						return s.VerifyAssertion(ctx, webauthn.VerifyAssertionRequest{Context: c, CeremonyID: record.ID, Origin: request.Origin, Response: wire, ExpectedVersion: version, ExpectedCredentialVersion: expectedCredentialVersion})
					}
					result, e := verify(service)
					if scenario == "withdrawn" {
						if _, restore := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='active' WHERE user_id='user-a'`); restore != nil {
							t.Fatal(restore)
						}
					}
					if scenario == "rollback" {
						if _, drop := pool.Raw().Exec(ctx, `DROP TRIGGER ed25519_rollback ON webauthn.effects; DROP FUNCTION public.ed25519_rollback();`); drop != nil {
							t.Fatal(drop)
						}
					}
					if scenario != "success" && scenario != "unknown-committed" {
						if e == nil {
							t.Fatal("invalid assertion authenticated")
						}
						if _, ok := result.Credential(); ok {
							t.Fatal("denial returned verification")
						}
						assertUntouched(record.ID, credential.Version)
						return
					}
					if scenario == "unknown-committed" {
						var unknown webauthn.UnknownCommit
						if !errors.As(e, &unknown) || unknown.CommandID != c.CommandID || !cut.cut.Load() {
							t.Fatal("lost actual commit acknowledgement not classified", e)
						}
						if _, ok := result.Credential(); ok {
							t.Fatal("unknown outcome authenticated")
						}
						op := webauthn.AssertionOperation
						if anonymous {
							op = webauthn.DiscoverableAssertionOperation
						}
						if outcome, e := svc.Recover(ctx, webauthn.RecoveryRequest{Context: c, Operation: op, CredentialID: id}); e != nil || outcome != identity.CommitOutcomeCommitted {
							t.Fatal("original Ed25519 command not recovered", e)
						}
					} else {
						if e != nil {
							t.Fatal("Ed25519 assertion", e)
						}
						verified, ok := result.Credential()
						if !ok || verified.Algorithm != -8 || verified.Version != expectedCredentialVersion+1 || verified.Counter != credential.Counter+1 || !bytes.Equal(verified.ID, id) || !bytes.Equal(verified.UserHandle, handle) || verified.UserID != "user-a" || verified.TenantID != "tenant-a" {
							t.Fatal("finalized Ed25519 result did not identify the original credential/subject")
						}
					}
					stored, e := store.LoadCredential(ctx, webauthn.Lookup{Context: fresh(false), RPID: "example.com", CeremonyID: record.ID}, id)
					if e != nil || stored.Version != credential.Version+1 || stored.Counter != credential.Counter+1 || !stored.BackupState || stored.Algorithm != -8 || !bytes.Equal(stored.PublicKey, credential.PublicKey) {
						t.Fatal("atomic Ed25519 credential update lost", e)
					}
					credential = stored
					if v, e := verify(svc); !errors.As(e, &replay) {
						t.Fatal("assertion replay did not deny", e)
					} else if _, ok := v.Credential(); ok {
						t.Fatal("replay authenticated")
					}
				})
			}
		})
	}
}
