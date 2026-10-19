//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	webauthn "github.com/faustbrian/go-webauthn"
	webauthnpg "github.com/faustbrian/go-webauthn/postgres"
)

func TestDiscoverablePopulatedMigrationPostgres(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	dsn := os.Getenv("WEBAUTHN_TEST_DSN")
	if dsn == "" {
		t.Fatal("WEBAUTHN_TEST_DSN requires an isolated empty task database")
	}
	pool, e := database.New(ctx, database.Config{DSN: dsn, MaxConns: 2})
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close(context.Background())
	history, e := (kernel.MigrationSource{}).Load(ctx)
	if e != nil {
		t.Fatal(e)
	}
	for _, m := range history {
		if _, e = pool.Raw().Exec(ctx, m.UpSQL()); e != nil {
			t.Fatal(e)
		}
	}
	history, e = (webauthnpg.MigrationSource{}).Load(ctx)
	if e != nil || len(history) != 2 {
		t.Fatal("forward migration history", e)
	}
	if _, e = pool.Raw().Exec(ctx, history[0].UpSQL()); e != nil {
		t.Fatal(e)
	}
	command, e := identity.NewCommandID()
	if e != nil {
		t.Fatal(e)
	}
	ceremony := webauthn.CeremonyRecord{Intent: webauthn.CeremonyIntent{Context: webauthn.CeremonyContext{CommandID: command, TenantID: "tenant-a", UserID: "user-a", ActorID: "actor-a", CorrelationID: "populated"}, Kind: "get", RPID: "example.com", RPVersion: 1, Origin: "https://example.com", UserHandle: bytes.Repeat([]byte{61}, 32), AllowedCredentials: [][]byte{[]byte("credential")}}, ID: string(command), ChallengeDigest: [32]byte{1}, ExpiresAt: time.Now().UTC().Truncate(time.Microsecond).Add(time.Minute), Version: 1}
	credential := webauthn.Credential{TenantID: "tenant-a", UserID: "user-a", RPID: "example.com", ID: []byte("credential"), UserHandle: ceremony.Intent.UserHandle, Algorithm: -7, Counter: 7, Version: 4}
	ceremonyWire, _ := json.Marshal(ceremony)
	credentialWire, _ := json.Marshal(credential)
	// Zero additive fields are absent, preserving historical record/command JSON.
	if bytes.Contains(ceremonyWire, []byte("AnonymousFlowID")) || bytes.Contains(ceremonyWire, []byte("ResidentKeyRequired")) {
		t.Fatal("identified encoding changed")
	}
	if _, e = pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('tenant-a','user-a','active',1);INSERT INTO webauthn.relying_parties(rp_id,tenant_id) VALUES('example.com','tenant-a')`); e != nil {
		t.Fatal(e)
	}
	if _, e = pool.Raw().Exec(ctx, `INSERT INTO webauthn.user_handles(rp_id,user_handle,tenant_id,user_id) VALUES('example.com',$1,'tenant-a','user-a')`, credential.UserHandle); e != nil {
		t.Fatal(e)
	}
	if _, e = pool.Raw().Exec(ctx, `INSERT INTO webauthn.credentials(rp_id,credential_id,tenant_id,user_id,user_handle,version,record) VALUES('example.com',$1,'tenant-a','user-a',$2,4,$3::jsonb)`, credential.ID, credential.UserHandle, string(credentialWire)); e != nil {
		t.Fatal(e)
	}
	if _, e = pool.Raw().Exec(ctx, `INSERT INTO webauthn.ceremonies(ceremony_id,rp_id,tenant_id,user_id,kind,challenge_digest,expires_at,version,record) VALUES($1,'example.com','tenant-a','user-a','get',$2,$3,1,$4::jsonb)`, string(command), ceremony.ChallengeDigest[:], ceremony.ExpiresAt, string(ceremonyWire)); e != nil {
		t.Fatal(e)
	}
	if _, e = pool.Raw().Exec(ctx, `INSERT INTO webauthn.effects(command_id,tenant_id,user_id,actor_id,purpose,record_id,fingerprint,ceremony_id,ceremony,before_credential,after_credential) VALUES($1,'tenant-a','user-a','actor-a','webauthn.assert','credential',$2,$1,$3::jsonb,$4::jsonb,$4::jsonb)`, string(command), ceremony.ChallengeDigest[:], string(ceremonyWire), string(credentialWire)); e != nil {
		t.Fatal(e)
	}
	var before string
	if e = pool.Raw().QueryRow(ctx, `SELECT row_to_json(c)::text FROM webauthn.credentials c`).Scan(&before); e != nil {
		t.Fatal(e)
	}
	if _, e = pool.Raw().Exec(ctx, history[1].UpSQL()); e != nil {
		t.Fatal("populated forward migration", e)
	}
	var after string
	var identifiedCeremonies, identifiedEffects int
	if e = pool.Raw().QueryRow(ctx, `SELECT row_to_json(c)::text FROM webauthn.credentials c`).Scan(&after); e != nil || after != before {
		t.Fatal("migration changed existing credential", e)
	}
	// These old-binary query shapes still address the same original subjects.
	if e = pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM webauthn.ceremonies WHERE user_id='user-a' AND anonymous_flow_id IS NULL),(SELECT count(*) FROM webauthn.effects WHERE user_id='user-a' AND anonymous_flow_id IS NULL)`).Scan(&identifiedCeremonies, &identifiedEffects); e != nil || identifiedCeremonies != 1 || identifiedEffects != 1 {
		t.Fatal("migration lost identified history", e)
	}
}
