// Package postgres supplies the real PostgreSQL participant for the selected
// WebAuthn ceremony profile. identity/postgres remains the sole coordinator.
package postgres

import (
	"context"

	migrations "github.com/faustbrian/go-migrations/v3"
	webauthn "github.com/faustbrian/go-webauthn"
)

// MigrationSource is this adapter's forward-only immutable history. Install the
// public identity kernel, audit and outbox histories first through their owners.
// Load performs no IO or mutation. The zero value is usable concurrently.
type MigrationSource struct{}

func (MigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil {
		return nil, webauthn.Invalid{Field: "migration_context"}
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	m, e := migrations.NewMigration(1, "webauthn_ceremonies", migrations.TransactionModeDefault, schemaSQL, "")
	if e != nil {
		return nil, webauthn.Unavailable{}
	}
	return []migrations.Migration{m}, nil
}

const schemaSQL = `CREATE SCHEMA webauthn;
CREATE TABLE webauthn.relying_parties (
 rp_id text COLLATE "C" PRIMARY KEY CHECK(octet_length(rp_id) BETWEEN 1 AND 253),
 tenant_id identity.directory_id NOT NULL
);
CREATE TABLE webauthn.user_handles (
 rp_id text COLLATE "C" NOT NULL REFERENCES webauthn.relying_parties(rp_id),
 user_handle bytea NOT NULL CHECK(octet_length(user_handle)=32),
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 PRIMARY KEY(rp_id,user_handle), UNIQUE(rp_id,tenant_id,user_id),
 FOREIGN KEY(tenant_id,user_id) REFERENCES identity.users(tenant_id,user_id)
);
CREATE TABLE webauthn.ceremonies (
 ceremony_id text COLLATE "C" PRIMARY KEY CHECK(octet_length(ceremony_id)=22),
 rp_id text COLLATE "C" NOT NULL REFERENCES webauthn.relying_parties(rp_id),
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 kind text COLLATE "C" NOT NULL CHECK(kind IN ('create','get')),
 challenge_digest bytea NOT NULL CHECK(octet_length(challenge_digest)=32),
 expires_at timestamptz NOT NULL,
 version identity.version NOT NULL CHECK(version=1),
 record jsonb NOT NULL CHECK(octet_length(record::text)<=262144),
 consumed_by text COLLATE "C",
 FOREIGN KEY(tenant_id,user_id) REFERENCES identity.users(tenant_id,user_id)
);
CREATE INDEX webauthn_expired_ceremonies ON webauthn.ceremonies(expires_at,ceremony_id) WHERE consumed_by IS NULL;
CREATE TABLE webauthn.credentials (
 rp_id text COLLATE "C" NOT NULL REFERENCES webauthn.relying_parties(rp_id),
 credential_id bytea NOT NULL CHECK(octet_length(credential_id) BETWEEN 1 AND 1024),
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 user_handle bytea NOT NULL CHECK(octet_length(user_handle)=32),
 version identity.version NOT NULL,
 record jsonb NOT NULL CHECK(octet_length(record::text)<=32768),
 PRIMARY KEY(rp_id,credential_id),
 FOREIGN KEY(rp_id,user_handle) REFERENCES webauthn.user_handles(rp_id,user_handle),
 FOREIGN KEY(tenant_id,user_id) REFERENCES identity.users(tenant_id,user_id)
);
CREATE INDEX webauthn_subject_credentials ON webauthn.credentials(tenant_id,user_id,rp_id);
-- Native evidence is not another command authority. It is written only inside
-- the shared coordinator transaction and never terminalizes its command ledger.
-- No raw challenge, clientDataJSON, attestation object or assertion is retained.
CREATE TABLE webauthn.effects (
 command_id text COLLATE "C" PRIMARY KEY CHECK(octet_length(command_id)=22),
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 actor_id identity.directory_id NOT NULL,
 purpose text COLLATE "C" NOT NULL,
 record_id identity.directory_id NOT NULL,
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 ceremony_id text COLLATE "C" NOT NULL,
 ceremony jsonb NOT NULL CHECK(octet_length(ceremony::text)<=262144),
 before_credential jsonb CHECK(octet_length(before_credential::text)<=32768),
 after_credential jsonb CHECK(octet_length(after_credential::text)<=32768)
);
`
