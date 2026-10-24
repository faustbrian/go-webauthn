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
	d, e := migrations.NewMigration(2, "webauthn_discoverable", migrations.TransactionModeDefault, discoverableSQL, "")
	if e != nil {
		return nil, webauthn.Unavailable{}
	}
	p, e := migrations.NewMigration(3, "webauthn_native_discovery_options", migrations.TransactionModeDefault, nativeDiscoverySQL, "")
	if e != nil {
		return nil, webauthn.Unavailable{}
	}
	s, e := migrations.NewMigration(4, "webauthn_signup_registration", migrations.TransactionModeDefault, signupRegistrationSQL, "")
	if e != nil {
		return nil, webauthn.Unavailable{}
	}
	a, e := migrations.NewMigration(5, "webauthn_session_enrollment", migrations.TransactionModeDefault, sessionEnrollmentSQL, "")
	if e != nil {
		return nil, webauthn.Unavailable{}
	}
	r, e := migrations.NewMigration(6, "webauthn_removal_assertion", migrations.TransactionModeDefault, removalAssertionSQL, "")
	if e != nil {
		return nil, webauthn.Unavailable{}
	}
	return []migrations.Migration{m, d, p, s, a, r}, nil
}

// The original effect's before/after remain the verifier's exact source state.
// Add bounded target snapshots instead of overwriting that historical evidence
// or introducing another effect journal when source and target differ.
const removalAssertionSQL = `ALTER TABLE webauthn.effects ADD COLUMN removal_before_credential jsonb CHECK(octet_length(removal_before_credential::text)<=32768);
ALTER TABLE webauthn.effects ADD COLUMN removal_after_credential jsonb CHECK(octet_length(removal_after_credential::text)<=32768);
ALTER TABLE webauthn.effects ADD CONSTRAINT effects_removal_assertion_profile CHECK(
 (removal_before_credential IS NULL AND removal_after_credential IS NULL) OR
 (removal_before_credential IS NOT NULL AND removal_after_credential IS NOT NULL AND
  purpose='identity.passkey.delete' AND user_id IS NOT NULL AND actor_id=user_id AND anonymous_flow_id IS NULL AND
  enrollment_stage IS NULL AND enrollment_source IS NULL AND before_credential IS NOT NULL AND after_credential IS NOT NULL AND
  octet_length(ceremony_id)=22 AND jsonb_typeof(ceremony)='object' AND
  jsonb_typeof(removal_before_credential)='object' AND jsonb_typeof(removal_after_credential)='object'));
`

// An enrollment assertion authorizes a later registration only until its own
// original expiry. Keep that independent ceiling outside the root's immutable
// digest-bound ceremony record, whose five-minute TTL must remain unchanged.
const sessionEnrollmentSQL = `ALTER TABLE webauthn.ceremonies ADD COLUMN authorization_expires_at timestamptz;
ALTER TABLE webauthn.ceremonies ADD COLUMN authorization_ceremony_id text COLLATE "C";
ALTER TABLE webauthn.ceremonies ADD CONSTRAINT ceremonies_enrollment_authority CHECK(
 (authorization_expires_at IS NULL AND authorization_ceremony_id IS NULL) OR
 (authorization_expires_at IS NOT NULL AND authorization_ceremony_id IS NOT NULL AND kind='create' AND user_id IS NOT NULL AND signup_flow_id IS NULL AND anonymous_flow_id IS NULL AND octet_length(authorization_ceremony_id)=22 AND authorization_ceremony_id<>ceremony_id AND authorization_expires_at<=expires_at));
ALTER TABLE webauthn.effects ADD COLUMN enrollment_stage smallint;
ALTER TABLE webauthn.effects ADD COLUMN enrollment_source jsonb CHECK(octet_length(enrollment_source::text)<=262144);
ALTER TABLE webauthn.effects ADD CONSTRAINT effects_enrollment_profile CHECK(
 (enrollment_stage IS NULL AND enrollment_source IS NULL) OR
 (enrollment_stage=1 AND purpose='identity.passkey.register-options' AND user_id IS NOT NULL AND actor_id=user_id AND anonymous_flow_id IS NULL AND enrollment_source IS NULL AND before_credential IS NULL AND after_credential IS NULL) OR
 (enrollment_stage=2 AND purpose='identity.passkey.register-options' AND user_id IS NOT NULL AND actor_id=user_id AND anonymous_flow_id IS NULL AND enrollment_source IS NOT NULL AND before_credential IS NOT NULL AND after_credential IS NOT NULL) OR
 (enrollment_stage=3 AND purpose='identity.passkey.register-verify' AND user_id IS NOT NULL AND actor_id=user_id AND anonymous_flow_id IS NULL AND enrollment_source IS NULL AND before_credential IS NULL AND after_credential IS NOT NULL));
`

// Pending signup has no identity to reference. Keep the existing user FK and
// anonymous-discovery namespace intact; a verified one-use update alone promotes
// the prospective ID to the real user association, retaining the original flow.
const signupRegistrationSQL = `ALTER TABLE webauthn.ceremonies ADD COLUMN signup_user_id identity.directory_id;
ALTER TABLE webauthn.ceremonies ADD COLUMN signup_flow_id identity.directory_id;
ALTER TABLE webauthn.ceremonies DROP CONSTRAINT ceremonies_subject_kind;
ALTER TABLE webauthn.ceremonies ADD CONSTRAINT ceremonies_subject_kind CHECK(
 (kind IN ('create','get') AND user_id IS NOT NULL AND anonymous_flow_id IS NULL AND signup_user_id IS NULL AND signup_flow_id IS NULL) OR
 (kind='get-discoverable' AND user_id IS NULL AND anonymous_flow_id IS NOT NULL AND signup_user_id IS NULL AND signup_flow_id IS NULL) OR
 (kind='create' AND anonymous_flow_id IS NULL AND signup_flow_id IS NOT NULL AND
  ((user_id IS NULL AND signup_user_id IS NOT NULL AND consumed_by IS NULL) OR
   (user_id IS NOT NULL AND signup_user_id IS NULL AND consumed_by IS NOT NULL))));
ALTER TABLE webauthn.effects DROP CONSTRAINT effects_subject_namespace;
ALTER TABLE webauthn.effects ADD CONSTRAINT effects_subject_namespace CHECK(
 (user_id IS NOT NULL AND anonymous_flow_id IS NULL) OR
 (user_id IS NULL AND anonymous_flow_id IS NOT NULL AND purpose IN ('webauthn.begin-get-discoverable','webauthn.assert-discoverable','identity.passkey.signin-options','identity.passkey.register-options','identity.passkey.register-verify')));
`

// Native discovery options share their parent's command and purpose; migration
// 2 intentionally admits only standalone anonymous protocol effects. Keep that
// installed history immutable and add only the selected native options purpose.
const nativeDiscoverySQL = `ALTER TABLE webauthn.effects DROP CONSTRAINT effects_subject_namespace;
ALTER TABLE webauthn.effects ADD CONSTRAINT effects_subject_namespace CHECK(
 (user_id IS NOT NULL AND anonymous_flow_id IS NULL) OR
 (user_id IS NULL AND anonymous_flow_id IS NOT NULL AND purpose IN ('webauthn.begin-get-discoverable','webauthn.assert-discoverable','identity.passkey.signin-options')));
`

// Existing rows remain identified; old binaries cannot select anonymous NULL
// subjects. New binaries require this forward migration before activation.
const discoverableSQL = `ALTER TABLE webauthn.ceremonies ALTER COLUMN user_id DROP NOT NULL;
ALTER TABLE webauthn.ceremonies ADD COLUMN anonymous_flow_id identity.directory_id;
ALTER TABLE webauthn.ceremonies DROP CONSTRAINT ceremonies_kind_check;
ALTER TABLE webauthn.ceremonies ADD CONSTRAINT ceremonies_subject_kind CHECK(
 (kind IN ('create','get') AND user_id IS NOT NULL AND anonymous_flow_id IS NULL) OR
 (kind='get-discoverable' AND user_id IS NULL AND anonymous_flow_id IS NOT NULL));
ALTER TABLE webauthn.effects ALTER COLUMN user_id DROP NOT NULL;
ALTER TABLE webauthn.effects ADD COLUMN anonymous_flow_id identity.directory_id;
ALTER TABLE webauthn.effects ADD CONSTRAINT effects_subject_namespace CHECK(
 (user_id IS NOT NULL AND anonymous_flow_id IS NULL) OR
 (user_id IS NULL AND anonymous_flow_id IS NOT NULL AND purpose IN ('webauthn.begin-get-discoverable','webauthn.assert-discoverable')));
`

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
