package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"math"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	webauthn "github.com/faustbrian/go-webauthn"
)

// CheckRemainingCredential reads and fences one current protocol credential
// inside this applied removal participant's original Work. The native parent
// selects and binds the candidate mapping/reference and current kernel authority,
// calls this during Apply and final precommit, and applies its algorithm policy.
// This method cannot establish last-key/recovery permission or authenticate.
//
// Scope and handle derive only from the genuine verified source. The removed
// target, erased keys, exhausted versions and non-resident registration histories
// deny. Original resident-required registration provenance must retain the same
// immutable ID/key/algorithm/handle. Its historical ceremony expiry is not a
// credential expiry. Credential, RP/handle and provenance row locks survive until
// this sole Work ends; the query returns at most two bounded rows under its
// deadline. No pool read, transaction, cache, goroutine or new state is created.
func (p *RemovalAssertionFinalization) CheckRemainingCredential(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, credentialID []byte) (webauthn.Credential, error) {
	if err := p.bind(ctx, w, owner, command, false); err != nil {
		return webauthn.Credential{}, err
	}
	s := p.state
	if !s.source.applied || len(credentialID) == 0 || len(credentialID) > 1024 || bytes.Equal(credentialID, s.removal.state.request.CredentialID) {
		return webauthn.Credential{}, webauthn.Denied{}
	}
	if err := s.source.current(ctx, w); err != nil {
		return webauthn.Credential{}, err
	}
	source := s.source.assertion.Before
	rows, err := w.Query(ctx, `SELECT c.record,c.version::text,e.after_credential,e.ceremony FROM webauthn.credentials c JOIN webauthn.user_handles h ON h.rp_id=c.rp_id AND h.user_handle=c.user_handle AND h.tenant_id=c.tenant_id AND h.user_id=c.user_id JOIN webauthn.relying_parties rp ON rp.rp_id=c.rp_id AND rp.tenant_id=c.tenant_id JOIN webauthn.effects e ON e.tenant_id=c.tenant_id AND e.after_credential->>'ID'=$6 AND e.after_credential->'PublicKey'=c.record->'PublicKey' AND e.after_credential->'Algorithm'=c.record->'Algorithm' AND e.after_credential->'UserHandle'=c.record->'UserHandle' JOIN webauthn.ceremonies r ON r.ceremony_id=e.ceremony_id AND r.record=e.ceremony AND r.consumed_by=e.command_id AND r.tenant_id=c.tenant_id AND r.user_id=c.user_id AND r.rp_id=c.rp_id WHERE c.rp_id=$1 AND c.credential_id=$2 AND c.tenant_id=$3 AND c.user_id=$4 AND c.user_handle=$5 AND c.version>0 AND c.version<18446744073709551615 AND COALESCE(c.record->>'PublicKey','')<>'' AND e.purpose IN ('webauthn.register','identity.passkey.register-verify') AND e.before_credential IS NULL AND e.actor_id=e.ceremony->'Intent'->'Context'->>'ActorID' AND ((e.user_id=c.user_id AND e.anonymous_flow_id IS NULL) OR (e.user_id IS NULL AND e.anonymous_flow_id=r.signup_flow_id AND r.signup_flow_id IS NOT NULL)) AND r.kind='create' AND e.ceremony->'Intent'->>'ResidentKeyRequired'='true' LIMIT 2 FOR SHARE OF c,h,rp,e,r`, source.RPID, credentialID, string(source.TenantID), string(source.UserID), source.UserHandle, base64.StdEncoding.EncodeToString(credentialID))
	if err != nil {
		return webauthn.Credential{}, err
	}
	var currentWire, originalWire, ceremonyWire []byte
	var version string
	if !rows.Next() {
		err = rows.Err()
		rows.Close()
		if err != nil {
			return webauthn.Credential{}, err
		}
		return webauthn.Credential{}, webauthn.Denied{}
	}
	err = rows.Scan(&currentWire, &version, &originalWire, &ceremonyWire)
	if rows.Next() {
		err = webauthn.Denied{}
	}
	rowErr := rows.Err()
	rows.Close()
	if err != nil {
		return webauthn.Credential{}, err
	}
	if rowErr != nil {
		return webauthn.Credential{}, rowErr
	}
	var current, original webauthn.Credential
	var ceremony webauthn.CeremonyRecord
	if len(currentWire) > 32768 || len(originalWire) > 32768 || len(ceremonyWire) > 262144 || json.Unmarshal(currentWire, &current) != nil || json.Unmarshal(originalWire, &original) != nil || json.Unmarshal(ceremonyWire, &ceremony) != nil {
		return webauthn.Credential{}, webauthn.Denied{}
	}
	i := ceremony.Intent
	if current.TenantID != source.TenantID || current.UserID != source.UserID || current.RPID != source.RPID || !bytes.Equal(current.ID, credentialID) || !bytes.Equal(current.UserHandle, source.UserHandle) || current.Version == 0 || current.Version == math.MaxUint64 || version != strconv.FormatUint(current.Version, 10) || len(current.PublicKey) == 0 || current.BackupState && !current.BackupEligible || original.Version != 1 || original.TenantID != current.TenantID || original.UserID != current.UserID || original.RPID != current.RPID || !bytes.Equal(original.ID, current.ID) || !bytes.Equal(original.UserHandle, current.UserHandle) || !bytes.Equal(original.PublicKey, current.PublicKey) || original.Algorithm != current.Algorithm || original.BackupEligible != current.BackupEligible || i.Kind != "create" || !i.ResidentKeyRequired || i.Context.TenantID != current.TenantID || i.Context.UserID != current.UserID || i.RPID != current.RPID || !bytes.Equal(i.UserHandle, current.UserHandle) || ceremony.ID != string(i.Context.CommandID) || ceremony.Version != 1 || ceremony.ChallengeDigest == ([32]byte{}) {
		return webauthn.Credential{}, webauthn.Denied{}
	}
	// Root assertionCredential requires a strictly larger positive counter for
	// non-backup credentials. Its uint32 maximum has no usable successor.
	if !current.BackupEligible && current.Counter == math.MaxUint32 {
		return webauthn.Credential{}, webauthn.Denied{}
	}
	if err := ctx.Err(); err != nil {
		return webauthn.Credential{}, err
	}
	return current, nil
}
