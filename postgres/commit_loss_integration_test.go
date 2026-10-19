//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	webauthn "github.com/faustbrian/go-webauthn"
	webauthnpg "github.com/faustbrian/go-webauthn/postgres"
	"github.com/jackc/pgx/v5"
)

// A real server COMMIT CommandComplete is discarded after PostgreSQL commits.
// This exercises unknown-but-committed recovery, not a simulated boolean result
// or a deferred trigger that actually rolls back. The wrapper owns no goroutine.
func TestCommittedAcknowledgementLossPostgres(t *testing.T) {
	ctx, primary, coordinator, _ := nativeFixture(t)
	cut := &commitCut{}
	pool, e := database.New(ctx, database.Config{DSN: os.Getenv("WEBAUTHN_TEST_DSN"), MaxConns: 2, SessionInit: func(ctx context.Context, c *pgx.Conn) error { _, e := c.Exec(ctx, `SET search_path=public`); return e }, Configure: func(c *database.PoolConfig) error {
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
	defer pool.Close(context.Background())
	store, e := webauthnpg.New(pool, webauthnpg.Config{Coordinator: coordinator, PolicyID: "webauthn-loss", PolicyVersion: 1})
	if e != nil {
		t.Fatal(e)
	}
	key, e := webauthn.NewChallengeDigestKey(bytes.Repeat([]byte{23}, 32))
	if e != nil {
		t.Fatal(e)
	}
	serviceConfig := webauthn.Config{TenantID: "tenant-a", RelyingParty: webauthn.RelyingParty{ID: "example.com", Name: "Loss fixture", Origins: []string{"https://login.example.com"}, Version: 1}, ChallengeKey: key, MaximumDuration: 10 * time.Second, Extensions: webauthn.ExtensionRequestSet{CredentialProperties: true, CredentialProtection: 3, EnforceCredentialProtection: true}}
	svc, e := webauthn.New(serviceConfig, webauthn.Dependencies{Store: store})
	if e != nil {
		t.Fatal(e)
	}
	restart := func() {
		store, e = webauthnpg.New(pool, webauthnpg.Config{Coordinator: coordinator, PolicyID: "webauthn-loss", PolicyVersion: 1})
		if e != nil {
			t.Fatal(e)
		}
		svc, e = webauthn.New(serviceConfig, webauthn.Dependencies{Store: store})
		if e != nil {
			t.Fatal(e)
		}
	}
	fresh := func() webauthn.CeremonyContext {
		id, e := identity.NewCommandID()
		if e != nil {
			t.Fatal(e)
		}
		return webauthn.CeremonyContext{CommandID: id, TenantID: "tenant-a", UserID: "user-a", ActorID: "actor-a", CorrelationID: "lost-commit"}
	}
	handle := bytes.Repeat([]byte{24}, 32)
	begin := webauthn.BeginRegistrationRequest{Context: fresh(), UserHandle: handle, Origin: "https://login.example.com"}
	cut.remaining.Store(2) // acknowledged reservation, then lost domain commit.
	options, e := svc.BeginRegistration(ctx, begin)
	var unknown webauthn.UnknownCommit
	if !errors.As(e, &unknown) || unknown.CommandID != begin.Context.CommandID || !cut.cut.Load() {
		t.Fatal("lost committed challenge acknowledgement not classified", e)
	}
	if _, ok := options.Ceremony(); ok {
		t.Fatal("unknown creation returned options")
	}
	restart()
	if outcome, e := svc.Recover(ctx, webauthn.RecoveryRequest{Context: begin.Context, Operation: webauthn.BeginRegistrationOperation}); e != nil || outcome != identity.CommitOutcomeCommitted {
		t.Fatal("committed original creation not recovered", e)
	}
	if retry, e := svc.BeginRegistration(ctx, begin); e != nil {
		t.Fatal("committed creation retry", e)
	} else if e = retry.TransferJSON(ctx, func(context.Context, []byte) error { t.Fatal("lost challenge was reminted/revealed"); return nil }); e == nil {
		t.Fatal("lost challenge unexpectedly available")
	}
	// A distinct fresh ceremony is allowed only after original commitment is
	// known. Its original user-handle mapping is unchanged.
	begin.Context = fresh()
	options, e = svc.BeginRegistration(ctx, begin)
	if e != nil {
		t.Fatal(e)
	}
	ceremony, _ := options.Ceremony()
	challenge := optionChallenge(t, ctx, options.TransferJSON)
	private, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	id := bytes.Repeat([]byte{25}, 32)
	registered, e := svc.VerifyRegistration(ctx, webauthn.VerifyRegistrationRequest{Context: fresh(), CeremonyID: ceremony.ID, Origin: begin.Origin, ExpectedVersion: 1, Response: registrationResponse(t, private, id, challenge, 0x45, 0)})
	if e != nil {
		t.Fatal(e)
	}
	credential, ok := registered.Credential()
	if !ok {
		t.Fatal("registration missing")
	}
	assertOptions, e := svc.BeginAssertion(ctx, webauthn.BeginAssertionRequest{Context: fresh(), UserHandle: handle, Origin: begin.Origin, AllowedCredentials: [][]byte{id}})
	if e != nil {
		t.Fatal(e)
	}
	assertCeremony, _ := assertOptions.Ceremony()
	assertChallenge := optionChallenge(t, ctx, assertOptions.TransferJSON)
	r := webauthn.VerifyAssertionRequest{Context: fresh(), CeremonyID: assertCeremony.ID, Origin: begin.Origin, ExpectedVersion: 1, ExpectedCredentialVersion: credential.Version, Response: assertionResponse(t, private, id, handle, assertChallenge, 0x05, 1)}
	cut.cut.Store(false)
	cut.remaining.Store(2)
	verified, e := svc.VerifyAssertion(ctx, r)
	if !errors.As(e, &unknown) || unknown.CommandID != r.Context.CommandID || !cut.cut.Load() {
		t.Fatal("lost committed assertion acknowledgement not classified", e)
	}
	if _, ok := verified.Credential(); ok {
		t.Fatal("unknown assertion returned verification")
	}
	restart()
	if outcome, e := svc.Recover(ctx, webauthn.RecoveryRequest{Context: r.Context, Operation: webauthn.AssertionOperation, CredentialID: id}); e != nil || outcome != identity.CommitOutcomeCommitted {
		t.Fatal("committed original assertion not recovered", e)
	}
	var count int
	if e = primary.Raw().QueryRow(ctx, `SELECT count(*) FROM webauthn.credentials WHERE record->>'Counter'='1' AND version=2`).Scan(&count); e != nil || count != 1 {
		t.Fatal("actual committed counter not retained", e)
	}
	var beforeEffects, beforeAudits, beforeOutbox int
	if e = primary.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM webauthn.effects),(SELECT count(*) FROM audit.identity_command_bindings),(SELECT count(*) FROM public.outbox_messages)`).Scan(&beforeEffects, &beforeAudits, &beforeOutbox); e != nil {
		t.Fatal(e)
	}
	var replay webauthn.Replay
	if v, e := svc.VerifyAssertion(ctx, r); !errors.As(e, &replay) {
		t.Fatal("lost-ack retry did not return historical replay", e)
	} else if _, ok := v.Credential(); ok {
		t.Fatal("lost-ack replay renewed verification")
	}
	var effects, audits, outbox int
	if e = primary.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM webauthn.effects),(SELECT count(*) FROM audit.identity_command_bindings),(SELECT count(*) FROM public.outbox_messages)`).Scan(&effects, &audits, &outbox); e != nil || effects != beforeEffects || audits != beforeAudits || outbox != beforeOutbox {
		t.Fatal("retry repeated durable effects", e)
	}
	t.Run("noncommit recovery loses its actual commit acknowledgement", func(t *testing.T) {
		begin := webauthn.BeginAssertionRequest{Context: fresh(), UserHandle: handle, Origin: "https://login.example.com", AllowedCredentials: [][]byte{id}}
		options, e := svc.BeginAssertion(ctx, begin)
		if e != nil {
			t.Fatal(e)
		}
		ceremony, _ := options.Ceremony()
		challenge := optionChallenge(t, ctx, options.TransferJSON)
		request := webauthn.VerifyAssertionRequest{Context: fresh(), CeremonyID: ceremony.ID, Origin: begin.Origin, ExpectedVersion: 1, ExpectedCredentialVersion: 2, Response: assertionResponse(t, private, id, handle, challenge, 0x05, 2)}
		if _, e = primary.Raw().Exec(ctx, `CREATE FUNCTION public.webauthn_recovery_commit_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'deferred recovery fixture failure'; END $$; CREATE CONSTRAINT TRIGGER webauthn_recovery_commit_fail AFTER INSERT ON webauthn.effects DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.webauthn_recovery_commit_fail();`); e != nil {
			t.Fatal(e)
		}
		verified, e := svc.VerifyAssertion(ctx, request)
		if _, drop := primary.Raw().Exec(ctx, `DROP TRIGGER webauthn_recovery_commit_fail ON webauthn.effects; DROP FUNCTION public.webauthn_recovery_commit_fail();`); drop != nil {
			t.Fatal(drop)
		}
		if !errors.As(e, &unknown) || unknown.CommandID != request.Context.CommandID {
			t.Fatal("fixture did not leave the original pending unknown command", e)
		}
		if _, ok := verified.Credential(); ok {
			t.Fatal("rolled-back domain command returned verification")
		}
		command, e := base64.RawURLEncoding.DecodeString(string(request.Context.CommandID))
		if e != nil {
			t.Fatal(e)
		}
		updated, e := primary.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1 AND state='pending'`, command)
		if e != nil || updated.RowsAffected() != 1 {
			t.Fatal(e)
		}
		var before [3]int
		if e = primary.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM webauthn.effects),(SELECT count(*) FROM audit.records WHERE outcome=$1),(SELECT count(*) FROM public.outbox_messages)`, int(audit.OutcomeSucceeded)).Scan(&before[0], &before[1], &before[2]); e != nil {
			t.Fatal(e)
		}
		recovery := webauthn.RecoveryRequest{Context: request.Context, Operation: webauthn.AssertionOperation, CredentialID: id}
		cut.cut.Store(false)
		cut.remaining.Store(1) // lose the actual noncommit reconciliation COMMIT.
		outcome, e := svc.Recover(ctx, recovery)
		if !cut.cut.Load() {
			t.Fatal("fixture did not discard the actual recovery COMMIT acknowledgement")
		}
		var reconciled bool
		if read := primary.Raw().QueryRow(ctx, `SELECT state='aborted' AND terminal_class='dependency-failure' FROM identity.commands WHERE command_id=$1`, command).Scan(&reconciled); read != nil || !reconciled {
			t.Fatal("server did not commit the original noncommit reconciliation", read)
		}
		if outcome != identity.CommitOutcomeUnknown || !errors.As(e, &unknown) || unknown.CommandID != request.Context.CommandID {
			t.Fatal("recovery commit ambiguity erased original unknown identity", outcome, e)
		}
		restart()
		var unavailable webauthn.Unavailable
		if outcome, e = svc.Recover(ctx, recovery); outcome != identity.CommitOutcomeNotCommitted || !errors.As(e, &unavailable) {
			t.Fatal("original recovery did not converge after lost acknowledgement", outcome, e)
		}
		var after [3]int
		if e = primary.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM webauthn.effects),(SELECT count(*) FROM audit.records WHERE outcome=$1),(SELECT count(*) FROM public.outbox_messages)`, int(audit.OutcomeSucceeded)).Scan(&after[0], &after[1], &after[2]); e != nil || after != before {
			t.Fatal("noncommit reconciliation retained success effects", e)
		}
		var unconsumed int
		if e = primary.Raw().QueryRow(ctx, `SELECT count(*) FROM webauthn.ceremonies WHERE ceremony_id=$1 AND consumed_by IS NULL`, request.CeremonyID).Scan(&unconsumed); e != nil || unconsumed != 1 {
			t.Fatal("noncommit recovery consumed the original ceremony", e)
		}
		stored, e := store.LoadCredential(ctx, webauthn.Lookup{Context: request.Context, RPID: "example.com", CeremonyID: request.CeremonyID}, id)
		if e != nil || stored.Counter != 1 || stored.Version != 2 {
			t.Fatal("noncommit recovery mutated current credential", e)
		}
		if result, e := svc.VerifyAssertion(ctx, request); e == nil {
			t.Fatal("recovered noncommit became a fresh authentication")
		} else if _, ok := result.Credential(); ok {
			t.Fatal("recovered retry renewed verification")
		}
		if replay, e := svc.BeginAssertion(ctx, begin); e != nil {
			t.Fatal(e)
		} else if e = replay.TransferJSON(ctx, func(context.Context, []byte) error {
			t.Fatal("recovery reminted original challenge custody")
			return nil
		}); e == nil {
			t.Fatal("recovered retry revealed original challenge")
		}
	})
}

func TestDiscoverableAcknowledgementLossPostgres(t *testing.T) {
	ctx, primary, coordinator, native := nativeFixture(t)
	key, _ := webauthn.NewChallengeDigestKey(bytes.Repeat([]byte{51}, 32))
	config := webauthn.Config{TenantID: "tenant-a", RelyingParty: webauthn.RelyingParty{ID: "example.com", Name: "Discoverable loss", Origins: []string{"https://login.example.com"}, Version: 1}, ChallengeKey: key, MaximumDuration: 10 * time.Second}
	svc, e := webauthn.NewDiscoverable(config, webauthn.Dependencies{Store: native})
	if e != nil {
		t.Fatal(e)
	}
	fresh := func(anonymous bool) webauthn.CeremonyContext {
		id, e := identity.NewCommandID()
		if e != nil {
			t.Fatal(e)
		}
		c := webauthn.CeremonyContext{CommandID: id, TenantID: "tenant-a", UserID: "user-a", ActorID: "actor-a", CorrelationID: "discoverable-loss"}
		if anonymous {
			c.UserID = ""
			c.AnonymousFlowID = "loss-pre-auth"
		}
		return c
	}
	handle, id := bytes.Repeat([]byte{52}, 32), bytes.Repeat([]byte{53}, 32)
	private, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	reg, e := svc.BeginRegistration(ctx, webauthn.BeginRegistrationRequest{Context: fresh(false), UserHandle: handle, Origin: config.RelyingParty.Origins[0], ResidentKeyRequired: true})
	if e != nil {
		t.Fatal(e)
	}
	r, _ := reg.Ceremony()
	challenge := optionChallenge(t, ctx, reg.TransferJSON)
	if _, e = svc.VerifyRegistration(ctx, webauthn.VerifyRegistrationRequest{Context: fresh(false), CeremonyID: r.ID, Origin: r.Intent.Origin, ExpectedVersion: 1, Response: registrationResponse(t, private, id, challenge, 0x45, 0)}); e != nil {
		t.Fatal(e)
	}
	cut := &commitCut{}
	pool, e := database.New(ctx, database.Config{DSN: os.Getenv("WEBAUTHN_TEST_DSN"), MaxConns: 2, SessionInit: func(ctx context.Context, c *pgx.Conn) error { _, e := c.Exec(ctx, `SET search_path=public`); return e }, Configure: func(c *database.PoolConfig) error {
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
	defer pool.Close(context.Background())
	restart := func() {
		store, e := webauthnpg.New(pool, webauthnpg.Config{Coordinator: coordinator, PolicyID: "discoverable-loss", PolicyVersion: 1})
		if e != nil {
			t.Fatal(e)
		}
		svc, e = webauthn.NewDiscoverable(config, webauthn.Dependencies{Store: store})
		if e != nil {
			t.Fatal(e)
		}
	}
	restart()
	begin := webauthn.BeginDiscoverableAssertionRequest{Context: fresh(true), Origin: r.Intent.Origin}
	cut.remaining.Store(2)
	options, e := svc.BeginDiscoverableAssertion(ctx, begin)
	var unknown webauthn.UnknownCommit
	if !errors.As(e, &unknown) || unknown.CommandID != begin.Context.CommandID || !cut.cut.Load() {
		t.Fatal("anonymous creation acknowledgement not unknown", e)
	}
	if _, ok := options.Ceremony(); ok {
		t.Fatal("unknown anonymous creation exposed custody")
	}
	restart()
	if out, e := svc.Recover(ctx, webauthn.RecoveryRequest{Context: begin.Context, Operation: webauthn.BeginDiscoverableAssertionOperation}); e != nil || out != identity.CommitOutcomeCommitted {
		t.Fatal("anonymous creation recovery", e)
	}
	if retry, e := svc.BeginDiscoverableAssertion(ctx, begin); e != nil {
		t.Fatal(e)
	} else if e = retry.TransferJSON(ctx, func(context.Context, []byte) error { t.Fatal("lost anonymous challenge revealed"); return nil }); e == nil {
		t.Fatal("lost anonymous challenge recreated")
	}
	begin.Context = fresh(true)
	options, e = svc.BeginDiscoverableAssertion(ctx, begin)
	if e != nil {
		t.Fatal(e)
	}
	c, _ := options.Ceremony()
	challenge = optionChallenge(t, ctx, options.TransferJSON)
	request := webauthn.VerifyDiscoverableAssertionRequest{Context: fresh(true), CeremonyID: c.ID, Origin: r.Intent.Origin, ExpectedVersion: 1, Response: assertionResponse(t, private, id, handle, challenge, 0x05, 1)}
	cut.cut.Store(false)
	cut.remaining.Store(2)
	verified, e := svc.VerifyDiscoverableAssertion(ctx, request)
	if !errors.As(e, &unknown) || unknown.CommandID != request.Context.CommandID || !cut.cut.Load() {
		t.Fatal("anonymous assertion acknowledgement not unknown", e)
	}
	if _, ok := verified.Credential(); ok {
		t.Fatal("unknown anonymous assertion authenticated")
	}
	restart()
	if out, e := svc.Recover(ctx, webauthn.RecoveryRequest{Context: request.Context, Operation: webauthn.DiscoverableAssertionOperation, CredentialID: id}); e != nil || out != identity.CommitOutcomeCommitted {
		t.Fatal("anonymous assertion recovery", e)
	}
	var before [3]int
	if e = primary.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM webauthn.effects),(SELECT count(*) FROM audit.identity_command_bindings),(SELECT count(*) FROM public.outbox_messages)`).Scan(&before[0], &before[1], &before[2]); e != nil {
		t.Fatal(e)
	}
	var replay webauthn.Replay
	if v, e := svc.VerifyDiscoverableAssertion(ctx, request); !errors.As(e, &replay) {
		t.Fatal("anonymous lost-ack replay", e)
	} else if _, ok := v.Credential(); ok {
		t.Fatal("anonymous lost-ack replay renewed verification")
	}
	var after [3]int
	if e = primary.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM webauthn.effects),(SELECT count(*) FROM audit.identity_command_bindings),(SELECT count(*) FROM public.outbox_messages)`).Scan(&after[0], &after[1], &after[2]); e != nil || after != before {
		t.Fatal("anonymous replay repeated effects", e)
	}
	var version string
	if e = primary.Raw().QueryRow(ctx, `SELECT version::text FROM webauthn.credentials WHERE rp_id='example.com' AND credential_id=$1 AND record->>'Counter'='1'`, id).Scan(&version); e != nil || version != "2" {
		t.Fatal("lost-ack counter transition missing", e)
	}
}

type commitCut struct {
	remaining atomic.Int32
	cut       atomic.Bool
}
type commitCutConn struct {
	net.Conn
	cut     *commitCut
	pending []byte
}

func (c *commitCutConn) Read(out []byte) (int, error) {
	if len(out) == 0 {
		return 0, nil
	}
	if len(c.pending) == 0 {
		var header [5]byte
		if _, e := io.ReadFull(c.Conn, header[:]); e != nil {
			return 0, e
		}
		n := binary.BigEndian.Uint32(header[1:])
		if n < 4 || n > 1<<20 {
			return 0, io.ErrUnexpectedEOF
		}
		message := make([]byte, int(n)+1)
		copy(message, header[:])
		if _, e := io.ReadFull(c.Conn, message[5:]); e != nil {
			return 0, e
		}
		if header[0] == 'C' && bytes.Equal(message[5:], []byte("COMMIT\x00")) && c.cut.remaining.Load() > 0 && c.cut.remaining.Add(-1) == 0 {
			c.cut.cut.Store(true)
			_ = c.Conn.Close()
			return 0, io.ErrUnexpectedEOF
		}
		c.pending = message
	}
	n := copy(out, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
