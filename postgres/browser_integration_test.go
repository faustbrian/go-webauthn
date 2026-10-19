//go:build integration && browser

package postgres_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	webauthn "github.com/faustbrian/go-webauthn"
)

// This is an independent real Chromium virtual authenticator, not the local
// handwritten signer. Both browser DTOs cross the supported core/native Store.
// Run alone against a fresh task database, with an explicit browser executable.
func TestBrowserRegistrationAssertionPostgres(t *testing.T) {
	ctx, _, _, store := nativeFixture(t)
	binary := os.Getenv("WEBAUTHN_BROWSER_BINARY")
	if binary == "" {
		t.Fatal("WEBAUTHN_BROWSER_BINARY is required for selected browser interoperability")
	}
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<!doctype html><title>WebAuthn test fixture</title>")
	}))
	defer web.Close()
	origin := strings.Replace(web.URL, "127.0.0.1", "localhost", 1)
	browser := startBrowser(t, ctx, binary, origin)
	key, e := webauthn.NewChallengeDigestKey(bytes.Repeat([]byte{14}, 32))
	if e != nil {
		t.Fatal(e)
	}
	config := webauthn.Config{TenantID: "tenant-a", RelyingParty: webauthn.RelyingParty{ID: "localhost", Name: "Browser fixture", Origins: []string{origin}, Version: 1}, ChallengeKey: key, DevelopmentLocalhostHTTP: true, MaximumDuration: 10 * time.Second, Extensions: webauthn.ExtensionRequestSet{CredentialProperties: true, CredentialProtection: 3, EnforceCredentialProtection: true}}
	svc, e := webauthn.New(config, webauthn.Dependencies{Store: store})
	if e != nil {
		t.Fatal(e)
	}
	fresh := func() webauthn.CeremonyContext {
		id, e := identity.NewCommandID()
		if e != nil {
			t.Fatal(e)
		}
		return webauthn.CeremonyContext{CommandID: id, TenantID: "tenant-a", UserID: "user-a", ActorID: "actor-a", CorrelationID: "browser-test"}
	}
	handle := bytes.Repeat([]byte{15}, 32)
	registrationOptions, e := svc.BeginRegistration(ctx, webauthn.BeginRegistrationRequest{Context: fresh(), UserHandle: handle, Origin: origin})
	if e != nil {
		t.Fatal(e)
	}
	ceremony, _ := registrationOptions.Ceremony()
	var options json.RawMessage
	if e = registrationOptions.TransferJSON(ctx, func(_ context.Context, wire []byte) error { options = bytes.Clone(wire); return nil }); e != nil {
		t.Fatal(e)
	}
	registration := browser.operation(t, "create", options)
	clear(options)
	verified, e := svc.VerifyRegistration(ctx, webauthn.VerifyRegistrationRequest{Context: fresh(), CeremonyID: ceremony.ID, Origin: origin, ExpectedVersion: 1, Response: registration})
	clear(registration)
	if e != nil {
		t.Fatal("actual Chromium registration rejected", e)
	}
	credential, ok := verified.Credential()
	if !ok || credential.Algorithm != -7 || credential.Extensions.CredentialProperties == nil || credential.Extensions.CredentialProtection == nil || credential.Extensions.CredentialProtection.Policy != 3 {
		t.Fatal("actual selected browser extension/algorithm profile missing")
	}
	assertionOptions, e := svc.BeginAssertion(ctx, webauthn.BeginAssertionRequest{Context: fresh(), UserHandle: handle, Origin: origin, AllowedCredentials: [][]byte{credential.ID}})
	if e != nil {
		t.Fatal(e)
	}
	assertionCeremony, _ := assertionOptions.Ceremony()
	if e = assertionOptions.TransferJSON(ctx, func(_ context.Context, wire []byte) error { options = bytes.Clone(wire); return nil }); e != nil {
		t.Fatal(e)
	}
	assertion := browser.operation(t, "get", options)
	clear(options)
	result, e := svc.VerifyAssertion(ctx, webauthn.VerifyAssertionRequest{Context: fresh(), CeremonyID: assertionCeremony.ID, Origin: origin, ExpectedVersion: 1, ExpectedCredentialVersion: credential.Version, Response: assertion})
	clear(assertion)
	if e != nil {
		t.Fatal("actual Chromium assertion rejected", e)
	}
	final, ok := result.Credential()
	if !ok || final.Version != 2 || final.Counter <= credential.Counter || final.Extensions.CredentialProtection == nil || final.Extensions.CredentialProtection.Policy != 3 || final.Extensions.CredentialProtection.Authority != webauthn.UnattestedAuthenticator || final.Extensions.CredentialProperties == nil || final.Extensions.CredentialProperties.Authority != webauthn.BrowserReported {
		t.Fatal("browser signature/counter was not finalized")
	}
}

type browserPipe struct {
	input   io.WriteCloser
	output  *bufio.Reader
	command *exec.Cmd
}

func (b *browserPipe) operation(t *testing.T, operation string, options json.RawMessage) json.RawMessage {
	t.Helper()
	if e := json.NewEncoder(b.input).Encode(struct {
		Operation string          `json:"operation"`
		Options   json.RawMessage `json:"options"`
	}{operation, options}); e != nil {
		t.Fatal("browser pipe write")
	}
	line, e := b.output.ReadBytes('\n')
	if e != nil {
		t.Fatal("browser pipe read")
	}
	if len(line) > 256<<10 {
		t.Fatal("browser response bound")
	}
	var response struct {
		Result json.RawMessage `json:"result"`
		Error  string          `json:"error"`
	}
	if json.Unmarshal(line, &response) != nil || response.Error != "" || len(response.Result) == 0 {
		t.Fatal("independent browser operation failed", response.Error)
	}
	return response.Result
}
func startBrowser(t *testing.T, ctx context.Context, binary, origin string) *browserPipe {
	t.Helper()
	profile := t.TempDir()
	browserCtx, stopBrowser := context.WithCancel(ctx)
	chrome := exec.CommandContext(browserCtx, binary, "--headless=new", "--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--disable-component-update", "--disable-default-apps", "--password-store=basic", "--use-mock-keychain", "--remote-debugging-address=127.0.0.1", "--remote-debugging-port=0", "--user-data-dir="+profile, "about:blank")
	chrome.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	chrome.Stdout = io.Discard
	chrome.Stderr = io.Discard
	if e := chrome.Start(); e != nil {
		stopBrowser()
		t.Fatal("start isolated headless browser")
	}
	t.Cleanup(func() { stopBrowser(); _ = syscall.Kill(-chrome.Process.Pid, syscall.SIGTERM); _ = chrome.Wait() })
	var endpoint string
	for range 100 {
		wire, e := os.ReadFile(filepath.Join(profile, "DevToolsActivePort"))
		if e == nil {
			parts := strings.Split(strings.TrimSpace(string(wire)), "\n")
			if len(parts) == 2 {
				endpoint = "ws://127.0.0.1:" + parts[0] + parts[1]
				break
			}
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			t.Fatal("browser startup deadline")
		case <-timer.C:
		}
	}
	if endpoint == "" {
		t.Fatal("isolated browser did not expose loopback debugging endpoint")
	}
	wpt, e := filepath.Abs("testdata/wpt")
	if e != nil {
		t.Fatal(e)
	}
	node := exec.CommandContext(ctx, "node", "--input-type=module", "-e", browserDriver, endpoint, origin, wpt)
	node.Stderr = io.Discard
	input, e := node.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	output, e := node.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = node.Start(); e != nil {
		t.Fatal("start independent CDP driver")
	}
	b := &browserPipe{input: input, output: bufio.NewReaderSize(output, 256<<10), command: node}
	t.Cleanup(func() { _ = input.Close(); _ = node.Process.Kill(); _ = node.Wait() })
	line, e := b.output.ReadBytes('\n')
	if e != nil {
		t.Fatal("independent browser initialization failed")
	}
	var ready struct {
		Ready   bool   `json:"ready"`
		Version string `json:"version"`
		Driver  string `json:"driver"`
	}
	if json.Unmarshal(line, &ready) != nil || !ready.Ready {
		t.Fatal("independent browser not ready")
	}
	t.Logf("independent authenticator runtime: %s; driver %s; pinned WPT9bc6e2404bff", ready.Version, ready.Driver)
	return b
}

// No raw browser data enters files/logs: request and result JSON stays in pipes.
// The public Chrome DevTools WebAuthn API supplies the independent CTAP engine.
const browserDriver = `
import fs from 'node:fs';
import readline from 'node:readline';
const [endpoint, origin, wpt] = process.argv.slice(1);
const socket = new WebSocket(endpoint);
await new Promise((resolve,reject)=>{socket.addEventListener('open',resolve,{once:true});socket.addEventListener('error',reject,{once:true});});
let next=0; const pending=new Map();
socket.addEventListener('message',event=>{const m=JSON.parse(event.data);if(m.id){const p=pending.get(m.id);if(p){pending.delete(m.id);m.error?p.reject(new Error('cdp-method-failed')):p.resolve(m.result);}}});
function send(method,params={},sessionId){const id=++next;return new Promise((resolve,reject)=>{pending.set(id,{resolve,reject});socket.send(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})}));});}
const version=await send('Browser.getVersion');
const {targetId}=await send('Target.createTarget',{url:origin});
const {sessionId}=await send('Target.attachToTarget',{targetId,flatten:true});
await send('Page.enable',{},sessionId);
await send('WebAuthn.enable',{enableUI:false},sessionId);
// Chromium 0e66b945 content/browser/webauth/virtual_authenticator.cc assigns
// config.cred_protect_support = config.cred_blob_support = has_cred_blob_.
// Without this capability, the requested enforced credProtect policy rejects.
// No credBlob extension is requested or accepted by the production verifier.
await send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',ctap2Version:'ctap2_1',transport:'internal',hasResidentKey:true,hasCredBlob:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}},sessionId);
const common=fs.readFileSync(wpt+'/common-inputs.js','utf8');
const utils=fs.readFileSync(wpt+'/utils.js','utf8');
const harness='function assert_equals(a,b){if(a!==b)throw new Error("wpt-equality");} function assert_greater_than_equal(a,b){if(a<b)throw new Error("wpt-bound");} function assert_unreached(){throw new Error("wpt-unreached");}';
const initialized=await send('Runtime.evaluate',{expression:harness+'\n'+common+'\n'+utils},sessionId);
if(initialized.exceptionDetails)throw new Error('official-wpt-initialization-failed');
process.stdout.write(JSON.stringify({ready:true,version:version.product+' '+version.revision,driver:process.version})+'\n');
const lines=readline.createInterface({input:process.stdin,crlfDelay:Infinity});
for await(const line of lines){try{
 const request=JSON.parse(line); if(!['create','get'].includes(request.operation))throw new Error('unsupported-operation');
 const input=JSON.stringify(request.options);
 const method=request.operation==='create'?'parseCreationOptionsFromJSON':'parseRequestOptionsFromJSON';
 const expression='(async()=>{let stage="parse-options";try{const input='+input+';const options=PublicKeyCredential.'+method+'(input.publicKey);stage="navigator-credentials";const credential=await navigator.credentials.'+request.operation+'({publicKey:options});stage="serialize-result";const output=credential.toJSON();stage="official-wpt-oracle";'+(request.operation==='create'?
 'const att=new Cbor(Uint8Array.from(base64urlDecode(output.response.attestationObject),c=>c.charCodeAt(0))).getCBOR();const auth=parseAuthenticatorData(att.authData);assert_equals(auth.attestedCredentialData.credentialPublicKey.alg,ES256_ID);assert_equals(auth.flags.up,true);assert_equals(auth.flags.uv,true);globalThis.wptPublicKey=coseObjectToJWK(auth.attestedCredentialData.credentialPublicKey);':
 'const auth=Uint8Array.from(base64urlDecode(output.response.authenticatorData),c=>c.charCodeAt(0));const client=Uint8Array.from(base64urlDecode(output.response.clientDataJSON),c=>c.charCodeAt(0));const hash=new Uint8Array(await crypto.subtle.digest("SHA-256",client));const signed=new Uint8Array(auth.length+hash.length);signed.set(auth);signed.set(hash,auth.length);const key=await crypto.subtle.importKey("jwk",globalThis.wptPublicKey,{name:"ECDSA",namedCurve:"P-256"},false,["verify"]);const signature=convertDERSignatureToSubtle(Uint8Array.from(base64urlDecode(output.response.signature),c=>c.charCodeAt(0)));assert_equals(await crypto.subtle.verify({name:"ECDSA",hash:"SHA-256"},key,signature,signed),true);')+'return output;}catch(error){const allowed=["TypeError","ReferenceError","SecurityError","NotAllowedError","NotSupportedError","InvalidStateError","Error"];return {fixtureError:{stage,name:allowed.includes(error.name)?error.name:"other"}};}})()';
 const evaluated=await send('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true},sessionId);
 if(evaluated.exceptionDetails)throw new Error('browser-webauthn-or-wpt-failed');
 if(evaluated.result.value?.fixtureError){const error=evaluated.result.value.fixtureError;throw new Error(error.stage+':'+error.name);}
 process.stdout.write(JSON.stringify({result:evaluated.result.value})+'\n');
 }catch(error){process.stdout.write(JSON.stringify({error:error.message})+'\n');}}
await send('Browser.close');socket.close();
`
