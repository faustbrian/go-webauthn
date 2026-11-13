// Test-fixture generator only. No private key or operational credential is kept.
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const openssl = process.env.RS256_OPENSSL;
if (!openssl) throw new Error('RS256_OPENSSL must select the exact OpenSSL executable');
const scratch = mkdtempSync(join(tmpdir(), 'webauthn-rsa-oracle-'));
try {
  const key = join(scratch, 'temporary-test-key.pem');
  const message = join(scratch, 'message.bin');
  execFileSync(openssl, ['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072', '-out', key], { stdio: ['ignore', 'ignore', 'ignore'] });
  const modulus = execFileSync(openssl, ['rsa', '-in', key, '-noout', '-modulus'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim().slice('Modulus='.length);
  const client = Buffer.from('{"type":"webauthn.get","challenge":"AA","origin":"https://login.example.com","crossOrigin":false}');
  const auth = Buffer.concat([createHash('sha256').update('example.com').digest(), Buffer.from([5, 0, 0, 0, 1])]);
  writeFileSync(message, Buffer.concat([auth, createHash('sha256').update(client).digest()]));
  const signature = execFileSync(openssl, ['dgst', '-sha256', '-sign', key, message]);
  const fixture = {
    source: 'OpenSSL independent RS256 crypto oracle; not an authenticator/browser',
    version: execFileSync(openssl, ['version'], { encoding: 'utf8' }).trim(),
    executable_sha256: createHash('sha256').update(readFileSync(openssl)).digest('hex'),
    modulus_hex: modulus.toLowerCase(), exponent: 65537,
    client_data: client.toString('utf8'), authenticator_data_hex: auth.toString('hex'),
    signature_hex: signature.toString('hex'),
  };
  writeFileSync(new URL('./openssl.json', import.meta.url), JSON.stringify(fixture, null, 2) + '\n');
} finally {
  rmSync(scratch, { recursive: true });
}
