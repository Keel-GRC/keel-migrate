import { test } from 'node:test';
import assert from 'node:assert/strict';
import { GuardedHttp, PolicyViolation } from '../src/http.js';
import { adapters } from '../src/registry.js';

// The guarded client is the runtime enforcement of "official APIs only".
test('guarded client rejects a non-allowlisted host', async () => {
  const http = new GuardedHttp({ allowedHosts: ['api.example.com'], tokenEndpoint: 'https://api.example.com/token' });
  await assert.rejects(() => http.getJson('https://evil.example.net/data'), PolicyViolation);
});

test('guarded client rejects a plain-HTTP request', async () => {
  const http = new GuardedHttp({ allowedHosts: ['api.example.com'], tokenEndpoint: 'https://api.example.com/token' });
  await assert.rejects(() => http.getJson('http://api.example.com/data'), PolicyViolation);
});

test('guarded client permits POST only to the declared token endpoint', async () => {
  const http = new GuardedHttp({ allowedHosts: ['api.example.com'], tokenEndpoint: 'https://api.example.com/token' });
  await assert.rejects(() => http.postToken('https://api.example.com/other', {}), PolicyViolation);
});

// Every adapter must fully declare what it touches (the manifest conformance rule).
for (const [name, adapter] of Object.entries(adapters)) {
  test(`adapter "${name}" declares a conformant manifest`, () => {
    const m = adapter.manifest;
    assert.ok(m.endpoints.length > 0, 'must declare at least one endpoint');
    for (const ep of m.endpoints) {
      assert.ok(ep.path.startsWith('/'), `endpoint path must be relative: ${ep.path}`);
      assert.ok(/^https:\/\//.test(ep.docUrl), `endpoint ${ep.path} must link to official docs`);
    }
    assert.ok(/^https:\/\//.test(m.officialDocsUrl), 'officialDocsUrl must be set');
    const tokenHost = new URL(m.tokenEndpoint).hostname;
    assert.ok(m.allowedHosts.includes(tokenHost), 'token endpoint host must be allowlisted');
    assert.ok(m.credentialEnv.length > 0, 'must declare credential env vars');
    assert.ok(m.scopes.every((s) => /read/i.test(s)), 'scopes should be read-only');
  });
}
