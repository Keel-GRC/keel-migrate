import { test } from 'node:test';
import assert from 'node:assert/strict';
import { GuardedHttp, PolicyViolation } from '../src/http.js';
import { resolvePolicy } from '../src/adapter.js';
import { fetchEvidenceDocuments } from '../src/files.js';
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

// Binary document download inherits the same host/HTTPS guard as getJson.
test('getBinary rejects a non-allowlisted host', async () => {
  const http = new GuardedHttp({ allowedHosts: ['api.example.com'], tokenEndpoint: null });
  await assert.rejects(() => http.getBinary('https://cdn.evil.net/policy.pdf'), PolicyViolation);
});

test('getBinary rejects a plain-HTTP document', async () => {
  const http = new GuardedHttp({ allowedHosts: ['api.example.com'], tokenEndpoint: null });
  await assert.rejects(() => http.getBinary('http://api.example.com/policy.pdf'), PolicyViolation);
});

test('guarded client permits POST only to the declared token endpoint', async () => {
  const http = new GuardedHttp({ allowedHosts: ['api.example.com'], tokenEndpoint: 'https://api.example.com/token' });
  await assert.rejects(() => http.postToken('https://api.example.com/other', {}), PolicyViolation);
});

test('guarded client refuses every POST for an API-key adapter (no token endpoint)', async () => {
  const http = new GuardedHttp({ allowedHosts: ['api.example.com'], tokenEndpoint: null });
  await assert.rejects(() => http.postToken('https://api.example.com/token', {}), PolicyViolation);
});

// Every adapter must fully declare what it touches (the manifest conformance rule).
for (const [name, adapter] of Object.entries(adapters)) {
  test(`adapter "${name}" declares a conformant manifest`, () => {
    const m = adapter.manifest;
    const allEndpoints = [...m.endpoints, ...(m.readPostEndpoints ?? [])];
    assert.ok(allEndpoints.length > 0, 'must declare at least one endpoint');
    for (const ep of allEndpoints) {
      assert.ok(ep.path.startsWith('/'), `endpoint path must be relative: ${ep.path}`);
      assert.ok(/^https:\/\//.test(ep.docUrl), `endpoint ${ep.path} must link to official docs`);
    }
    assert.ok(/^https:\/\//.test(m.officialDocsUrl), 'officialDocsUrl must be set');
    // Static-host OAuth adapters declare a concrete token endpoint (host must be
    // allowlisted). Dynamic-host adapters declare null + a tokenPath instead (the
    // real URL is formed from the customer host at runtime). API-key adapters use null.
    if (m.tokenEndpoint !== null) {
      const tokenHost = new URL(m.tokenEndpoint).hostname;
      assert.ok(m.allowedHosts.includes(tokenHost), 'token endpoint host must be allowlisted');
    }
    // Dynamic-host adapters must constrain the host to the vendor's own domain.
    if (m.dynamicHost) {
      assert.ok(m.dynamicHost.env, 'dynamicHost must name an env var');
      assert.ok(
        m.dynamicHost.allowedSuffixes.length > 0 &&
          m.dynamicHost.allowedSuffixes.every((s) => s.startsWith('.')),
        'dynamicHost.allowedSuffixes must be non-empty dotted suffixes',
      );
      if (m.tokenPath) assert.ok(m.tokenPath.startsWith('/'), 'tokenPath must be relative');
    }
    assert.ok(m.credentialEnv.length > 0, 'must declare credential env vars');
    // Read-only: no scope may request write/admin/manage access.
    assert.ok(
      m.scopes.every((s) => !/(write|create|update|delete|admin|manage|edit)/i.test(s)),
      'scopes must be read-only (no write/admin scopes)',
    );
  });
}

// Evidence download inherits the guard: an off-allowlist media URL is skipped
// (counted), never fetched, and never sinks the export.
test('fetchEvidenceDocuments skips off-allowlist artifacts without throwing', async () => {
  const http = new GuardedHttp({ allowedHosts: ['api.vanta.com'], tokenEndpoint: null });
  const { files, skipped } = await fetchEvidenceDocuments(http, [
    { externalId: 'doc:up', mediaUrl: 'https://cdn.evil.net/evidence.pdf' },
    { externalId: 'no-url', mediaUrl: '' },
  ]);
  assert.equal(files.length, 0);
  assert.equal(skipped, 2);
});

// A rate-limited read (429) is retried and succeeds once the host recovers.
test('getJson retries a 429 and then succeeds', async () => {
  const http = new GuardedHttp({ allowedHosts: ['api.example.com'], tokenEndpoint: null });
  const realFetch = globalThis.fetch;
  let calls = 0;
  // Retry-After: 0 keeps the backoff at zero so the test stays fast.
  globalThis.fetch = (async () => {
    calls++;
    if (calls === 1) {
      return new Response('{"error":"Too Many Requests"}', {
        status: 429,
        headers: { 'retry-after': '0' },
      });
    }
    return new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } });
  }) as typeof fetch;
  try {
    const out = await http.getJson<{ ok: boolean }>('https://api.example.com/data');
    assert.equal(out.ok, true);
    assert.equal(calls, 2, 'should have retried exactly once');
  } finally {
    globalThis.fetch = realFetch;
  }
});

// A declared read-POST path is permitted; anything else POSTed is refused.
test('postRead permits only declared read-query paths', async () => {
  const http = new GuardedHttp({
    allowedHosts: ['api.example.com'],
    tokenEndpoint: null,
    readPostPaths: ['/api/risk/v2/risks/pages'],
  });
  await assert.rejects(
    () => http.postRead('https://api.example.com/api/vendors/create', {}),
    PolicyViolation,
  );
});

test('postRead refuses a POST when no read paths are declared', async () => {
  const http = new GuardedHttp({ allowedHosts: ['api.example.com'], tokenEndpoint: null });
  await assert.rejects(
    () => http.postRead('https://api.example.com/api/risk/v2/risks/pages', {}),
    PolicyViolation,
  );
});

// resolvePolicy validates a customer-supplied tenant host against the allowed suffix.
test('resolvePolicy rejects tenant hosts outside the vendor domain', () => {
  const onetrust = adapters.onetrust;
  if (!onetrust?.manifest.dynamicHost) return; // skip if adapter absent
  const env = onetrust.manifest.dynamicHost.env;
  // Plain wrong domain, plus crafted look-alikes that a naive substring/endsWith
  // check would let through (fragment, path, userinfo, suffix-in-the-middle).
  for (const bad of [
    'evil.attacker.com',
    'attacker.com#.onetrust.com',
    'attacker.com/.onetrust.com',
    'onetrust.com.attacker.com',
    'notonetrust.com',
    'user@attacker.com',
    'https://attacker.com/.onetrust.com',
  ]) {
    assert.throws(() => resolvePolicy(onetrust.manifest, { [env]: bad }), undefined, `should reject ${bad}`);
  }
});

test('resolvePolicy admits a valid tenant host and forms the token endpoint', () => {
  const onetrust = adapters.onetrust;
  if (!onetrust?.manifest.dynamicHost) return;
  const host = 'yourco.my.onetrust.com';
  const policy = resolvePolicy(onetrust.manifest, {
    [onetrust.manifest.dynamicHost.env]: host,
  });
  assert.ok(
    policy.allowedHosts.some((h) => h === host),
    'tenant host added to allowlist',
  );
  if (onetrust.manifest.tokenPath) {
    assert.equal(policy.tokenEndpoint, `https://${host}${onetrust.manifest.tokenPath}`);
  }
});
