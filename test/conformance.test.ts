import { test } from 'node:test';
import assert from 'node:assert/strict';
import { GuardedHttp, PolicyViolation } from '../src/http.js';
import { resolvePolicy } from '../src/adapter.js';
import { fetchEvidenceDocuments } from '../src/files.js';
import {
  makeBundle,
  shardBundle,
  shardFileName,
  type BundleFile,
  type MigrationBundle,
} from '../src/bundle.js';
import { crc32, zipSync } from '../src/archive.js';
import { adapters } from '../src/registry.js';
import { execFileSync } from 'node:child_process';
import { writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as zlib from 'node:zlib';
import { inflateRawSync } from 'node:zlib';

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

// Sharding splits a large evidence set across importable bundle files, dropping
// nothing, while a small export stays a single bundle.
test('shardBundle splits files across shards and preserves every file', () => {
  const mkFile = (i: number, kb: number): BundleFile => ({
    externalId: `f${i}`,
    kind: 'evidence',
    refExternalId: null,
    name: `f${i}.bin`,
    contentType: 'application/octet-stream',
    sizeBytes: kb * 1024,
    sha256: 'x'.repeat(64),
    contentBase64: 'A'.repeat(kb * 1024), // ~kb KB of base64 chars
  });
  const files = Array.from({ length: 10 }, (_, i) => mkFile(i, 100)); // 10 x ~100 KB
  const bundle = makeBundle(
    'vanta',
    '0.0.0',
    { vendors: [{ externalId: 'v1', name: 'V' }], risks: [], people: [], policies: [], files },
    '2026-01-01T00:00:00.000Z',
  );

  // Cap at ~250 KB -> multiple shards.
  const shards = shardBundle(bundle, 250 * 1024);
  assert.ok(shards.length > 1, 'large export splits into multiple shards');
  // Registers ride only on shard 0; later shards have empty registers.
  assert.equal(shards[0]!.records.vendors.length, 1);
  for (let i = 1; i < shards.length; i++) assert.equal(shards[i]!.records.vendors.length, 0);
  // Every file appears exactly once across all shards.
  const ids = shards.flatMap((s) => s.records.files.map((f) => f.externalId)).sort();
  assert.deepEqual(ids, files.map((f) => f.externalId).sort());
  // Each shard is a valid v1 bundle.
  for (const s of shards) assert.equal(s.bundleVersion, 1);

  // A small export stays one bundle.
  const one = shardBundle(makeBundle('vanta', '0.0.0', { vendors: [], risks: [], people: [], policies: [], files: [mkFile(0, 10)] }, '2026-01-01T00:00:00.000Z'), 45 * 1024 * 1024);
  assert.equal(one.length, 1);
});

/* ------------------------------------------------------------------ *
 * Single-archive export
 * ------------------------------------------------------------------ */

/**
 * An independent ZIP reader for the tests: it walks the CENTRAL DIRECTORY (not
 * the writer's own bookkeeping), seeks to each declared local-header offset and
 * inflates from there. That is the path a real unzip implementation takes, so a
 * writer bug in offsets, sizes or signatures fails here rather than at a
 * customer's import.
 */
function readZip(buf: Buffer): { name: string; data: Buffer }[] {
  // End-of-central-directory: scan back for its signature (no comment, so it is
  // the last 22 bytes, but search anyway rather than assume the writer's layout).
  let eocd = -1;
  for (let i = buf.length - 22; i >= 0; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  assert.ok(eocd >= 0, 'archive has an end-of-central-directory record');
  const count = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);

  const out: { name: string; data: Buffer }[] = [];
  for (let i = 0; i < count; i++) {
    assert.equal(buf.readUInt32LE(p), 0x02014b50, 'central directory header signature');
    const method = buf.readUInt16LE(p + 10);
    const crc = buf.readUInt32LE(p + 16);
    const csize = buf.readUInt32LE(p + 20);
    const usize = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const localOffset = buf.readUInt32LE(p + 42);
    const name = buf.toString('utf8', p + 46, p + 46 + nameLen);
    assert.equal(method, 8, `${name} is deflated`);

    // Seek to the local header and inflate from just past it.
    assert.equal(buf.readUInt32LE(localOffset), 0x04034b50, 'local file header signature');
    const localNameLen = buf.readUInt16LE(localOffset + 26);
    const localExtraLen = buf.readUInt16LE(localOffset + 28);
    assert.equal(
      buf.toString('utf8', localOffset + 30, localOffset + 30 + localNameLen),
      name,
      'local and central names agree',
    );
    const start = localOffset + 30 + localNameLen + localExtraLen;
    const data = inflateRawSync(buf.subarray(start, start + csize));
    assert.equal(data.length, usize, `${name} inflates to its declared size`);
    assert.equal(crc32(data), crc, `${name} matches its declared CRC-32`);
    out.push({ name, data });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return out;
}

// The hand-written CRC-32 must agree with a known-good implementation. It is the
// one field an unzip tool checks byte-for-byte, so a table bug corrupts every
// archive silently until someone tries to extract one.
test('crc32 matches zlib for known vectors', () => {
  assert.equal(crc32(Buffer.from('')), 0);
  assert.equal(crc32(Buffer.from('123456789')), 0xcbf43926); // the standard check value
  const zlibCrc = (zlib as { crc32?: (b: Buffer) => number }).crc32;
  if (typeof zlibCrc === 'function') {
    for (const s of ['', 'a', 'keel-migrate', 'A'.repeat(10_000), 'éèê']) {
      assert.equal(crc32(Buffer.from(s)), zlibCrc(Buffer.from(s)), `crc32 differs for ${JSON.stringify(s.slice(0, 12))}`);
    }
  }
});

// The whole point of the archive: N shards go in, exactly N valid bundles come
// out, in a set the importer can prove is complete.
test('a sharded export archives to exactly its shards, each a valid bundle', () => {
  const mkFile = (i: number, kb: number): BundleFile => ({
    externalId: `f${i}`,
    kind: 'evidence',
    refExternalId: null,
    name: `f${i}.bin`,
    contentType: 'application/octet-stream',
    sizeBytes: kb * 1024,
    sha256: 'x'.repeat(64),
    contentBase64: 'A'.repeat(kb * 1024),
  });
  const files = Array.from({ length: 10 }, (_, i) => mkFile(i, 100));
  const bundle = makeBundle(
    'vanta',
    '0.0.0',
    {
      vendors: [{ externalId: 'v1', name: 'V' }],
      risks: [],
      people: [],
      policies: [],
      files,
    },
    '2026-01-01T00:00:00.000Z',
  );
  const shards = shardBundle(bundle, 250 * 1024);
  assert.ok(shards.length > 1, 'this fixture must actually shard');

  // Same composition the CLI performs.
  const zipBytes = zipSync(
    shards.map((s, i) => ({ name: shardFileName(i + 1), data: Buffer.from(JSON.stringify(s, null, 2)) })),
    new Date(bundle.exportedAt),
  );
  const entries = readZip(zipBytes);

  // Exactly the shards, named exactly like the loose files.
  assert.deepEqual(
    entries.map((e) => e.name),
    shards.map((_, i) => shardFileName(i + 1)),
  );

  // Every entry is itself a valid, complete v1 bundle.
  const parsed = entries.map((e) => JSON.parse(e.data.toString('utf8')) as MigrationBundle);
  for (const b of parsed) {
    assert.equal(b.bundleVersion, 1);
    assert.equal(b.source, 'vanta');
    assert.equal(b.exportedAt, bundle.exportedAt);
    assert.ok(Array.isArray(b.records.files));
  }

  // shardIndex/shardCount are correct, contiguous and 1-based.
  assert.deepEqual(
    parsed.map((b) => b.shardIndex),
    parsed.map((_, i) => i + 1),
  );
  for (const b of parsed) assert.equal(b.shardCount, parsed.length);
  const indices = new Set(parsed.map((b) => b.shardIndex));
  assert.equal(indices.size, parsed.length, 'no duplicate shardIndex');
  for (let i = 1; i <= parsed.length; i++) assert.ok(indices.has(i), `shard ${i} present`);

  // Nothing was lost on the way through the zip.
  const ids = parsed.flatMap((b) => b.records.files.map((f) => f.externalId)).sort();
  assert.deepEqual(ids, files.map((f) => f.externalId).sort());
  // Registers still ride on shard 1 only.
  assert.equal(parsed[0]!.records.vendors.length, 1);
  for (let i = 1; i < parsed.length; i++) assert.equal(parsed[i]!.records.vendors.length, 0);
});

// A small export must not change shape: one shard, one file, 1 of 1.
test('a single-shard export behaves as before', () => {
  const shards = shardBundle(
    makeBundle(
      'drata',
      '0.0.0',
      { vendors: [{ externalId: 'v1', name: 'V' }], risks: [], people: [], policies: [], files: [] },
      '2026-01-01T00:00:00.000Z',
    ),
    10 * 1024 * 1024,
  );
  assert.equal(shards.length, 1);
  assert.equal(shardFileName(1), 'migration-bundle.json');
  assert.equal(shards[0]!.shardIndex, 1);
  assert.equal(shards[0]!.shardCount, 1);
  assert.equal(shards[0]!.records.vendors.length, 1);
  // The shard fields are additive: the format is still version 1, and dropping
  // them leaves a bundle indistinguishable from one written before they existed.
  assert.equal(shards[0]!.bundleVersion, 1);
});

// The archive must be readable by something that is not us. `unzip -t` is the
// broadest available oracle for "this file is a real ZIP".
test('the archive passes an external unzip integrity check', (t) => {
  const zipBytes = zipSync([
    { name: 'migration-bundle.json', data: Buffer.from('{"bundleVersion":1}') },
    { name: 'migration-bundle-002.json', data: Buffer.from(JSON.stringify({ a: 'B'.repeat(5000) })) },
  ]);
  const path = join(tmpdir(), `keel-migrate-test-${process.pid}.zip`);
  writeFileSync(path, zipBytes);
  try {
    execFileSync('unzip', ['-t', path], { stdio: 'pipe' });
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    if (err.code === 'ENOENT') return t.skip('unzip not installed');
    throw e;
  } finally {
    rmSync(path, { force: true });
  }
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

// A single file too big for one shard can't be split (base64 lives in one JSON
// string), so it is skipped and reported as `oversized` - not admitted, which
// would produce an unimportable lone shard. Smaller files are unaffected.
test('fetchEvidenceDocuments skips files larger than maxInlineBytes', async () => {
  const http = new GuardedHttp({ allowedHosts: ['api.vanta.com'], tokenEndpoint: null });
  const realFetch = globalThis.fetch;
  const big = new Uint8Array(90_000); // ~120 KB once base64-encoded
  const small = new Uint8Array(3_000); // ~4 KB once base64-encoded
  globalThis.fetch = (async (url: string) =>
    new Response(String(url).includes('/1/') ? big : small, {
      status: 200,
      headers: { 'content-type': 'application/pdf' },
    })) as typeof fetch;
  try {
    // Cap admits the ~4 KB file but not the ~120 KB one.
    const { files, oversized, skipped } = await fetchEvidenceDocuments(
      http,
      [
        { externalId: 'd:1', mediaUrl: 'https://api.vanta.com/v1/documents/d/uploads/1/media' },
        { externalId: 'd:2', mediaUrl: 'https://api.vanta.com/v1/documents/d/uploads/2/media' },
      ],
      {},
      { maxInlineBytes: 50_000 },
    );
    assert.equal(files.length, 1, 'the small file is kept');
    assert.equal(files[0]!.externalId, 'd:2');
    assert.equal(oversized, 1, 'the over-cap file is skipped as oversized, not admitted');
    assert.equal(skipped, 0);
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
