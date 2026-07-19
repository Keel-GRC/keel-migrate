#!/usr/bin/env node
/**
 * keel-migrate — export your GRC data to a portable bundle, from your own machine.
 *
 *   keel-migrate export --source vanta --out ./out
 *
 * Credentials are read from the source adapter's declared environment variables
 * (for Vanta: VANTA_CLIENT_ID, VANTA_CLIENT_SECRET) and are never written to disk
 * or transmitted anywhere except the source's own official API. Read-only.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { GuardedHttp } from './http.js';
import { resolvePolicy } from './adapter.js';
import { makeBundle, shardBundle } from './bundle.js';
import { adapters } from './registry.js';

const VERSION = '0.1.0';

function fail(msg: string): never {
  console.error(`\nError: ${msg}\n`);
  process.exit(1);
}

function usage(): void {
  console.log(`keel-migrate ${VERSION} — portable GRC data export

Usage:
  keel-migrate export --source <name> --out <dir>

Options:
  --source          Source platform to export from. Available: ${Object.keys(adapters).join(', ')}
  --out             Output directory for the bundle (default: ./keel-migrate-out)
  --max-bundle-mb   Per-file size cap in MB (default: 10). A large export is split
                    into multiple importable bundle files under this size; nothing
                    is dropped. Import each file into your destination. The default
                    is sized to import cleanly through a memory-bounded worker;
                    raise it only if your destination can take larger uploads.

Credentials come from environment variables declared by the source adapter.
For Vanta: export VANTA_CLIENT_ID and VANTA_CLIENT_SECRET (read-only OAuth client).

Everything runs locally. The tool only contacts the source's official API over
HTTPS, read-only, and writes a single migration-bundle.json you can import
wherever you like.`);
}

async function main(): Promise<void> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      source: { type: 'string' },
      out: { type: 'string' },
      'max-bundle-mb': { type: 'string' },
      help: { type: 'boolean', short: 'h' },
    },
  });

  const command = positionals[0];
  if (values.help || !command) return usage();
  if (command !== 'export') fail(`Unknown command "${command}". Try: keel-migrate export --source <name> --out <dir>`);

  const sourceName = values.source;
  if (!sourceName) fail('Missing --source. Available: ' + Object.keys(adapters).join(', '));
  const adapter = adapters[sourceName];
  if (!adapter) fail(`Unknown source "${sourceName}". Available: ${Object.keys(adapters).join(', ')}`);

  const creds: Record<string, string> = {};
  const missing: string[] = [];
  for (const name of adapter.manifest.credentialEnv) {
    const v = process.env[name];
    if (!v) missing.push(name);
    else creds[name] = v;
  }
  if (missing.length) fail(`Set these environment variables first: ${missing.join(', ')}`);

  const outDir = values.out || './keel-migrate-out';
  const http = new GuardedHttp(resolvePolicy(adapter.manifest, process.env));

  // Per-shard size cap for inlined document bytes. Each output file is kept under
  // this so it stays importable through the destination's memory-bounded worker.
  // 10 MB is a conservative default: a bundle is read whole and JSON-parsed in the
  // importer's Worker (peak memory ~2x the file), so larger shards risk an
  // out-of-memory crash that surfaces as a generic "temporary error" on import.
  let maxShardBytes = 10 * 1024 * 1024;
  if (values['max-bundle-mb'] != null) {
    const mb = Number(values['max-bundle-mb']);
    if (!Number.isFinite(mb) || mb <= 0) fail('--max-bundle-mb must be a positive number.');
    maxShardBytes = Math.round(mb * 1024 * 1024);
  }

  console.log(`Exporting from ${adapter.manifest.displayName} (read-only, official API)…`);
  const records = await adapter.export(creds, http);
  const bundle = makeBundle(sourceName, VERSION, records, new Date().toISOString());

  // Split into independently-importable shards so a large evidence library moves
  // in full without any single file exceeding the import limit. Small exports
  // stay a single migration-bundle.json.
  const shards = shardBundle(bundle, maxShardBytes);

  mkdirSync(outDir, { recursive: true });
  const written: { path: string; sizeMb: string; files: number }[] = [];
  for (let i = 0; i < shards.length; i++) {
    const name = i === 0 ? 'migration-bundle.json' : `migration-bundle-${String(i + 1).padStart(3, '0')}.json`;
    const outPath = join(outDir, name);
    let serialized: string;
    try {
      serialized = JSON.stringify(shards[i], null, 2);
    } catch {
      fail(
        'A shard was too large to write as a single JSON file (it exceeded the runtime string ' +
          'limit). Re-run with a smaller --max-bundle-mb.',
      );
    }
    writeFileSync(outPath, serialized);
    written.push({
      path: outPath,
      sizeMb: (Buffer.byteLength(serialized) / (1024 * 1024)).toFixed(1),
      files: shards[i]!.counts.files,
    });
  }

  const fileList = written.map((w) => `  ${w.path} (${w.sizeMb} MB, ${w.files} files)`).join('\n');
  const multi = written.length > 1;
  console.log(
    `\nDone. Wrote ${written.length} bundle file${multi ? 's' : ''}:\n${fileList}\n\n` +
      `  vendors:  ${bundle.counts.vendors}\n` +
      `  risks:    ${bundle.counts.risks}\n` +
      `  people:   ${bundle.counts.people}\n` +
      `  policies: ${bundle.counts.policies}\n` +
      `  files:    ${bundle.counts.files}  (policy + evidence documents, inlined)\n` +
      `\nPolicy and evidence documents served from the source's official API are\n` +
      `downloaded and inlined; any served from an off-allowlist host keep a link.\n` +
      (multi
        ? `\nThis export was split into ${written.length} files to stay under the import size\n` +
          `limit. Import EACH file into your destination (any order; re-runs are idempotent).\n`
        : '') +
      `Import into your destination — in Keel: Admin → Data & migration → Import.`,
  );
}

main().catch((e) => fail(e instanceof Error ? e.message : String(e)));
