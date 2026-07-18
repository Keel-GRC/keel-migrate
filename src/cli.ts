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
import { makeBundle } from './bundle.js';
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
  --source   Source platform to export from. Available: ${Object.keys(adapters).join(', ')}
  --out      Output directory for the bundle (default: ./keel-migrate-out)

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

  console.log(`Exporting from ${adapter.manifest.displayName} (read-only, official API)…`);
  const records = await adapter.export(creds, http);
  const bundle = makeBundle(sourceName, VERSION, records, new Date().toISOString());

  mkdirSync(outDir, { recursive: true });
  const outPath = join(outDir, 'migration-bundle.json');
  writeFileSync(outPath, JSON.stringify(bundle, null, 2));

  console.log(
    `\nDone. Wrote ${outPath}\n` +
      `  vendors:  ${bundle.counts.vendors}\n` +
      `  risks:    ${bundle.counts.risks}\n` +
      `  people:   ${bundle.counts.people}\n` +
      `  policies: ${bundle.counts.policies}\n` +
      `  files:    ${bundle.counts.files}  (policy + evidence documents, inlined)\n` +
      `\nPolicy and evidence documents served from the source's official API are\n` +
      `downloaded and inlined; any served from an off-allowlist host keep a link.\n` +
      `Import into your destination — in Keel: Admin → Data & migration → Import.`,
  );
}

main().catch((e) => fail(e instanceof Error ? e.message : String(e)));
