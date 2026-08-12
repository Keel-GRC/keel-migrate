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
import { makeBundle, shardBundle, shardFileName, ARCHIVE_FILE_NAME } from './bundle.js';
import { ZipBuilder } from './archive.js';
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
                    is dropped. The default is sized to import cleanly through a
                    memory-bounded worker; raise it only if your destination can
                    take larger uploads.
  --archive         Also write ${ARCHIVE_FILE_NAME}, one zip containing every
                    bundle file, so a split export is a single upload. ON by
                    default when the export splits; use --archive to force it for
                    a single-file export too.
  --no-archive      Never write the zip. Loose .json files only.

Credentials come from environment variables declared by the source adapter.
For Vanta: export VANTA_CLIENT_ID and VANTA_CLIENT_SECRET (read-only OAuth client).

Everything runs locally. The tool only contacts the source's official API over
HTTPS, read-only, and writes plain JSON bundle files (plus, for a split export,
a zip of them) that you can import wherever you like.`);
}

async function main(): Promise<void> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      source: { type: 'string' },
      out: { type: 'string' },
      'max-bundle-mb': { type: 'string' },
      // Node's parseArgs has no built-in --no-<flag> negation, so the opt-out is
      // declared as its own boolean rather than silently erroring as unknown.
      archive: { type: 'boolean' },
      'no-archive': { type: 'boolean' },
      help: { type: 'boolean', short: 'h' },
    },
  });

  const command = positionals[0];
  if (values.help || !command) return usage();
  if (values.archive && values['no-archive']) fail('Pass either --archive or --no-archive, not both.');
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
  // Pass the per-shard cap so adapters that inline documents skip any single file
  // too big to fit an importable shard (it can't be split), rather than emitting
  // an unimportable lone shard. A large *library* still shards across many files.
  const records = await adapter.export(creds, http, { maxInlineBytes: maxShardBytes });
  const bundle = makeBundle(sourceName, VERSION, records, new Date().toISOString());

  // Split into independently-importable shards so a large evidence library moves
  // in full without any single file exceeding the import limit. Small exports
  // stay a single migration-bundle.json.
  const shards = shardBundle(bundle, maxShardBytes);

  const multi = shards.length > 1;
  // Archive policy, and why it is this and not something tidier:
  //
  //  - Default ON only when the export actually splits. A single-file export has
  //    nothing to bundle up, and wrapping migration-bundle.json in a zip would
  //    make the common case worse: an extra step for the customer and an extra
  //    format for every non-Keel destination to understand.
  //  - The loose .json files are ALWAYS written, archive or not. They are the
  //    vendor-neutral artifact this tool promises — readable with no zip tooling,
  //    diffable, greppable, and importable one at a time by a destination that
  //    has never heard of our archive. The zip is a convenience layer over them,
  //    not a replacement for them, and quietly withdrawing the plain-JSON output
  //    the moment an export grows past 10 MB would be a lock-in move in a tool
  //    whose entire point is portability.
  //  - The cost is transient duplicate disk on the customer's own machine.
  //    `--no-archive` opts out for anyone who minds; `--archive` forces the zip
  //    for a single-file export (useful when a destination only takes archives).
  const writeArchive = values.archive === true || (multi && values['no-archive'] !== true);

  mkdirSync(outDir, { recursive: true });
  // Deflate each shard as it is written so only the compressed copy is retained;
  // the JSON string is released before the next shard is serialized. A bundle is
  // mostly base64 of already-compressed documents, so the retained bytes are
  // roughly the size of the underlying files rather than of the JSON.
  const zip = writeArchive ? new ZipBuilder(new Date(bundle.exportedAt)) : null;
  const written: { path: string; sizeMb: string; files: number }[] = [];
  for (let i = 0; i < shards.length; i++) {
    const name = shardFileName(i + 1);
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
    if (zip) zip.add(name, Buffer.from(serialized, 'utf8'));
    written.push({
      path: outPath,
      sizeMb: (Buffer.byteLength(serialized) / (1024 * 1024)).toFixed(1),
      files: shards[i]!.counts.files,
    });
  }

  let archivePath: string | null = null;
  let archiveMb = '0.0';
  if (zip) {
    archivePath = join(outDir, ARCHIVE_FILE_NAME);
    let bytes: Buffer;
    try {
      bytes = zip.finish();
    } catch (e) {
      fail(e instanceof Error ? e.message : String(e));
    }
    writeFileSync(archivePath, bytes);
    archiveMb = (bytes.length / (1024 * 1024)).toFixed(1);
  }

  const fileList = written.map((w) => `  ${w.path} (${w.sizeMb} MB, ${w.files} files)`).join('\n');
  console.log(
    `\nDone. Wrote ${written.length} bundle file${multi ? 's' : ''}:\n${fileList}\n` +
      (archivePath ? `\n  ${archivePath} (${archiveMb} MB, all ${written.length} of the above)\n` : '') +
      `\n  vendors:  ${bundle.counts.vendors}\n` +
      `  risks:    ${bundle.counts.risks}\n` +
      `  people:   ${bundle.counts.people}\n` +
      `  policies: ${bundle.counts.policies}\n` +
      `  files:    ${bundle.counts.files}  (policy + evidence documents, inlined)\n` +
      `\nPolicy and evidence documents served from the source's official API are\n` +
      `downloaded and inlined; any served from an off-allowlist host keep a link.\n` +
      (multi
        ? `\nThis export was split into ${written.length} files to stay under the import size limit.\n` +
          (archivePath
            ? `Upload ${ARCHIVE_FILE_NAME} once — a destination that reads the archive\n` +
              `imports every part in order and checks the set is complete first. Destinations\n` +
              `that take plain JSON can still import each .json file individually, in any\n` +
              `order (re-runs are idempotent).\n`
            : `Import EACH file into your destination (any order; re-runs are idempotent).\n`)
        : '') +
      `Import into your destination — in Keel: Admin → Data & migration → Import.`,
  );
}

main().catch((e) => fail(e instanceof Error ? e.message : String(e)));
