# keel-migrate

**Own your compliance data.** A small, open-source command-line tool that exports
your GRC data — vendors, risks, people, and policies — from platforms like Vanta
into a neutral, documented bundle you can take anywhere.

- **Runs on your machine.** Your API credentials never leave your computer and are
  never written to disk. The tool talks only to the source platform's own official
  API, over HTTPS, **read-only**.
- **Official APIs only.** Every source adapter is pinned to documented endpoints
  and an allowlisted host; the tool cannot call anything else and cannot write to
  the source system (see [CONTRIBUTING.md](./CONTRIBUTING.md)).
- **Vendor-neutral output.** You get plain `migration-bundle*.json` files in an
  open, documented format — one file for a typical export, several if your
  evidence library is large (plus a single zip of them, so a big export is still
  one upload). Import them wherever you like: [Keel](https://keelgrc.com) offers a
  one-click import, but the format isn't locked to any destination.

Maintained by [Keel](https://keelgrc.com). Not affiliated with or endorsed by any
source platform; product names are used only to identify the platform you are
exporting your own data from.

## Install & run

Requires Node.js 18.17+.

```bash
# clone the repo
git clone https://github.com/Keel-GRC/keel-migrate.git
cd keel-migrate

# from source (no build step needed)
npm install
npm run export -- --source vanta --out ./out

# or after building
npm run build
./dist/cli.js export --source vanta --out ./out
```

## Usage

```
keel-migrate export --source <name> --out <dir>
```

Credentials come from environment variables declared by each source adapter.

**Vanta** — create a **read-only** API client (scope `vanta-api.all:read`) in your
Vanta admin settings, then:

```bash
export VANTA_CLIENT_ID='vci_…'
export VANTA_CLIENT_SECRET='vcs_…'
keel-migrate export --source vanta --out ./out
```

**Drata** — create an API key in your Drata workspace (Settings → API keys). The
key is used **read-only** (the tool only issues GETs against Drata's Public API),
then:

```bash
export DRATA_API_KEY='…'
keel-migrate export --source drata --out ./out
```

Either writes `./out/migration-bundle.json`. A large export additionally writes
`migration-bundle-002.json`, `-003.json`, … and a single
`keel-migration-bundle.zip` containing all of them — see
[Large exports](#large-exports-sharding-and-the-single-archive).

## What it exports (v1)

| Record  | Fields (neutral) |
|---------|------------------|
| Vendors | name, website, criticality, status, review dates, notes |
| Risks   | title, description, likelihood/impact + residual, treatment, owner ref, status |
| People  | email, name, job title, active/inactive, groups |
| Policies| name, description, status, approval date, version, document URL |
| Files   | policy/evidence **documents** — the actual bytes, inlined (base64 + sha256) |

Each record keeps the untouched source object under `raw` for a lossless
round-trip. Both **policy documents** and **evidence documents** are downloaded
and inlined into the bundle (`records.files`, `kind: 'policy' | 'evidence'`)
when the source serves the bytes from the adapter's own allowlisted API host —
so you take the real files, not links that expire when you leave. For Vanta
that means evidence pulled from the documents API
(`GET /v1/documents/{id}/uploads/{id}/media`) travels with the bundle. Anything
served from an off-allowlist host (e.g. a signed CDN URL the adapter hasn't
declared) keeps its link instead of being pulled, so the guarded "official APIs
only" boundary stays intact.

One Vanta limitation to note: the policies API exposes only an `app.vanta.com`
UI link for the approved policy PDF (no downloadable file id), so those specific
policy PDFs remain a manual export. Evidence documents, which do have a media
download endpoint, are pulled automatically.

## Large exports: sharding and the single archive

Documents are inlined as base64, and because the destination reads each bundle
file whole (in a memory-bounded worker), a large evidence library is **split
across multiple importable bundle files** rather than dropped. Each file is kept
under a per-file cap (default **10 MB**, set with `--max-bundle-mb`):

- A small export stays a single `migration-bundle.json` — unchanged, and no zip.
- A large one also writes `migration-bundle-002.json`, `migration-bundle-003.json`,
  and so on. Registers (vendors/risks/people/policies) ride on the first file;
  the rest carry the remaining evidence. Every shard is itself a valid bundle.
- A large one **also writes `keel-migration-bundle.zip`**, containing every one of
  those files as a zip entry under the same names. Upload that one file and a
  destination that reads the archive imports all the parts for you.

The loose `.json` files are always written, archive or not: they are the
vendor-neutral artifact, readable with no zip tooling and importable one at a
time by any destination. The zip is a convenience layer over them.

Every shard carries `shardIndex` (1-based) and `shardCount`, so a destination can
prove it has the whole set before it writes anything — shard 2 on its own is a
perfectly valid bundle holding a third of your evidence and none of your
registers, and an importer with no way to notice that would report success. Both
fields are optional and additive: `bundleVersion` is still `1`, and a bundle
without them still imports.

| Flag | Effect |
|---|---|
| *(default)* | Zip written **only** when the export splits into more than one file. |
| `--archive` | Always write the zip, even for a single-file export. |
| `--no-archive` | Never write the zip. Loose `.json` files only. |

To import a multi-file export: upload `keel-migration-bundle.zip` once, or import
**each** `.json` file individually, in any order. Re-runs are idempotent (records
are matched by source id), so nothing is duplicated. (A direct-to-storage
streaming upload for very large sets, so bytes skip the bundle entirely, is on the
roadmap.)

**In Keel**, both `/import` and the admin importer accept either the `.zip` or a
single `.json`, up to the limit stated on the page. The archive path verifies the
shard set is complete and refuses the whole upload if it is not, rather than
importing part of it.

A single document larger than the per-file cap can't be split across shards (its
base64 lives in one JSON string), so it is **skipped and reported** rather than
written as a bundle no importer would accept: the record keeps its metadata (and,
for policies, its document link). Raise `--max-bundle-mb` to include such files,
keeping in mind the destination's own import limit.

## Sources

- ✅ **Vanta** (`--source vanta`) — OAuth client-credentials, read-only
- ✅ **Drata** (`--source drata`) — static API key, read-only
- 🧪 **OneTrust** (`--source onetrust`) — OAuth client-credentials against your own
  tenant host. Set `ONETRUST_HOSTNAME` (e.g. `yourco.my.onetrust.com`),
  `ONETRUST_CLIENT_ID`, `ONETRUST_CLIENT_SECRET`. Exports **users** and the **risk
  register** today; built to OneTrust's public API docs — validate against your
  tenant, and expect vendors/policies to follow once their per-tenant list paths
  are confirmed.
- 🚧 Secureframe and others — [contributions welcome](./CONTRIBUTING.md)

## The bundle format

`migration-bundle.json` is a documented, versioned interchange format
(`bundleVersion`). See [`src/bundle.ts`](./src/bundle.ts) for the schema. Adapters
absorb upstream API changes and keep emitting this stable shape, so importers
never break when a source platform changes.

`keel-migration-bundle.zip` is an ordinary ZIP (deflate, no ZIP64, no
encryption) whose entries are exactly those JSON files. It is produced by
[`src/archive.ts`](./src/archive.ts) using only Node's built-in `zlib` — this
tool has **zero runtime dependencies** and keeps it that way, because "nothing
but the standard library is in the loop" is a claim you can verify in one command
about a program you hand read-only API credentials.

## License

MIT — see [LICENSE](./LICENSE).
