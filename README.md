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
- **Vendor-neutral output.** You get one `migration-bundle.json` in an open format.
  Import it wherever you like — [Keel](https://keelgrc.com) offers a one-click
  import, but the format is documented so it isn't locked to any destination.

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

Either writes `./out/migration-bundle.json`.

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

Because every document is inlined as base64 into a single JSON file that the
destination reads whole, the total inlined bytes are capped (default **45 MB**,
set with `--max-bundle-mb`). This keeps the bundle serializable and importable;
documents beyond the cap are left out and reported at the end of the run. If you
have a large evidence library, raise the cap or export in stages. (A streamed,
multi-part transport for very large evidence sets is on the roadmap.)

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

## License

MIT — see [LICENSE](./LICENSE).
