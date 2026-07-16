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
round-trip. Policy **documents** are downloaded and inlined into the bundle
(`records.files`) when the source serves them from the adapter's own
allowlisted API host — so you take the real PDFs, not links that expire when
you leave. Documents served from an off-allowlist host (e.g. a signed CDN URL
the adapter hasn't declared) keep their `documentUrl` link instead of being
pulled, so the guarded "official APIs only" boundary stays intact.

## Sources

- ✅ **Vanta** (`--source vanta`) — OAuth client-credentials, read-only
- ✅ **Drata** (`--source drata`) — static API key, read-only
- 🚧 Secureframe and others — [contributions welcome](./CONTRIBUTING.md)

## The bundle format

`migration-bundle.json` is a documented, versioned interchange format
(`bundleVersion`). See [`src/bundle.ts`](./src/bundle.ts) for the schema. Adapters
absorb upstream API changes and keep emitting this stable shape, so importers
never break when a source platform changes.

## License

MIT — see [LICENSE](./LICENSE).
