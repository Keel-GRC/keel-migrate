# Contributing to keel-migrate

Contributions — especially new source adapters — are welcome. One rule is
non-negotiable, because it is the tool's legal and ethical foundation.

## Official, documented APIs only

Every adapter MUST use **only** the source platform's official, publicly
documented API, authenticated with **the customer's own credentials**, and it
MUST be **read-only**. Concretely:

- **No UI scraping.** Do not parse HTML pages, drive the web app, or automate the
  dashboard. Consume documented JSON REST endpoints only.
- **No undocumented endpoints.** Every endpoint an adapter calls must be listed in
  its `manifest.endpoints` with a link to the endpoint's official documentation.
- **No reverse engineering.** Do not decompile, inspect minified bundles, or
  probe for hidden endpoints to discover an API surface.
- **Read-only.** The only write an adapter may perform is the single OAuth token
  exchange declared as `manifest.tokenEndpoint`. Everything else is `GET`.
- **Allowlisted hosts.** An adapter may only contact hosts in
  `manifest.allowedHosts`. The guarded HTTP client (`src/http.ts`) enforces this
  and the read-only rule at runtime — a violation throws before any network call.

These constraints keep the tool squarely in the "data portability" lane: the
customer exports **their own data** using the vendor's **own supported API**. That
is what makes it defensible. A change that weakens any of the above will not be
merged.

## Adding a source adapter

1. Create `src/adapters/<source>.ts` exporting an `Adapter`.
2. Fill in the `AdapterManifest`: `source`, `displayName`, `officialDocsUrl`,
   `apiBase`, `allowedHosts`, `tokenEndpoint`, `scopes`, `credentialEnv`, and an
   `endpoints[]` entry (with `docUrl`) for **every** endpoint you read.
3. Map the source's objects into the neutral records in `src/bundle.ts`. Keep the
   untouched source object under `raw`. Be tolerant of missing/extra fields.
4. Register it in `src/registry.ts`.
5. Prefer capturing a redacted response-shape snapshot (field names + types, no
   values) so schema drift can be detected over time.

## Style

- No runtime dependencies. Node built-ins + global `fetch` only.
- TypeScript strict mode; `npm run typecheck` must pass.
- Do not add any feature that makes live calls to a large-language-model API or
  otherwise generates endpoints/requests dynamically — adapters are deterministic,
  human-authored, and reviewed.
