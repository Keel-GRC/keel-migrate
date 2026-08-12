/**
 * Hyperproof adapter. Reads the official, published Hyperproof API and maps it
 * into the neutral migration bundle.
 *
 * Docs: https://developer.hyperproof.app/
 * Machine-readable specs: Hyperproof publishes ONE OpenAPI 3.0.1 document per
 * resource rather than a single combined spec. Every path, query parameter and
 * response field used below was read out of those documents — Vendors API,
 * Risks API, Users API, Policies API, Policy Versions API and Proof API — not
 * inferred. Note each resource spec's `servers` entry already includes the
 * resource segment (e.g. `https://api.hyperproof.app/v1/vendors`), so the spec's
 * `GET /` is this adapter's `GET /v1/vendors`.
 *
 * Auth is OAuth 2.0 client credentials against a single token URL
 * (`https://accounts.hyperproof.app/oauth/token`, declared identically in all six
 * specs), then `Authorization: Bearer <jwt>`. The token is org-scoped: no spec
 * declares an organization/tenant path segment, query parameter or header on any
 * of these endpoints, so the adapter needs only a client id and secret — there is
 * no org id to ask the customer for. Read-only: the only write is the token
 * exchange, and the guarded client permits a POST to nowhere else.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * WHAT THIS ADAPTER CAN AND CANNOT GET, STATED PLAINLY
 *
 * 1. EVIDENCE BYTES *ARE* REACHABLE — this is the reason to prefer this adapter.
 *    `GET /v1/proof/{proofId}/contents` is documented to return the proof file
 *    itself (a wildcard content type with `schema: { type: string, format: binary }`) on
 *    api.hyperproof.app, which is already on the allowlist. So a customer's
 *    evidence library travels inside the bundle as real bytes rather than as
 *    links that die the day they stop paying Hyperproof.
 *
 * 2. POLICY DOCUMENT BYTES ARE NOT. A Policy carries `effectiveDocumentId` and a
 *    PolicyVersion carries `documentId`, but NO documented endpoint turns either
 *    id into bytes. It is tempting to assume a document id is a proof id and call
 *    `/v1/proof/{id}/contents` with it; that is a guess, and a guess that 404s (or
 *    worse, silently returns some other org object) is exactly what this project
 *    refuses to ship. Policies therefore export with metadata and, where the
 *    version publishes one, a `publishedUrl`/`shareLink` fallback link — and no
 *    inlined file. If Hyperproof documents a document-contents endpoint, wiring it
 *    up here is a few lines.
 *
 * 3. ONLY PROOF IS PAGINATED. `GET /v1/proof` documents `limit` (default 25, max
 *    500) and `nextToken`, and is walked properly below with a repeat-token guard
 *    so a server that keeps handing back the same token can never spin forever.
 *    Vendors, risks, users, policies and policy versions declare NO paging
 *    parameters and return a bare JSON array with no envelope, no total and no
 *    cursor — there is nothing to page with and nothing to compare against. The
 *    adapter does not pretend otherwise: it reads the array and then checks
 *    whether the row count landed exactly on one of Hyperproof's own page sizes
 *    (25 and 500 are the documented default and maximum on the one endpoint that
 *    does page) or another common cap. That is the only observable signal of a
 *    silent server-side limit on an unpaginated endpoint, and hitting it produces
 *    a loud INCOMPLETE warning rather than a partial export that looks whole.
 *
 * 4. REGIONS: US ONLY, DELIBERATELY. The specs list EU (`api.hyperproof.eu`) and
 *    GovCloud (`api.hyperproofgov.app`) servers alongside the US host, and every
 *    one of them declares the SAME US token URL (`accounts.hyperproof.app`) —
 *    which is very likely wrong for at least the GovCloud deployment and is not
 *    something we can verify without a tenant in that region. On top of that, the
 *    CLI treats every entry in `credentialEnv` as mandatory, so adding a region
 *    selector there would force every US customer to set a variable they do not
 *    need. Shipping US-only is the honest position: an EU/Gov customer gets a
 *    clear allowlist refusal rather than a half-working export. Adding a region
 *    later means allowlisting the two hosts, confirming their token URL, and
 *    selecting the base — a small change, once someone can actually test it.
 */
import type { Adapter, AdapterManifest, ExportOptions } from '../adapter.js';
import type { GuardedHttp } from '../http.js';
import { fetchEvidenceDocuments, type EvidenceRef } from '../files.js';
import type {
  BundleRecords,
  BundleVendor,
  BundleRisk,
  BundlePerson,
  BundlePolicy,
  Criticality,
} from '../bundle.js';

const API_BASE = 'https://api.hyperproof.app';
const TOKEN_ENDPOINT = 'https://accounts.hyperproof.app/oauth/token';
/**
 * Only the documentation root is cited. Hyperproof does publish per-resource
 * pages (e.g. /hyperproof-api/vendors/vendors.openapi.md), but a link that has
 * rotted into the wrong page is worse than one that is merely general, and the
 * root is the URL that was actually verified.
 */
const DOCS = 'https://developer.hyperproof.app/';

/** Documented maximum for `GET /v1/proof?limit=` (default is 25). */
const PROOF_PAGE_SIZE = 500;
/** Bound the proof walk so a misbehaving cursor can never loop forever. */
const MAX_PAGES = 500;

/**
 * Row counts that most likely mean "the server capped you", not "that is all
 * there is". 25 and 500 are Hyperproof's own documented default and maximum page
 * size on `/v1/proof`; the rest are the usual suspects. See point 3 in the header.
 */
const LIKELY_PAGE_CAPS = new Set([25, 50, 100, 200, 250, 500, 1000]);

export const manifest: AdapterManifest = {
  source: 'hyperproof',
  displayName: 'Hyperproof',
  officialDocsUrl: DOCS,
  apiBase: API_BASE,
  allowedHosts: ['api.hyperproof.app', 'accounts.hyperproof.app'],
  tokenEndpoint: TOKEN_ENDPOINT,
  // Read scopes only — the update scopes (vendor.update, risk.update, …) exist and
  // are deliberately not requested.
  scopes: [
    'vendor.read',
    'risk.read',
    'user.read',
    'policy.read',
    'policyversion.read',
    'proof.read',
  ],
  credentialEnv: ['HYPERPROOF_CLIENT_ID', 'HYPERPROOF_CLIENT_SECRET'],
  endpoints: [
    { path: '/v1/vendors', docUrl: DOCS },
    { path: '/v1/risks', docUrl: DOCS },
    { path: '/v1/users', docUrl: DOCS },
    { path: '/v1/policies', docUrl: DOCS },
    { path: '/v1/policyversions', docUrl: DOCS },
    { path: '/v1/proof', docUrl: DOCS },
    // The documented binary download — the one that makes evidence portable.
    { path: '/v1/proof/{proofId}/contents', docUrl: DOCS },
  ],
};

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * Read one of the unpaginated list endpoints, which return a bare JSON array.
 *
 * There is no cursor, no page parameter and no total to reconcile against, so
 * "did we get everything?" is genuinely unanswerable from the response alone.
 * What we can do is refuse to be quietly wrong: if the row count lands exactly on
 * a plausible server-side page size, say so in the loudest terms available.
 */
async function listArray<T>(
  http: GuardedHttp,
  auth: Record<string, string>,
  url: string,
  label: string,
): Promise<T[]> {
  const body = await http.getJson<T[]>(url, auth);
  if (!Array.isArray(body)) {
    // Not a shape any of these specs describe. Failing loudly beats exporting an
    // empty register that reads as "this customer had no vendors".
    throw new Error(
      `Hyperproof returned a non-array response for ${label} (${url}). The export was stopped ` +
        `rather than record zero ${label}.`,
    );
  }
  if (LIKELY_PAGE_CAPS.has(body.length)) {
    console.warn(
      `WARNING: ${label} returned exactly ${body.length} records — a common server-side page ` +
        `size. Hyperproof documents NO pagination for this endpoint (no page, limit or cursor ` +
        `parameter, and no total in the response), so this export may be INCOMPLETE and there ` +
        `is no way to tell from the API. Check the ${label} count in the Hyperproof UI before ` +
        `you migrate; if it is higher than ${body.length}, ask Hyperproof support for a paged ` +
        `or bulk export of ${label}.`,
    );
  }
  return body;
}

/**
 * Walk `GET /v1/proof` — the ONE Hyperproof endpoint that documents pagination
 * (`limit` + `nextToken`, response `{ data, nextToken }`).
 *
 * The token is verified rather than trusted: if the server returns a token it has
 * already given us, it is not advancing, so we stop and report the truncation
 * instead of looping. Same for exhausting MAX_PAGES with a token still pending.
 */
async function listProof(http: GuardedHttp, auth: Record<string, string>): Promise<any[]> {
  const out: any[] = [];
  const seenTokens = new Set<string>();
  let nextToken: string | undefined;

  for (let page = 0; page < MAX_PAGES; page++) {
    const url = new URL(`${API_BASE}/v1/proof`);
    url.searchParams.set('limit', String(PROOF_PAGE_SIZE));
    if (nextToken) url.searchParams.set('nextToken', nextToken);
    const j = await http.getJson<{ data?: any[]; nextToken?: string }>(url.toString(), auth);
    out.push(...(j.data ?? []));

    const token = j.nextToken;
    if (!token) return out;
    if (seenTokens.has(token)) {
      console.warn(
        `WARNING: Hyperproof kept returning the same proof pagination token after ${out.length} ` +
          `record(s), so the evidence list could not be advanced. This evidence export is ` +
          `INCOMPLETE. Re-run the export (imports are idempotent) and, if it repeats, ask ` +
          `Hyperproof support for a bulk proof export.`,
      );
      return out;
    }
    seenTokens.add(token);
    nextToken = token;
  }

  console.warn(
    `WARNING: stopped after ${MAX_PAGES} pages of proof (${out.length} records) with more still ` +
      `pending. This evidence export is INCOMPLETE.`,
  );
  return out;
}

const str = (v: unknown): string | null => {
  const s = typeof v === 'string' ? v.trim() : '';
  return s ? s : null;
};

/** Keep only an absolute HTTPS link; Hyperproof's own example is `www.hyperproof.io`. */
const httpsUrl = (v: unknown): string | null => {
  const s = str(v);
  return s && /^https:\/\//i.test(s) ? s : null;
};

/**
 * VendorRiskLevel is `notSet | veryHigh | high | moderate | low | veryLow` — six
 * tokens onto the bundle's four. `veryHigh` is the top of Hyperproof's scale, so
 * it maps to `critical`; `veryLow` and `low` both land on `low` (the bundle has no
 * fifth step below it, and inventing one would misrepresent the source).
 */
function toCriticality(v: unknown): Criticality | null {
  switch (str(v)) {
    case 'veryHigh':
      return 'critical';
    case 'high':
      return 'high';
    case 'moderate':
      return 'medium';
    case 'low':
    case 'veryLow':
      return 'low';
    // 'notSet', absent, or anything unrecognised → no claim.
    default:
      return null;
  }
}

/**
 * Hyperproof risk likelihood/impact are `*Level` fields: 0-BASED INDICES into the
 * risk register's own `customRiskScales` arrays. The scale is per-register and can
 * have any number of steps, and its `value` numbers are arbitrary (the documented
 * example is 1/2/5/8/10 — they exist so `likelihoodValue × impactValue` produces
 * the register's inherentRisk figure, and are NOT a 1–5 severity).
 *
 * So the meaning we can honestly carry across is the ORDINAL POSITION within the
 * scale, rescaled onto the bundle's 1–5. A 5-step scale maps 0→1 … 4→5 exactly;
 * a 3-step scale maps 0→1, 1→3, 2→5.
 *
 * When the response omits `customRiskScales`, the number of steps is unknown, so
 * this returns null rather than assuming five and coercing a number that would
 * look like evidence.
 */
function levelToFive(level: unknown, scale: unknown): number | null {
  if (!Array.isArray(scale) || scale.length < 2) return null;
  if (typeof level !== 'number' || !Number.isInteger(level)) return null;
  if (level < 0 || level >= scale.length) return null;
  return 1 + Math.round((level * 4) / (scale.length - 1));
}

export const hyperproofAdapter: Adapter = {
  manifest,
  async export(creds, http, opts: ExportOptions = {}): Promise<BundleRecords> {
    const clientId = creds.HYPERPROOF_CLIENT_ID;
    const clientSecret = creds.HYPERPROOF_CLIENT_SECRET;
    if (!clientId) throw new Error('HYPERPROOF_CLIENT_ID is required.');
    if (!clientSecret) throw new Error('HYPERPROOF_CLIENT_SECRET is required.');

    // The specs declare a plain OAuth 2.0 clientCredentials flow and document no
    // JSON body for it, so the request is form-encoded per RFC 6749 §4.4 — the
    // encoding the grant is specified with — rather than a guess at a JSON shape.
    const token = (
      await http.postToken<{ access_token?: string }>(
        TOKEN_ENDPOINT,
        {
          grant_type: 'client_credentials',
          client_id: clientId,
          client_secret: clientSecret,
          scope: manifest.scopes.join(' '),
        },
        { form: true },
      )
    ).access_token;
    if (!token) {
      throw new Error('Hyperproof returned no access token — check the client id and secret.');
    }
    const auth = { Authorization: `Bearer ${token}` };

    // `status` is a documented query parameter on /v1/risks ("Comma separated list
    // of statuses… Supported values: active, archived") and the endpoint returns
    // ONLY active risks by default. A retired-but-recorded risk is still part of
    // the register a customer is moving, so both are requested; the status rides
    // through onto each bundle record.
    const risksUrl = new URL(`${API_BASE}/v1/risks`);
    risksUrl.searchParams.set('status', 'active,archived');
    // Likewise `includeDeactivated` on /v1/users: an offboarded person is exactly
    // who an access-review history needs, so they are exported (marked inactive)
    // rather than silently missing.
    const usersUrl = new URL(`${API_BASE}/v1/users`);
    usersUrl.searchParams.set('includeDeactivated', 'true');

    const [rawVendors, rawRisks, rawUsers, rawPolicies] = await Promise.all([
      listArray<any>(http, auth, `${API_BASE}/v1/vendors`, 'vendors'),
      listArray<any>(http, auth, risksUrl.toString(), 'risks'),
      listArray<any>(http, auth, usersUrl.toString(), 'users'),
      listArray<any>(http, auth, `${API_BASE}/v1/policies`, 'policies'),
    ]);

    // A risk's owner is a bare uuid. Resolve it to an email where the users list
    // can — a destination can match a person by email and cannot by Hyperproof's
    // internal id. The map is keyed on BOTH id fields the User schema carries
    // (`id`, the org-user id, and `userId`, the cross-org identity) because the
    // Risk spec says only "the unique identifier for the user"; both keys point at
    // the same person, so an ambiguous lookup cannot resolve to the wrong one.
    const emailById = new Map<string, string>();
    for (const u of rawUsers) {
      const email = str(u?.email);
      if (!email) continue;
      for (const key of [u?.id, u?.userId]) {
        const k = str(key);
        if (k) emailById.set(k, email);
      }
    }

    // Policy versions carry the lifecycle dates and the published link; they hang
    // off a policy via the documented `?policyId=` query parameter, one call each.
    const policies: BundlePolicy[] = [];
    for (const p of rawPolicies) {
      const id = str(p?.id);
      if (!id) continue;
      const url = new URL(`${API_BASE}/v1/policyversions`);
      url.searchParams.set('policyId', id);
      let versions: any[] = [];
      try {
        versions = await listArray<any>(http, auth, url.toString(), `versions of policy ${id}`);
      } catch (e) {
        // One policy's version history failing must not sink an export whose
        // registers already succeeded — the policy still exports, without dates.
        console.warn(
          `Could not read policy versions for "${p?.name ?? id}" ` +
            `(${e instanceof Error ? e.message : String(e)}). The policy is exported without its ` +
            `version dates or published link.`,
        );
      }
      policies.push(mapPolicy(p, pickCurrentVersion(versions)));
    }

    // People with no email cannot be matched by any destination and the bundle
    // requires one (Hyperproof service accounts frequently have none). Drop them,
    // and say how many, so the count is never a silent discrepancy.
    const people = rawUsers.map(mapPerson).filter((p): p is BundlePerson => p !== null);
    const droppedPeople = rawUsers.length - people.length;
    if (droppedPeople > 0) {
      console.warn(
        `${droppedPeople} Hyperproof user(s) had no email address on the API response and were ` +
          `not exported (a person record without an email cannot be matched on import). ` +
          `Service accounts are the usual cause.`,
      );
    }

    // Evidence: list proof metadata, then pull each file's bytes from the
    // documented /contents endpoint on the already-allowlisted API host.
    const refs = collectProofRefs(await listProof(http, auth));
    const evidence = await fetchEvidenceDocuments(http, refs, auth, {
      maxInlineBytes: opts.maxInlineBytes,
    });
    if (evidence.skipped > 0) {
      console.warn(
        `${evidence.skipped} proof file(s) could not be downloaded and are not in the bundle. ` +
          `Their metadata is not exported either — a file record without bytes is not evidence.`,
      );
    }
    if (evidence.oversized > 0) {
      console.warn(
        `${evidence.oversized} proof file(s) exceeded the per-file import cap and were skipped. ` +
          `Raise --max-bundle-mb to include them.`,
      );
    }

    return {
      vendors: rawVendors.map(mapVendor),
      risks: rawRisks.map((r) => mapRisk(r, emailById)),
      people,
      policies,
      files: evidence.files,
    };
  },
};

/**
 * The version a migrating customer means by "the policy": the effective one, or
 * failing that the most recently approved. Deleted/archived versions are ignored.
 */
function pickCurrentVersion(versions: any[]): any | null {
  const live = versions.filter((v) => {
    const s = str(v?.status);
    return s === null || s === 'active';
  });
  if (live.length === 0) return null;
  const when = (v: any): number => {
    const t = Date.parse(v?.effectiveDate ?? v?.approvedDate ?? v?.updatedOn ?? v?.createdOn ?? '');
    return Number.isFinite(t) ? t : 0;
  };
  const effective = live.filter((v) => str(v?.revisionStatus) === 'effective');
  const pool = effective.length > 0 ? effective : live;
  return pool.reduce((best, v) => (when(v) >= when(best) ? v : best), pool[0]);
}

function mapVendor(v: any): BundleVendor {
  const notes = [
    str(v?.category) ? `Category: ${v.category}` : null,
    str(v?.contractStartDate) || str(v?.contractEndDate)
      ? `Contract: ${str(v?.contractStartDate) ?? '?'} → ${str(v?.contractEndDate) ?? '?'}`
      : null,
    str(v?.freshAsOfNote),
    str(v?.riskLevelOverrideReasoning)
      ? `Risk level overridden: ${v.riskLevelOverrideReasoning}`
      : null,
  ]
    .filter(Boolean)
    .join('\n\n');

  // ObjectStatus (active/archived/deleted/…) is the record's lifecycle;
  // VendorStatus (preassessment/approved/active/inactive/expired/rejected) is the
  // relationship. A non-active lifecycle wins, because "deleted" outranks
  // "approved". `notSet` is dropped rather than exported as a value.
  const objectStatus = str(v?.status);
  const vendorStatus = str(v?.vendorStatus);
  const status =
    objectStatus && objectStatus !== 'active'
      ? objectStatus
      : vendorStatus && vendorStatus !== 'notSet'
        ? vendorStatus
        : objectStatus;

  return {
    externalId: String(v?.id),
    name: str(v?.name) ?? 'Imported vendor',
    // The Vendor schema has no website/url/domain field at all — there is nothing
    // to map here, so nothing is invented.
    website: null,
    // assessedRiskLevel is documented as the INHERENT risk (from the latest vendor
    // questionnaire); riskLevel is the RESIDUAL risk after linked-control
    // mitigation. Both are kept rather than collapsed into one number.
    criticality: toCriticality(v?.assessedRiskLevel),
    residualCriticality: toCriticality(v?.riskLevel),
    status,
    // `freshAsOfDate` is the date the vendor was last marked fresh — the closest
    // documented thing to a completed review.
    reviewLastAt: str(v?.freshAsOfDate),
    // There is no next-review date on a Hyperproof vendor. `freshForDuration` is an
    // ISO-8601 duration, and adding it to freshAsOfDate would be our arithmetic
    // presented as the customer's schedule, so it stays out.
    reviewNextAt: null,
    notes: notes || null,
    raw: v,
  };
}

function mapRisk(r: any, emailById: Map<string, string>): BundleRisk {
  const scales = r?.customRiskScales ?? {};
  const ownerId = str(r?.ownerId);
  const response = str(r?.response);
  return {
    externalId: String(r?.id),
    title: String(str(r?.name) ?? str(r?.riskIdentifier) ?? 'Imported risk').slice(0, 200),
    description: str(r?.description),
    category: str(r?.category),
    likelihood: levelToFive(r?.likelihoodLevel, scales.likelihood),
    impact: levelToFive(r?.impactLevel, scales.impact),
    // residual*Level is documented as "the USER-OVERRIDDEN residual … level", and
    // the paired override flag says whether it means anything. Without the flag
    // set, the field is not a residual score, so it is not read as one. (The
    // calculated residuals Hyperproof does expose — actualLikelihood/actualImpact
    // — are raw scale values, not levels, and there is no documented way back from
    // a value to a scale position when the value falls between steps. They stay in
    // `raw` rather than being reverse-engineered.)
    residualLikelihood:
      r?.overrideResidualLikelihood === true
        ? levelToFive(r?.residualLikelihoodLevel, scales.likelihood)
        : null,
    residualImpact:
      r?.overrideResidualImpact === true
        ? levelToFive(r?.residualImpactLevel, scales.impact)
        : null,
    // RiskResponse is mitigate|accept|transfer|avoid|notSet.
    treatment: response && response !== 'notSet' ? response : null,
    ownerRef: (ownerId ? emailById.get(ownerId) : null) ?? ownerId,
    // ObjectStatus (active/archived/…). riskStage (proposed/evaluating/approved/
    // operating) is a different axis and stays in `raw`.
    status: str(r?.status),
    raw: r,
  };
}

/**
 * Returns null when the user has no email — see the caller, which counts the drop.
 */
function mapPerson(u: any): BundlePerson | null {
  const email = str(u?.email);
  if (!email) return null;
  const type = str(u?.type) ?? '';
  const objectStatus = str(u?.status);
  return {
    externalId: String(u?.id),
    email,
    fullName: [str(u?.givenName), str(u?.surname)].filter(Boolean).join(' ') || email,
    jobTitle: str(u?.title),
    // Hyperproof's User carries no department and no group membership, and no
    // manager reference. Left null/empty rather than filled with a guess.
    department: null,
    managerEmail: null,
    // OrganizationUserType distinguishes activeUser / deactivatedUser / contact /
    // serviceAccount / deactivatedServiceAccount / syncServiceAccount /
    // deactivatedSyncServiceAccount. Anything "deactivated", or a non-active
    // object status, is inactive. Service accounts and contacts ARE exported —
    // they are organization users the API returned, and dropping them would lose
    // records silently; `type` is preserved in `raw` so a destination can filter.
    active: !type.toLowerCase().startsWith('deactivated') && (objectStatus ?? 'active') === 'active',
    groups: [],
    raw: u,
  };
}

function mapPolicy(p: any, version: any | null): BundlePolicy {
  return {
    externalId: String(p?.id),
    name: str(p?.name) ?? 'Imported policy',
    description: str(p?.description),
    // PolicyVersionStatus (approval|draft|effective|retired) describes the live
    // version and is the more useful of the two; PolicyApprovalStatus
    // (approved|approval|changesRequested|editing) is the fallback. Both are
    // documented enum tokens and are passed through verbatim rather than
    // lower-cased into something that is no longer the source's vocabulary.
    status: str(version?.revisionStatus) ?? str(p?.policyApprovalStatus),
    approvedAt: str(version?.approvedDate) ?? str(version?.effectiveDate) ?? str(p?.effectiveDate),
    // Hyperproof's PolicyVersion has no version number or revision counter — only
    // a name and a lifecycle status. There is no version string to carry, so this
    // is null rather than the version's name masquerading as one.
    version: null,
    // `publishedUrl`/`shareLink` are the only documented links to a policy's
    // content. They point at wherever the customer published it (Hyperproof's own
    // example value is `www.hyperproof.io`), i.e. off this adapter's allowlist, so
    // no download is attempted — the link travels as a fallback. See point 2 in
    // the file header for why the document ids are not resolved to bytes.
    documentUrl: httpsUrl(version?.publishedUrl) ?? httpsUrl(version?.shareLink),
    raw: p,
  };
}

/**
 * Proof metadata → neutral evidence refs pointed at the documented
 * `/v1/proof/{proofId}/contents` download. Non-active proof (archived, deleted,
 * pending, canceled) is skipped: its bytes are not something the customer is
 * carrying forward, and a deleted file may no longer be retrievable at all.
 */
function collectProofRefs(proof: any[]): EvidenceRef[] {
  const refs: EvidenceRef[] = [];
  // A cursor that repeats a page (see listProof) would otherwise hand us the same
  // proof twice, and a bundle with two files sharing an externalId is a bug at the
  // destination, not just noise.
  const seen = new Set<string>();
  for (const p of proof) {
    const id = str(p?.id);
    if (!id || seen.has(id)) continue;
    const status = str(p?.status);
    if (status && status !== 'active') continue;
    seen.add(id);
    const detail = [
      str(p?.source) ? `Source: ${p.source}.` : '',
      p?.version != null ? `Hyperproof proof version ${p.version}.` : '',
      p?.isPrivate === true ? 'Marked private in Hyperproof.' : '',
    ]
      .filter(Boolean)
      .join(' ');
    refs.push({
      externalId: id,
      mediaUrl: `${API_BASE}/v1/proof/${encodeURIComponent(id)}/contents`,
      // Proof carries no link back to a policy or control on the object itself
      // (the association is a query filter on the list endpoint, not a field), so
      // there is no bundle record to reference.
      refExternalId: null,
      name: str(p?.nameOverride) ?? str(p?.filename) ?? id,
      contentType: str(p?.contentType),
      description: detail || null,
      collectedAt: str(p?.uploadedOn) ?? str(p?.createdOn),
    });
  }
  return refs;
}
