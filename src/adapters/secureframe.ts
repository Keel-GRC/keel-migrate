/**
 * Secureframe adapter. Reads the official, documented Secureframe REST API and
 * maps it into the neutral migration bundle.
 *
 * Docs: https://api.secureframe.com/docs — this is the citable documentation URL.
 * (`developer.secureframe.com` 301s here, and both `openapi.json` and
 * `swagger.json` return 401, so there is no publicly fetchable spec URL to point
 * at. Every path, query parameter and response field below was read out of the
 * OpenAPI 3.0.0 document `Secureframe API`, dated version 2023-10-18, served
 * behind that docs page — none of it is inferred.)
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * AUTHENTICATION IS NOT BEARER. Secureframe uses a space-separated API key/secret
 * PAIR in the Authorization header:
 *
 *     Authorization: <API_KEY> <API_SECRET>
 *
 * Not `Bearer <token>`, not Basic. There is no token exchange, so this adapter
 * performs NO POST at all and the guarded client refuses every write for it
 * (`tokenEndpoint: null`).
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * THREE LIMITS, STATED PLAINLY. Two of them mean this adapter deliberately
 * under-delivers rather than shipping something that looks right and is not.
 *
 * 1. NO POLICIES. `policies: []`. Secureframe's API has no policy-library
 *    endpoint. The nearest thing is `GET /ssp_policies`, and it is not one: an
 *    SspPolicy is `{ id, control_id, name, owner, ssp_report_id, summary }` — a
 *    row scoped to one System Security Plan report, describing a control's policy
 *    narrative, with no document body, no version, no approval date and no
 *    lifecycle. Mapping it onto BundlePolicy would produce a policy register that
 *    imports cleanly, reads plausibly, and is not the customer's policy library —
 *    every row wrong, in a way nobody would catch until an audit. An obviously
 *    empty register is a far better outcome: it is visible, and it is honest.
 *
 * 2. NO EVIDENCE FILES. `files: []`. `GET /evidences` returns Evidence records
 *    carrying a `document_id`, but NO documented endpoint turns that id into
 *    bytes — there is no download/contents/media path for evidence anywhere in
 *    the spec, and the Evidence schema has no URL or filename field either.
 *    Bundle files exist to carry real bytes; empty shells are not evidence. So
 *    evidence is not exported at all. (If a customer needs their Secureframe
 *    evidence library moved, it has to come out of the console today. The
 *    Hyperproof adapter, by contrast, does get bytes — its API documents one.)
 *
 * 3. NO RISK SCORES. Secureframe's CompanyRisk schema carries no likelihood or
 *    impact field of any kind — not a rating, not an enum, not a number. It
 *    models quantitative inputs instead (`annualized_rate_of_occurrence`,
 *    `asset_value`, `exposure_factor`, `uncertainty`) plus free-text
 *    justifications (`likelihood_justification`, `impact_justification`, and
 *    their residual counterparts). Deriving a 1–5 likelihood from an ARO, or
 *    reading a severity out of a justification paragraph, would be this tool
 *    inventing the customer's risk scores. `likelihood`/`impact` are therefore
 *    null; the quantitative fields ride through untouched in `raw`, where a
 *    destination that understands them can use them.
 *
 * Pagination IS properly documented here (`page`, `per_page`, default 100, plus
 * `meta.total`), and is walked below with a page cap and a total-vs-collected
 * reconciliation, so a truncated export is reported rather than assumed complete.
 *
 * Rate limit: 500 requests/minute per IP. The guarded client already retries 429s
 * with backoff, so a large export slows down instead of failing.
 */
import type { Adapter, AdapterManifest } from '../adapter.js';
import type { GuardedHttp } from '../http.js';
import type {
  BundleRecords,
  BundleVendor,
  BundleRisk,
  BundlePerson,
  Criticality,
} from '../bundle.js';

const API_BASE = 'https://api.secureframe.com';
const DOCS = 'https://api.secureframe.com/docs';
/** Documented default page size; the spec sets no maximum. */
const PAGE_SIZE = 100;
/** Bound the walk so a server that ignores `page` can never loop forever. */
const MAX_PAGES = 500;

export const manifest: AdapterManifest = {
  source: 'secureframe',
  displayName: 'Secureframe',
  officialDocsUrl: DOCS,
  apiBase: API_BASE,
  // The UK host (api-uk.secureframe.com) is a documented server, but the CLI
  // treats every credentialEnv entry as mandatory, so a region selector would
  // force a variable on every US customer. Left US-only, deliberately: a UK
  // customer gets a clear allowlist refusal, not a half-working export.
  allowedHosts: ['api.secureframe.com'],
  // API key + secret in one header — no OAuth exchange, so no write endpoint at
  // all and the guarded client rejects every POST for this adapter.
  tokenEndpoint: null,
  scopes: [],
  credentialEnv: ['SECUREFRAME_API_KEY', 'SECUREFRAME_API_SECRET'],
  endpoints: [
    // The non-deprecated vendor endpoint. `GET /vendors` covers the same vendors
    // and the spec marks it "[DEPRECATED - Use the Third Party Risk Management
    // Vendor endpoint]", so it is not also called: it would duplicate every
    // vendor under a second id, and the TPRM record is the richer of the two
    // (it carries `website` and `vendor_status`, which the legacy one does not).
    { path: '/tprm/vendors', docUrl: DOCS },
    { path: '/risks', docUrl: DOCS },
    { path: '/users', docUrl: DOCS },
  ],
};

/* eslint-disable @typescript-eslint/no-explicit-any */

/** JSON:API-style envelope every Secureframe list endpoint returns. */
interface ListResponse {
  data?: { id?: string; type?: string; attributes?: any }[];
  meta?: { total?: number };
}

/**
 * Walk a `page`/`per_page` list endpoint, returning each row's `attributes` with
 * the envelope's `id` merged in (the envelope carries the canonical id; some
 * attribute blocks repeat it, some do not).
 *
 * Two guards, both of which exist so an incomplete export cannot pass for a whole
 * one: the loop stops at MAX_PAGES rather than trusting the server to run out of
 * pages, and the collected count is reconciled against the documented
 * `meta.total` — a shortfall is reported loudly instead of silently shipped.
 */
async function listAll(
  http: GuardedHttp,
  auth: Record<string, string>,
  path: string,
  label: string,
): Promise<any[]> {
  const out: any[] = [];
  let total: number | null = null;

  for (let page = 1; page <= MAX_PAGES; page++) {
    const url = new URL(`${API_BASE}${path}`);
    url.searchParams.set('page', String(page));
    url.searchParams.set('per_page', String(PAGE_SIZE));
    const j = await http.getJson<ListResponse>(url.toString(), auth);
    const rows = j.data ?? [];
    for (const row of rows) {
      const attrs = row?.attributes ?? {};
      out.push({ ...attrs, id: row?.id ?? attrs.id });
    }
    if (typeof j.meta?.total === 'number') total = j.meta.total;

    // A short page is the last page. An empty page ends the walk regardless.
    if (rows.length === 0 || rows.length < PAGE_SIZE) break;
    if (total != null && out.length >= total) break;

    if (page === MAX_PAGES) {
      console.warn(
        `WARNING: stopped after ${MAX_PAGES} pages of ${label} (${out.length} records) with more ` +
          `still pending. This export is INCOMPLETE.`,
      );
    }
  }

  if (total != null && out.length < total) {
    console.warn(
      `WARNING: Secureframe reported ${total} ${label} but only ${out.length} were returned ` +
        `across the pages read. This export is INCOMPLETE — do not treat the ${label} register ` +
        `as a full copy. Re-run the export; if the shortfall repeats, the API key's role may ` +
        `lack permission on some records (Secureframe applies RBAC to API requests).`,
    );
  }
  return out;
}

const str = (v: unknown): string | null => {
  const s = typeof v === 'string' ? v.trim() : '';
  return s ? s : null;
};

/**
 * Vendor `risk_level` is documented as `high | medium | low` on the legacy Vendor
 * schema; the TPRM VendorRiskDetail declares it as a free string, so it is
 * matched case-insensitively and anything outside those three (including
 * Secureframe's occasional `n_a`) maps to null rather than being forced onto the
 * scale. There is no `critical` tier in Secureframe.
 */
function toCriticality(v: unknown): Criticality | null {
  switch ((str(v) ?? '').toLowerCase()) {
    case 'high':
      return 'high';
    case 'medium':
      return 'medium';
    case 'low':
      return 'low';
    default:
      return null;
  }
}

export const secureframeAdapter: Adapter = {
  manifest,
  async export(creds, http): Promise<BundleRecords> {
    const apiKey = creds.SECUREFRAME_API_KEY;
    const apiSecret = creds.SECUREFRAME_API_SECRET;
    if (!apiKey) throw new Error('SECUREFRAME_API_KEY is required.');
    if (!apiSecret) throw new Error('SECUREFRAME_API_SECRET is required.');
    // The documented header format: key and secret separated by a single space.
    const auth = { Authorization: `${apiKey} ${apiSecret}` };

    const [rawVendors, rawRisks, rawUsers] = await Promise.all([
      listAll(http, auth, '/tprm/vendors', 'vendors'),
      listAll(http, auth, '/risks', 'risks'),
      listAll(http, auth, '/users', 'users'),
    ]);

    // A person with no email cannot be matched by any destination and the bundle
    // requires one. Drop them, and report how many, so the count is never a
    // silent discrepancy between what Secureframe holds and what was exported.
    const people = rawUsers.map(mapPerson).filter((p): p is BundlePerson => p !== null);
    const droppedPeople = rawUsers.length - people.length;
    if (droppedPeople > 0) {
      console.warn(
        `${droppedPeople} Secureframe user(s) had no email address on the API response and were ` +
          `not exported (a person record without an email cannot be matched on import).`,
      );
    }

    // See limits 1 and 2 in the file header: Secureframe documents no policy
    // library and no way to download an evidence file's bytes, so both are empty
    // rather than filled with something that resembles them.
    console.warn(
      'Secureframe note: policies and evidence files are NOT part of this export. The API ' +
        'documents no policy-library endpoint (/ssp_policies is System-Security-Plan scoped and ' +
        'carries no document), and no endpoint returns an evidence file\'s bytes. Export those ' +
        'from the Secureframe console before you switch off the account.',
    );

    return {
      vendors: rawVendors.map(mapVendor),
      risks: rawRisks.map(mapRisk),
      people,
      policies: [],
      files: [],
    };
  },
};

function mapVendor(v: any): BundleVendor {
  const notes = [
    str(v?.services_provided) ? `Services: ${v.services_provided}` : null,
    str(v?.data_collected) ? `Data collected: ${v.data_collected}` : null,
    Array.isArray(v?.environment_types) && v.environment_types.length
      ? `Environments: ${v.environment_types.filter(Boolean).join(', ')}`
      : null,
    str(v?.third_party_audit_report_concerns)
      ? `Audit report concerns: ${v.third_party_audit_report_concerns}`
      : null,
    str(v?.other_information),
  ]
    .filter(Boolean)
    .join('\n\n');

  return {
    externalId: String(v?.id),
    name: str(v?.name) ?? 'Imported vendor',
    website: str(v?.website) ?? str(v?.security_url),
    // Secureframe scores one risk level per vendor — there is no inherent/residual
    // split to preserve, so residual is left null rather than duplicating it.
    criticality: toCriticality(v?.risk_level),
    residualCriticality: null,
    // `archived` is the lifecycle flag; `vendor_status` (accepted/rejected/pending)
    // is the review outcome. Archived wins, because it outranks "accepted".
    status: v?.archived === true ? 'archived' : str(v?.vendor_status),
    reviewLastAt: str(v?.last_reviewed_at),
    // No next-review date exists on a Secureframe vendor.
    reviewNextAt: null,
    notes: notes || null,
    raw: v,
  };
}

function mapRisk(r: any): BundleRisk {
  const notes = [str(r?.notes), str(r?.treatment_decision_notes)].filter(Boolean).join('\n\n');
  return {
    externalId: String(r?.id),
    // CompanyRisk has no title field. `custom_risk_id` is the human-readable
    // identifier the customer sees; the description is the only prose available,
    // so the title falls back to a truncation of it rather than being left blank.
    title: String(str(r?.custom_risk_id) ?? str(r?.description) ?? 'Imported risk').slice(0, 200),
    description: [str(r?.description), notes || null].filter(Boolean).join('\n\n') || null,
    category: Array.isArray(r?.categories) ? (str(r.categories[0]) ?? null) : null,
    // See limit 3 in the file header: Secureframe models no likelihood or impact
    // score. The quantitative inputs it does carry (annualized_rate_of_occurrence,
    // asset_value, exposure_factor, uncertainty) are an ALE model, not a 1-5
    // scale, and the *_justification fields are prose. Nothing here can be
    // converted honestly, so nothing is.
    likelihood: null,
    impact: null,
    residualLikelihood: null,
    residualImpact: null,
    treatment: str(r?.treatment),
    // owner_id is an opaque uuid. The users list is keyed by user id and could be
    // joined here, but CompanyRisk's `owner_id` is not documented as referencing
    // the User resource (unlike the `include=owner` relationship, which returns
    // its payload in the JSON:API `included` block rather than in `data`). Passing
    // the id through unchanged is the documented-safe choice: a destination
    // resolves an opaque ref, but cannot un-resolve a wrong email.
    ownerRef: str(r?.owner_id),
    status: str(r?.status),
    raw: r,
  };
}

/** Returns null when the user has no email — see the caller, which counts the drop. */
function mapPerson(u: any): BundlePerson | null {
  const email = str(u?.email);
  if (!email) return null;
  const ended = u?.end_date ? Date.parse(u.end_date) : NaN;
  const composed = [str(u?.preferred_first_name) ?? str(u?.first_name), str(u?.last_name)]
    .filter(Boolean)
    .join(' ');
  return {
    externalId: String(u?.id),
    email,
    fullName: str(u?.name) ?? (composed || email),
    jobTitle: str(u?.title),
    // `department_id` is an opaque id and the API documents no department resource
    // to resolve it against, so there is no name to put here.
    department: null,
    // `manager_name` is a display name, not an email; BundlePerson.managerEmail is
    // an email and a name in that slot would not resolve on import. It stays in
    // `raw`.
    managerEmail: null,
    // `active` is the documented account flag; a past `end_date` means the person
    // is offboarded even where the flag has not caught up.
    active: u?.active !== false && !(Number.isFinite(ended) && ended <= Date.now()),
    // Secureframe has no group concept on User. `employee_type` (employee /
    // contractor / auditor / …) and `personnel_status` are a different axis and
    // stay in `raw` rather than being flattened into groups.
    groups: [],
    raw: u,
  };
}
