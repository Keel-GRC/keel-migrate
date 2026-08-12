/**
 * Oneleet adapter. Reads the official, publicly published Oneleet Public API and
 * maps it into the neutral migration bundle.
 *
 * Docs: https://api.oneleet.com/api/v1/public/api-reference
 * Machine-readable spec: https://api.oneleet.com/api/v1/public/openapi.json
 *   (OpenAPI 3.0.3, `Oneleet Public API` v1.0.0 — every path and field mapped
 *   below was read from that spec, not inferred.)
 *
 * Authentication is a static, read-only service key presented as a Bearer token
 * (`service_<id>_<secret>`), so the adapter performs NO write and the guarded
 * client refuses every POST for it (`tokenEndpoint: null`).
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * TWO LIMITS OF THE PUBLIC API, STATED PLAINLY
 *
 * 1. PAGINATION IS PARTIALLY DOCUMENTED. The list endpoints for controls,
 *    policies, vendors and members return a `pagination` envelope
 *    (`current_page` / `next_page` / `num_pages`) but declare no `page` query
 *    parameter of their own. `page` IS a documented parameter elsewhere in the
 *    same spec version (e.g. `GET /api/v1/tenants/{tenant}/actions`), so this
 *    adapter *probes* it rather than assuming it: it requests page 2, and if the
 *    response does not actually advance `current_page`, it stops and reports the
 *    truncation loudly instead of silently looping or silently exporting page 1
 *    as if it were everything. A partial export that looks complete is the worst
 *    possible outcome for a migration tool.
 *
 * 2. EVIDENCE BYTES ARE NOT REACHABLE. `GET /api/v1/tenants/{tenant}/evidence`
 *    returns evidence metadata (name, type, fileName, link, linked control ids)
 *    but the public API documents no endpoint that returns an evidence file's
 *    bytes. The bundle's file record requires actual content, so evidence is not
 *    exported rather than exported as empty shells. Policy documents ARE
 *    attempted, via `currentVersion.fileUrl`; if that URL resolves to a host
 *    outside `api.oneleet.com` (a presigned object-store link), the guarded
 *    client refuses it and the policy keeps its link as the fallback — the same
 *    behaviour, and the same honest failure mode, as the Vanta adapter.
 */
import type { Adapter, AdapterManifest, ExportOptions } from '../adapter.js';
import type { GuardedHttp } from '../http.js';
import { fetchPolicyDocuments } from '../files.js';
import type {
  BundleRecords,
  BundleVendor,
  BundleRisk,
  BundlePerson,
  BundlePolicy,
  Criticality,
} from '../bundle.js';

const API_BASE = 'https://api.oneleet.com';
const DOCS = 'https://api.oneleet.com/api/v1/public/api-reference';
/** Bound the page probe so a server that ignores `page` can never loop forever. */
const MAX_PAGES = 200;

export const manifest: AdapterManifest = {
  source: 'oneleet',
  displayName: 'Oneleet',
  officialDocsUrl: DOCS,
  apiBase: API_BASE,
  allowedHosts: ['api.oneleet.com'],
  // Static service key (Bearer) — no OAuth exchange, so no write endpoint at all.
  tokenEndpoint: null,
  scopes: [],
  credentialEnv: ['ONELEET_API_KEY', 'ONELEET_TENANT_ID'],
  endpoints: [
    { path: '/api/v1/tenants/{tenant}/vendors', docUrl: DOCS },
    { path: '/api/v1/tenants/{tenant}/members', docUrl: DOCS },
    { path: '/api/v1/tenants/{tenant}/policies', docUrl: DOCS },
    { path: '/api/v1/tenants/{tenant}/risk-assessments', docUrl: DOCS },
    { path: '/api/v1/risks-assessments/{risk-assessment}', docUrl: DOCS },
  ],
};

/* eslint-disable @typescript-eslint/no-explicit-any */

interface Paginated<T> {
  rows?: T[];
  pagination?: { current_page?: number; next_page?: number; num_pages?: number };
}

/**
 * Read a `{ rows, pagination }` list endpoint.
 *
 * Requests page 1 with no parameter (matching what the spec documents), then —
 * only if `num_pages` says there is more — probes `?page=N`. The probe is
 * verified: if the server returns the same `current_page` it already gave us, it
 * is ignoring the parameter, so we stop and report exactly how much was missed
 * rather than spinning or lying about completeness.
 */
async function listPaged<T>(
  http: GuardedHttp,
  apiKey: string,
  path: string,
  label: string,
): Promise<T[]> {
  const get = (page?: number): Promise<Paginated<T>> => {
    const url = new URL(`${API_BASE}${path}`);
    if (page != null) url.searchParams.set('page', String(page));
    return http.getJson<Paginated<T>>(url.toString(), { Authorization: `Bearer ${apiKey}` });
  };

  const first = await get();
  const out: T[] = [...(first.rows ?? [])];
  const totalPages = Number(first.pagination?.num_pages ?? 1);
  if (!Number.isFinite(totalPages) || totalPages <= 1) return out;

  let lastSeenPage = Number(first.pagination?.current_page ?? 1);
  for (let page = 2; page <= Math.min(totalPages, MAX_PAGES); page++) {
    const next = await get(page);
    const reported = Number(next.pagination?.current_page ?? lastSeenPage);
    if (reported <= lastSeenPage) {
      // The endpoint accepted the request but did not advance — it does not
      // support `page`. Stop, and be loud: the alternative is an export that
      // looks whole and is not.
      console.warn(
        `WARNING: ${label} has ${totalPages} pages but the Oneleet public API does not ` +
          `paginate this endpoint (it kept returning page ${reported}). ` +
          `Exported ${out.length} ${label} from page 1 only — this export is INCOMPLETE. ` +
          `Ask Oneleet support for a paginated or bulk export of ${label} before migrating.`,
      );
      return out;
    }
    lastSeenPage = reported;
    out.push(...(next.rows ?? []));
    if (!next.rows?.length) break;
  }
  return out;
}

const norm = (s: unknown): string =>
  String(s ?? '')
    .trim()
    .toLowerCase();

/** Oneleet's ordinal risk scales are five-point, in the bundle's own order. */
const LIKELIHOOD: Record<string, number> = {
  REMOTE: 1,
  UNLIKELY: 2,
  POSSIBLE: 3,
  LIKELY: 4,
  ALMOST_CERTAIN: 5,
};
const IMPACT: Record<string, number> = {
  NEGLIGIBLE: 1,
  MINOR: 2,
  MODERATE: 3,
  MAJOR: 4,
  DEVASTATING: 5,
};
const score = (table: Record<string, number>, v: unknown): number | null =>
  typeof v === 'string' ? (table[v.toUpperCase()] ?? null) : null;

/** TenantVendorRisk is LOW | MEDIUM | HIGH — there is no 'critical' tier. */
function toCriticality(v: unknown): Criticality | null {
  switch (norm(v)) {
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

export const oneleetAdapter: Adapter = {
  manifest,
  async export(creds, http, opts: ExportOptions = {}): Promise<BundleRecords> {
    const apiKey = creds.ONELEET_API_KEY;
    const tenant = creds.ONELEET_TENANT_ID;
    if (!apiKey) throw new Error('ONELEET_API_KEY is required.');
    if (!tenant) throw new Error('ONELEET_TENANT_ID is required.');
    // The tenant id is a path segment. Encode it so a malformed value can never
    // escape the documented path shape.
    const t = encodeURIComponent(tenant);
    const auth = { Authorization: `Bearer ${apiKey}` };

    const [rawVendors, rawMembers, rawPolicies] = await Promise.all([
      listPaged<any>(http, apiKey, `/api/v1/tenants/${t}/vendors`, 'vendors'),
      listPaged<any>(http, apiKey, `/api/v1/tenants/${t}/members`, 'members'),
      listPaged<any>(http, apiKey, `/api/v1/tenants/${t}/policies`, 'policies'),
    ]);

    // Risks hang off risk assessments. The list endpoint returns assessments;
    // the documented per-assessment GET is what carries the `risks` array.
    const assessments = await http.getJson<any[]>(
      `${API_BASE}/api/v1/tenants/${t}/risk-assessments`,
      auth,
    );
    const rawRisks: any[] = [];
    for (const a of Array.isArray(assessments) ? assessments : []) {
      if (!a?.id) continue;
      const detail = await http.getJson<any>(
        `${API_BASE}/api/v1/risks-assessments/${encodeURIComponent(String(a.id))}`,
        auth,
      );
      for (const r of detail?.risks ?? []) rawRisks.push({ ...r, __assessmentTitle: detail?.title });
    }

    const policies = rawPolicies.map(mapPolicy);
    // Attempt the policy PDFs. `currentVersion.fileUrl` may point at an
    // object-store host outside the allowlist, in which case the guarded client
    // refuses it and the policy keeps its link — counted, never fatal.
    const { files, skipped, oversized } = await fetchPolicyDocuments(http, policies, auth, {
      maxBytes: opts.maxInlineBytes,
      maxInlineBytes: opts.maxInlineBytes,
    });
    if (skipped > 0) {
      console.warn(
        `${skipped} policy document(s) could not be downloaded (the document URL is outside ` +
          `Oneleet's API host, so this tool will not fetch it). Those policies keep their ` +
          `document link and import without attached files.`,
      );
    }
    if (oversized > 0) {
      console.warn(`${oversized} policy document(s) exceeded the per-file import cap and were skipped.`);
    }

    // People without an email cannot be matched by any destination, and the
    // bundle requires one. Drop them rather than emit an unusable record, and
    // say how many so the count is never a silent discrepancy.
    const people = rawMembers.map(mapPerson).filter((p): p is BundlePerson => p !== null);
    const droppedPeople = rawMembers.length - people.length;
    if (droppedPeople > 0) {
      console.warn(
        `${droppedPeople} Oneleet member(s) had no email address on the API response and were not ` +
          `exported (a person record without an email cannot be matched on import).`,
      );
    }

    return {
      vendors: rawVendors.map(mapVendor),
      risks: rawRisks.map(mapRisk),
      people,
      policies,
      files,
    };
  },
};

/**
 * A Oneleet vendor record is a `TenantVendor` (the customer's relationship)
 * wrapping a `Vendor` (the catalog entry). Name and website live on the inner
 * object; the risk rating, notes and review date live on the outer one.
 */
function mapVendor(v: any): BundleVendor {
  const inner = v.vendor ?? {};
  const services = Array.isArray(v.services) ? v.services.filter(Boolean) : [];
  const notes = [v.notes, services.length ? `Services: ${services.join(', ')}` : null]
    .filter(Boolean)
    .join('\n\n');
  return {
    externalId: String(v.id),
    name: inner.name ?? 'Imported vendor',
    website: v.vendorUrl ?? inner.url ?? null,
    criticality: toCriticality(v.risk),
    // Oneleet scores a single vendor risk rather than inherent vs residual.
    residualCriticality: null,
    status: v.deletedAt ? 'deleted' : v.isCompleted ? 'active' : 'in_review',
    reviewLastAt: v.reviewedAt ?? null,
    reviewNextAt: null,
    notes: notes || null,
    raw: v,
  };
}

function mapRisk(r: any): BundleRisk {
  return {
    externalId: String(r.id),
    title: String(r.title ?? 'Imported risk').slice(0, 200),
    description: r.description ?? null,
    // Oneleet's RiskCategory is an enum (SECURITY, LEGAL_AND_COMPLIANCE, …).
    // Lower-case it and restore the spaces so it reads as a category, not a token.
    category: r.category ? norm(r.category).replace(/_/g, ' ') : (r.__assessmentTitle ?? null),
    likelihood: score(LIKELIHOOD, r.likelihood),
    impact: score(IMPACT, r.impact),
    residualLikelihood: score(LIKELIHOOD, r.residualLikelihood),
    residualImpact: score(IMPACT, r.residualImpact),
    treatment: r.response ? norm(r.response) : null,
    ownerRef: r.owner?.email ?? r.owner?.user?.email ?? r.ownerId ?? null,
    status: r.archivedAt ? 'archived' : null,
    raw: r,
  };
}

/**
 * `TenantMember` carries the employment relationship; the email is on the
 * attached `user` (full record) or `userPublic` (email + name only). Returns
 * null when neither is present — see the caller, which counts the drop.
 */
function mapPerson(m: any): BundlePerson | null {
  const email = m.user?.email ?? m.userPublic?.email ?? null;
  if (!email) return null;
  const status = String(m.status ?? '').toUpperCase();
  const ended = m.employmentEndDate ? Date.parse(m.employmentEndDate) : NaN;
  const departed = status === 'FORMER' || status === 'OFFBOARDING';
  return {
    externalId: String(m.id),
    email,
    fullName: m.name ?? m.user?.name ?? m.userPublic?.name ?? null,
    // The public API models employment type (EMPLOYEE/CONTRACTOR/GUEST) and role,
    // not a job title or department. Left null rather than filled with a guess.
    jobTitle: null,
    department: null,
    managerEmail: null,
    active: !departed && !(Number.isFinite(ended) && ended <= Date.now()),
    groups: Array.isArray(m.groups)
      ? m.groups.map((g: any) => g?.name).filter((n: unknown): n is string => typeof n === 'string')
      : [],
    raw: m,
  };
}

function mapPolicy(p: any): BundlePolicy {
  const cv = p.currentVersion ?? {};
  const version =
    cv.versionNumber != null
      ? [cv.versionNumber, cv.minorVersionNumber].filter((x) => x != null).join('.')
      : null;
  return {
    externalId: String(p.id),
    name: p.name ?? 'Imported policy',
    description: p.description ?? null,
    status: cv.status ? norm(cv.status) : null,
    approvedAt: cv.publishedAt ?? null,
    version: version || null,
    documentUrl: cv.fileUrl ?? null,
    raw: p,
  };
}
