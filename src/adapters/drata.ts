/**
 * Drata adapter. Reads the official, documented Drata Public API (v2) and maps it
 * into the neutral migration bundle. Authentication is a static, read-only API key
 * (Bearer), so the adapter performs NO write — the guarded client refuses every
 * POST for this adapter (tokenEndpoint: null). Docs:
 * https://developers.drata.com/openapi/reference/v2/overview/
 */
import type { Adapter, AdapterManifest } from '../adapter.js';
import type { GuardedHttp } from '../http.js';
import type {
  BundleRecords,
  BundleVendor,
  BundleRisk,
  BundlePerson,
  BundlePolicy,
  Criticality,
} from '../bundle.js';

const API_BASE = 'https://public-api.drata.com/public/v2';
const PAGE_SIZE = 100;
const MAX_PAGES = 500;

export const manifest: AdapterManifest = {
  source: 'drata',
  displayName: 'Drata',
  officialDocsUrl: 'https://developers.drata.com/openapi/reference/v2/overview/',
  apiBase: API_BASE,
  allowedHosts: ['public-api.drata.com'],
  // Static API key (Bearer) — no OAuth token exchange, so no write endpoint at all.
  tokenEndpoint: null,
  scopes: [],
  credentialEnv: ['DRATA_API_KEY'],
  endpoints: [
    { path: '/vendors', docUrl: 'https://developers.drata.com/openapi/reference/v2/tag/Vendors/' },
    { path: '/risks', docUrl: 'https://developers.drata.com/openapi/reference/v2/tag/Risks/' },
    {
      path: '/users',
      docUrl: 'https://developers.drata.com/openapi/reference/v2/tag/Users-and-Roles/',
    },
    { path: '/policies', docUrl: 'https://developers.drata.com/openapi/reference/v2/tag/Policies/' },
  ],
};

interface Page<T> {
  data?: T[];
  pagination?: { cursor?: string | null };
}

/** Walk Drata's cursor-paginated list endpoints (data[] + pagination.cursor). */
async function listAll<T>(http: GuardedHttp, apiKey: string, path: string): Promise<T[]> {
  const out: T[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < MAX_PAGES; page++) {
    const url = new URL(`${API_BASE}${path}`);
    url.searchParams.set('size', String(PAGE_SIZE));
    if (cursor) url.searchParams.set('cursor', cursor);
    const j = await http.getJson<Page<T>>(url.toString(), { Authorization: `Bearer ${apiKey}` });
    out.push(...(j.data ?? []));
    const next = j.pagination?.cursor;
    if (!next) break;
    cursor = next;
  }
  return out;
}

const norm = (s: unknown): string =>
  String(s ?? '')
    .trim()
    .toLowerCase();

/** Drata risk/impact scores are 1-10; the neutral bundle uses 1-5. */
const scale10to5 = (n: unknown): number | null => {
  const v = typeof n === 'number' ? n : Number(n);
  return Number.isFinite(v) && v > 0 ? Math.min(5, Math.max(1, Math.round(v / 2))) : null;
};

/* eslint-disable @typescript-eslint/no-explicit-any */
export const drataAdapter: Adapter = {
  manifest,
  async export(creds, http): Promise<BundleRecords> {
    const apiKey = creds.DRATA_API_KEY;
    if (!apiKey) throw new Error('DRATA_API_KEY is required.');

    const [vendors, risks, users, policies] = await Promise.all([
      listAll<any>(http, apiKey, '/vendors'),
      listAll<any>(http, apiKey, '/risks'),
      listAll<any>(http, apiKey, '/users'),
      listAll<any>(http, apiKey, '/policies'),
    ]);

    return {
      vendors: vendors.map(mapVendor),
      risks: risks.map(mapRisk),
      people: users.map(mapPerson),
      policies: policies.map(mapPolicy),
    };
  },
};

/** Drata vendor `risk` enum + `critical` flag → neutral criticality. */
function toCriticality(v: any): Criticality | null {
  if (v.critical === true) return 'critical';
  switch (norm(v.risk)) {
    case 'high':
      return 'high';
    case 'moderate':
      return 'medium';
    case 'low':
      return 'low';
    case 'none':
      return 'low';
    default:
      return null;
  }
}

function mapVendor(v: any): BundleVendor {
  return {
    externalId: String(v.id),
    name: v.name,
    website: v.url ?? null,
    criticality: toCriticality(v),
    status: v.status ? norm(v.status) : null,
    reviewLastAt: null,
    reviewNextAt: v.renewalDate ?? null,
    notes: null,
    raw: v,
  };
}

function mapRisk(r: any): BundleRisk {
  const owner = Array.isArray(r.owners) ? r.owners.find((o: any) => o?.email) : null;
  return {
    externalId: String(r.id),
    title: String(r.title ?? 'Imported risk').slice(0, 200),
    description: r.description ?? null,
    category: Array.isArray(r.categories) ? (r.categories[0]?.name ?? null) : null,
    likelihood: scale10to5(r.likelihood),
    impact: scale10to5(r.impact),
    residualLikelihood: r.residualLikelihood != null ? scale10to5(r.residualLikelihood) : null,
    residualImpact: r.residualImpact != null ? scale10to5(r.residualImpact) : null,
    treatment: r.treatmentPlan ? norm(r.treatmentPlan) : null,
    ownerRef: owner?.email ?? null,
    status: r.status ? norm(r.status) : null,
    raw: r,
  };
}

function mapPerson(u: any): BundlePerson {
  const display = [u.firstName, u.lastName].filter(Boolean).join(' ') || u.email;
  // separatedAt (directly or on an expanded identity) marks an offboarded person.
  const separated = u.separatedAt ?? (Array.isArray(u.identities) ? u.identities[0]?.separatedAt : null);
  return {
    externalId: String(u.id),
    email: u.email,
    fullName: display || null,
    jobTitle: u.jobTitle ?? null,
    department: null,
    active: !separated,
    groups: [],
    raw: u,
  };
}

function mapPolicy(p: any): BundlePolicy {
  const version = [p.version, p.subVersion].filter((x) => x != null).join('.');
  return {
    externalId: String(p.id),
    name: p.name,
    description: p.description ?? null,
    status: p.status ? norm(p.status) : null,
    approvedAt: p.approvedAt ?? null,
    version: version || null,
    // The list endpoint carries no document URL; files are on the roadmap.
    documentUrl: null,
    raw: p,
  };
}
