/**
 * Vanta adapter. Reads the official, documented Vanta REST API (verified live)
 * and maps it into the neutral migration bundle. Read-only: the only write is the
 * OAuth token exchange declared in the manifest. See docs at
 * https://developer.vanta.com/reference/manage-vanta/overview.
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

const API_BASE = 'https://api.vanta.com';
const TOKEN_ENDPOINT = `${API_BASE}/oauth/token`;
const PAGE_SIZE = 100;
const MAX_PAGES = 200;

export const manifest: AdapterManifest = {
  source: 'vanta',
  displayName: 'Vanta',
  officialDocsUrl: 'https://developer.vanta.com/reference/manage-vanta/overview',
  apiBase: API_BASE,
  allowedHosts: ['api.vanta.com'],
  tokenEndpoint: TOKEN_ENDPOINT,
  scopes: ['vanta-api.all:read'],
  credentialEnv: ['VANTA_CLIENT_ID', 'VANTA_CLIENT_SECRET'],
  endpoints: [
    { path: '/v1/vendors', docUrl: 'https://developer.vanta.com/reference/getvendors' },
    { path: '/v1/risk-scenarios', docUrl: 'https://developer.vanta.com/reference/getriskscenarios' },
    { path: '/v1/people', docUrl: 'https://developer.vanta.com/reference/getpeople' },
    { path: '/v1/policies', docUrl: 'https://developer.vanta.com/reference/getpolicies' },
  ],
};

interface PageInfo {
  endCursor?: string | null;
  hasNextPage?: boolean;
}
interface ListResponse<T> {
  results?: { data?: T[]; pageInfo?: PageInfo };
}

async function listAll<T>(http: GuardedHttp, token: string, path: string): Promise<T[]> {
  const out: T[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < MAX_PAGES; page++) {
    const url = new URL(`${API_BASE}${path}`);
    url.searchParams.set('pageSize', String(PAGE_SIZE));
    if (cursor) url.searchParams.set('pageCursor', cursor);
    const j = await http.getJson<ListResponse<T>>(url.toString(), { Authorization: `Bearer ${token}` });
    out.push(...(j.results?.data ?? []));
    const info = j.results?.pageInfo;
    if (!info?.hasNextPage || !info.endCursor) break;
    cursor = info.endCursor;
  }
  return out;
}

const norm = (s: unknown): string => String(s ?? '').trim().toLowerCase();
const clamp15 = (n: unknown): number | null => {
  const v = typeof n === 'number' ? n : Number(n);
  return Number.isFinite(v) ? Math.min(5, Math.max(1, Math.round(v))) : null;
};

function toCriticality(level: unknown): Criticality | null {
  switch (norm(level)) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'medium':
      return 'medium';
    case 'low':
    case 'none':
    case 'no_risk':
      return 'low';
    default:
      return null;
  }
}

/* eslint-disable @typescript-eslint/no-explicit-any */
export const vantaAdapter: Adapter = {
  manifest,
  async export(creds, http): Promise<BundleRecords> {
    const token = (
      await http.postToken<{ access_token?: string }>(TOKEN_ENDPOINT, {
        client_id: creds.VANTA_CLIENT_ID,
        client_secret: creds.VANTA_CLIENT_SECRET,
        scope: manifest.scopes.join(' '),
        grant_type: 'client_credentials',
      })
    ).access_token;
    if (!token) throw new Error('Vanta returned no access token — check the client id and secret.');

    const [vendors, risks, people, policies] = await Promise.all([
      listAll<any>(http, token, '/v1/vendors'),
      listAll<any>(http, token, '/v1/risk-scenarios'),
      listAll<any>(http, token, '/v1/people'),
      listAll<any>(http, token, '/v1/policies'),
    ]);

    return {
      vendors: vendors.map(mapVendor),
      risks: risks.map(mapRisk),
      people: people.map(mapPerson),
      policies: policies.map(mapPolicy),
    };
  },
};

function mapVendor(v: any): BundleVendor {
  return {
    externalId: v.id,
    name: v.name,
    website: v.websiteUrl ?? null,
    criticality: toCriticality(v.residualRiskLevel ?? v.inherentRiskLevel),
    status: v.status ?? null,
    reviewLastAt: v.lastSecurityReviewCompletionDate ?? null,
    reviewNextAt: v.nextSecurityReviewDueDate ?? null,
    notes:
      [v.servicesProvided ? `Services: ${v.servicesProvided}` : '', v.additionalNotes ?? '']
        .filter(Boolean)
        .join('\n') || null,
    raw: v,
  };
}

function mapRisk(r: any): BundleRisk {
  return {
    externalId: r.riskId,
    title: String(r.description ?? 'Imported risk').slice(0, 200),
    description: r.detailedDescription ?? null,
    category: Array.isArray(r.categories) ? (r.categories[0] ?? null) : null,
    likelihood: clamp15(r.likelihood),
    impact: clamp15(r.impact),
    residualLikelihood: r.residualLikelihood != null ? clamp15(r.residualLikelihood) : null,
    residualImpact: r.residualImpact != null ? clamp15(r.residualImpact) : null,
    treatment: r.treatment ?? null,
    ownerRef: r.owner ?? null,
    status: r.isArchived ? 'archived' : (r.reviewStatus ?? null),
    raw: r,
  };
}

function mapPerson(p: any): BundlePerson {
  const display =
    p.name?.display || [p.name?.first, p.name?.last].filter(Boolean).join(' ') || p.emailAddress;
  return {
    externalId: p.id,
    email: p.emailAddress,
    fullName: display || null,
    jobTitle: p.employment?.jobTitle ?? null,
    department: null,
    active: !(p.employment?.endDate || p.leaveInfo),
    groups: Array.isArray(p.groupIds) ? p.groupIds : [],
    raw: p,
  };
}

function mapPolicy(p: any): BundlePolicy {
  return {
    externalId: p.id,
    name: p.name,
    description: p.description ?? null,
    status: p.status ?? null,
    approvedAt: p.approvedAtDate ?? null,
    version: p.latestApprovedVersion?.versionId ?? null,
    documentUrl: p.latestApprovedVersion?.documents?.[0]?.url ?? null,
    raw: p,
  };
}
