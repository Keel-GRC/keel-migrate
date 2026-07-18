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
import { fetchPolicyDocuments, fetchEvidenceDocuments, type EvidenceRef } from '../files.js';

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
    // Evidence documents and their uploaded files. The /media endpoint returns the
    // raw bytes on api.vanta.com (already allowlisted), so evidence travels with
    // the bundle rather than as a link that dies when the customer leaves Vanta.
    { path: '/v1/documents', docUrl: 'https://developer.vanta.com/reference/getdocuments' },
    {
      path: '/v1/documents/{documentId}/uploads',
      docUrl: 'https://developer.vanta.com/reference/getdocumentuploads',
    },
    {
      path: '/v1/documents/{documentId}/uploads/{uploadedFileId}/media',
      docUrl: 'https://developer.vanta.com/reference/getdocumentuploadmedia',
    },
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

    const authHeader = { Authorization: `Bearer ${token}` };

    const mappedPolicies = policies.map(mapPolicy);
    // Pull each policy's approved document where it's served from an allowlisted
    // host; off-allowlist documents keep their documentUrl link (see files.ts).
    const { files: policyFiles } = await fetchPolicyDocuments(http, mappedPolicies, authHeader);

    // Evidence: list documents, then each document's uploaded files, and pull the
    // bytes from the /media endpoint (all on api.vanta.com, already allowlisted).
    const evidenceRefs = await collectEvidenceRefs(http, token);
    const { files: evidenceFiles } = await fetchEvidenceDocuments(http, evidenceRefs, authHeader);

    return {
      vendors: vendors.map(mapVendor),
      risks: risks.map(mapRisk),
      people: people.map(mapPerson),
      policies: mappedPolicies,
      files: [...policyFiles, ...evidenceFiles],
    };
  },
};

/**
 * Walk Vanta's documents and their uploads into neutral EvidenceRefs. Each
 * upload's bytes come from GET /v1/documents/{documentId}/uploads/{id}/media,
 * which returns the raw file on api.vanta.com. Uploads with a deletionDate are
 * skipped (they no longer have retrievable media). Missing fields degrade
 * gracefully so one odd record never sinks the export.
 */
async function collectEvidenceRefs(http: GuardedHttp, token: string): Promise<EvidenceRef[]> {
  const refs: EvidenceRef[] = [];
  let documents: any[];
  try {
    documents = await listAll<any>(http, token, '/v1/documents');
  } catch (e) {
    // The guarded client already retries transient 429s; if listing documents
    // still fails, skip evidence entirely rather than sinking an export whose
    // registers and policies already succeeded.
    console.warn(
      `Skipping evidence: could not list documents (${e instanceof Error ? e.message : String(e)}).`,
    );
    return refs;
  }
  let skippedDocs = 0;
  for (const doc of documents) {
    const documentId = doc?.id;
    if (!documentId) continue;
    let uploads: any[];
    try {
      uploads = await listAll<any>(
        http,
        token,
        `/v1/documents/${encodeURIComponent(String(documentId))}/uploads`,
      );
    } catch {
      // One document's uploads listing failed even after retries (sustained rate
      // limit or a transient error). Skip just this document; a re-run is
      // idempotent on import, so nothing is lost by continuing.
      skippedDocs++;
      continue;
    }
    for (const up of uploads) {
      const uploadId = up?.id;
      if (!uploadId || up?.deletionDate) continue;
      const title = doc?.title ? String(doc.title) : 'Evidence document';
      const detail = [
        `Evidence for "${title}".`,
        doc?.category ? `Category: ${doc.category}.` : '',
        doc?.isSensitive ? 'Marked sensitive in Vanta.' : '',
        up?.description ? String(up.description) : '',
      ]
        .filter(Boolean)
        .join(' ');
      refs.push({
        externalId: `${documentId}:${uploadId}`,
        refExternalId: String(documentId),
        mediaUrl: `${API_BASE}/v1/documents/${encodeURIComponent(String(documentId))}/uploads/${encodeURIComponent(String(uploadId))}/media`,
        name: up?.fileName ?? up?.title ?? title,
        contentType: up?.mimeType ?? null,
        description: detail || null,
        collectedAt: up?.effectiveDate ?? up?.updatedDate ?? up?.creationDate ?? null,
      });
    }
  }
  if (skippedDocs > 0) {
    console.warn(
      `${skippedDocs} document(s) had their uploads skipped after repeated rate limits. ` +
        `Re-run the export to pick them up — imports are idempotent, so already-imported files are not duplicated.`,
    );
  }
  return refs;
}

function mapVendor(v: any): BundleVendor {
  return {
    externalId: v.id,
    name: v.name,
    website: v.websiteUrl ?? null,
    // Keep Vanta's inherent/residual split: criticality is inherent, residual is
    // carried separately so the destination can preserve both (not collapse to one).
    criticality: toCriticality(v.inherentRiskLevel ?? v.residualRiskLevel),
    residualCriticality: v.residualRiskLevel ? toCriticality(v.residualRiskLevel) : null,
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
