/**
 * OneTrust adapter. Reads the official, documented OneTrust API and maps it into
 * the neutral migration bundle. Two things differ from the Vanta/Drata adapters,
 * both inherent to OneTrust's enterprise API and enforced by the guarded client:
 *
 *   - the API host is the customer's OWN tenant (e.g. yourco.my.onetrust.com or a
 *     regional app-*.onetrust.com), supplied via ONETRUST_HOSTNAME and validated
 *     to end in `.onetrust.com` before it's added to the allowlist (see the
 *     manifest's `dynamicHost` + resolvePolicy);
 *   - some reads paginate over POST (`/api/risk/v2/risks/pages`), declared in
 *     `readPostEndpoints` so the guarded client permits POST to exactly that path.
 *
 * Auth is OAuth2 client-credentials with a form-encoded token request. Read-only:
 * the only write is the token exchange.
 *
 * NOTE: built against OneTrust's public API documentation; response-field mapping
 * should be validated against a live tenant (OneTrust is modular and versioned).
 * Vendors and policies are not yet pulled — their exact tenant-version list paths
 * need confirming against a real environment before they're added (kept honest
 * rather than guessed). See docs: https://developer.onetrust.com/
 */
import type { Adapter, AdapterManifest } from '../adapter.js';
import { normalizeHost } from '../adapter.js';
import type { GuardedHttp } from '../http.js';
import type { BundleRecords, BundleRisk, BundlePerson } from '../bundle.js';

const TOKEN_PATH = '/api/access/v1/oauth/token';
const PAGE_SIZE = 100;
const MAX_PAGES = 500;

export const manifest: AdapterManifest = {
  source: 'onetrust',
  displayName: 'OneTrust',
  officialDocsUrl: 'https://developer.onetrust.com/',
  // Host is the customer's tenant, resolved at runtime — see dynamicHost.
  apiBase: 'https://{ONETRUST_HOSTNAME}',
  allowedHosts: [],
  // OAuth token URL is formed from tokenPath + the resolved tenant host.
  tokenEndpoint: null,
  tokenPath: TOKEN_PATH,
  dynamicHost: { env: 'ONETRUST_HOSTNAME', allowedSuffixes: ['.onetrust.com'] },
  scopes: ['RISK_READ', 'USER'],
  credentialEnv: ['ONETRUST_HOSTNAME', 'ONETRUST_CLIENT_ID', 'ONETRUST_CLIENT_SECRET'],
  endpoints: [
    // Deep-link these to the specific reference pages once verified per tenant version.
    { path: '/api/access/v2/users', docUrl: 'https://developer.onetrust.com/onetrust/reference' },
  ],
  readPostEndpoints: [
    { path: '/api/risk/v2/risks/pages', docUrl: 'https://developer.onetrust.com/onetrust/reference' },
  ],
};

const norm = (s: unknown): string =>
  String(s ?? '')
    .trim()
    .toLowerCase();

/* eslint-disable @typescript-eslint/no-explicit-any */

/** Spring-style page response shape used across OneTrust list endpoints. */
interface Page<T> {
  content?: T[];
  number?: number;
  last?: boolean;
  totalPages?: number;
}

export const onetrustAdapter: Adapter = {
  manifest,
  async export(creds, http): Promise<BundleRecords> {
    const host = normalizeHost(creds.ONETRUST_HOSTNAME ?? '');
    if (!host) {
      throw new Error(
        'ONETRUST_HOSTNAME is required — your OneTrust tenant host, e.g. yourco.my.onetrust.com.',
      );
    }
    const base = `https://${host}`;

    const token = (
      await http.postToken<{ access_token?: string }>(
        `${base}${TOKEN_PATH}`,
        {
          grant_type: 'client_credentials',
          client_id: creds.ONETRUST_CLIENT_ID,
          client_secret: creds.ONETRUST_CLIENT_SECRET,
        },
        { form: true },
      )
    ).access_token;
    if (!token) throw new Error('OneTrust returned no access token — check the client id and secret.');
    const auth = { Authorization: `Bearer ${token}` };

    const [people, risks] = await Promise.all([
      fetchUsers(http, base, auth),
      fetchRisks(http, base, auth),
    ]);

    // Vendors + policies pending live-tenant path validation (see file header).
    return { vendors: [], risks, people, policies: [], files: [] };
  },
};

/** GET /api/access/v2/users — page-based; tolerate a bare array too. */
async function fetchUsers(
  http: GuardedHttp,
  base: string,
  auth: Record<string, string>,
): Promise<BundlePerson[]> {
  const out: BundlePerson[] = [];
  for (let page = 0; page < MAX_PAGES; page++) {
    const url = new URL(`${base}/api/access/v2/users`);
    url.searchParams.set('page', String(page));
    url.searchParams.set('size', String(PAGE_SIZE));
    const j = await http.getJson<Page<any> | any[]>(url.toString(), auth);
    const rows = Array.isArray(j) ? j : (j.content ?? []);
    out.push(...rows.map(mapPerson));
    if (Array.isArray(j)) break; // non-paginated response
    if (j.last || rows.length < PAGE_SIZE || (j.totalPages != null && page + 1 >= j.totalPages)) break;
  }
  return out;
}

/** POST /api/risk/v2/risks/pages — paginated read query (declared read-POST). */
async function fetchRisks(
  http: GuardedHttp,
  base: string,
  auth: Record<string, string>,
): Promise<BundleRisk[]> {
  const out: BundleRisk[] = [];
  for (let page = 0; page < MAX_PAGES; page++) {
    const j = await http.postRead<Page<any>>(
      `${base}/api/risk/v2/risks/pages`,
      { page, size: PAGE_SIZE },
      auth,
    );
    const rows = j.content ?? [];
    out.push(...rows.map(mapRisk));
    if (j.last || rows.length < PAGE_SIZE || (j.totalPages != null && page + 1 >= j.totalPages)) break;
  }
  return out;
}

function mapPerson(u: any): BundlePerson {
  const full =
    u.name || [u.firstName, u.middleName, u.lastName].filter(Boolean).join(' ') || u.email;
  return {
    externalId: String(u.userId ?? u.id ?? u.email),
    email: u.email,
    fullName: full || null,
    jobTitle: u.title ?? null,
    department: null,
    active: u.active !== false,
    groups: [],
    raw: u,
  };
}

/** Map OneTrust risk state → neutral status. */
function riskStatus(s: unknown): string | null {
  const v = norm(s);
  if (!v) return null;
  if (v.includes('closed') || v.includes('archiv')) return 'closed';
  if (v.includes('accept')) return 'accepted';
  if (v.includes('remediat') || v.includes('progress') || v.includes('treat')) return 'treating';
  return 'open';
}

function mapRisk(r: any): BundleRisk {
  const owner = Array.isArray(r.owners) ? r.owners.find((o: any) => o?.email) : null;
  return {
    externalId: String(r.id ?? r.riskId),
    title: String(r.name ?? r.description ?? 'Imported risk').slice(0, 200),
    description: r.description ?? null,
    category: r.category ?? (Array.isArray(r.categories) ? (r.categories[0]?.name ?? null) : null),
    // The pages endpoint carries limited columns; scores come through when present.
    likelihood: null,
    impact: null,
    residualLikelihood: null,
    residualImpact: null,
    treatment: r.treatment ? norm(r.treatment) : null,
    ownerRef: owner?.email ?? r.ownerId ?? null,
    status: riskStatus(r.state ?? r.status),
    raw: r,
  };
}
