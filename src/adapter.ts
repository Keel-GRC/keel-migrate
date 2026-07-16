import type { GuardedHttp, HttpPolicy } from './http.js';
import type { BundleRecords } from './bundle.js';

/**
 * An adapter maps ONE source platform's official API into the neutral bundle.
 *
 * Its `manifest` is the machine-readable declaration of exactly what the adapter
 * is allowed to touch — the official docs it was written against, the API base,
 * the host allowlist, the single OAuth token endpoint, and each documented
 * endpoint it reads (with a link to that endpoint's docs). The guarded HTTP
 * client enforces the manifest at runtime; a conformance test enforces that the
 * adapter declares every endpoint it uses. This is how "official APIs only" is
 * kept honest as the project grows.
 */
export interface EndpointRef {
  /** Path relative to apiBase, e.g. '/v1/vendors'. */
  path: string;
  /** Link to the official documentation for this endpoint. */
  docUrl: string;
}

/**
 * For multi-tenant platforms where the API host is the customer's own tenant
 * (e.g. `yourco.my.onetrust.com`, or a regional `app-eu.onetrust.com`): the env
 * var that supplies the host, and the suffixes an accepted host MUST end with.
 * The suffix check is what stops an arbitrary host being injected into the
 * allowlist — only hosts under the vendor's own domain are ever permitted.
 */
export interface DynamicHost {
  env: string;
  allowedSuffixes: string[];
}

export interface AdapterManifest {
  source: string;
  displayName: string;
  /** Link to the platform's official API documentation. */
  officialDocsUrl: string;
  apiBase: string;
  /** Hostnames the guarded client will permit for this adapter. */
  allowedHosts: string[];
  /**
   * The single URL permitted for a POST (OAuth token exchange), or `null` for
   * static-API-key adapters and dynamic-host adapters (which resolve the token
   * URL at runtime from `tokenPath` + the customer host — see resolvePolicy).
   */
  tokenEndpoint: string | null;
  /**
   * For dynamic-host OAuth adapters: the token path, combined with the resolved
   * customer host to form the concrete token endpoint at runtime.
   */
  tokenPath?: string | null;
  /** Every documented endpoint this adapter reads over GET. */
  endpoints: EndpointRef[];
  /**
   * Documented endpoints this adapter reads over POST (pagination/filter
   * queries) — some enterprise APIs paginate reads via POST. Declared
   * separately so the guarded client can allow POST to exactly these paths.
   */
  readPostEndpoints?: EndpointRef[];
  /** Multi-tenant host resolution, when the API host is the customer's tenant. */
  dynamicHost?: DynamicHost | null;
  /** OAuth scopes required (read-only). Empty for API-key adapters. */
  scopes: string[];
  /** Environment variables the adapter reads credentials from. */
  credentialEnv: string[];
}

export interface Adapter {
  manifest: AdapterManifest;
  /** Pull the source's data and return neutral bundle records. Read-only. */
  export(creds: Record<string, string>, http: GuardedHttp): Promise<BundleRecords>;
}

/**
 * Normalize a user-supplied host to a clean hostname: accept a bare host or a
 * pasted URL, but ALWAYS resolve through the URL parser so the result is only
 * ever the hostname — never userinfo, port, path, query, or fragment. Returns ''
 * for anything unparseable. (Parsing here is what makes the domain check in
 * resolvePolicy sound: a crafted value like `attacker.com#.onetrust.com` resolves
 * to hostname `attacker.com`, which is not under `onetrust.com`.)
 */
export function normalizeHost(raw: string): string {
  const s = raw.trim();
  if (!s) return '';
  try {
    const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `https://${s}`);
    return u.hostname;
  } catch {
    return '';
  }
}

/**
 * True iff `host` is exactly `domain` or a subdomain of it — compared label by
 * label (not a substring/`endsWith` check), so `onetrust.com.attacker.com` and
 * `notonetrust.com` are correctly rejected.
 */
export function isHostUnderDomain(host: string, domain: string): boolean {
  if (!host || !domain) return false;
  if (host === domain) return true;
  const h = host.split('.');
  const d = domain.split('.');
  if (h.length <= d.length) return false;
  return d.every((label, i) => label === h[h.length - d.length + i]);
}

/** Build the HttpPolicy the guarded client enforces from an adapter manifest. */
export function policyFromManifest(m: AdapterManifest): HttpPolicy {
  return {
    allowedHosts: m.allowedHosts,
    tokenEndpoint: m.tokenEndpoint,
    readPostPaths: (m.readPostEndpoints ?? []).map((e) => e.path),
  };
}

/**
 * The policy with any dynamic (customer-tenant) host resolved from the
 * environment: the host is validated against the manifest's allowed suffixes
 * and added to the allowlist, and — for OAuth dynamic-host adapters — the
 * concrete token endpoint is formed from `tokenPath` + that host. Throws if the
 * declared env var is set to a host outside the vendor's own domain.
 */
export function resolvePolicy(
  m: AdapterManifest,
  env: Record<string, string | undefined> = process.env,
): HttpPolicy {
  const policy = policyFromManifest(m);
  if (!m.dynamicHost) return policy;
  const raw = env[m.dynamicHost.env];
  if (!raw) return policy; // absent host is caught later as a missing credential
  const host = normalizeHost(raw);
  // `host` is a clean hostname (URL-parsed). Permit it only if it IS the allowed
  // registrable domain or a subdomain of it — an exact DNS-label comparison, not
  // a substring match.
  const permitted = m.dynamicHost.allowedSuffixes.some((suffix) =>
    isHostUnderDomain(host, suffix.replace(/^\./, '')),
  );
  if (!permitted) {
    throw new Error(
      `${m.dynamicHost.env} must be a host under ${m.dynamicHost.allowedSuffixes.join(' or ')} (got "${raw}").`,
    );
  }
  policy.allowedHosts = [...policy.allowedHosts, host];
  if (m.tokenPath) policy.tokenEndpoint = `https://${host}${m.tokenPath}`;
  return policy;
}
