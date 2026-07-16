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
   * static-API-key adapters that perform no write at all.
   */
  tokenEndpoint: string | null;
  /** Every documented endpoint this adapter reads. */
  endpoints: EndpointRef[];
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

/** Build the HttpPolicy the guarded client enforces from an adapter manifest. */
export function policyFromManifest(m: AdapterManifest): HttpPolicy {
  return { allowedHosts: m.allowedHosts, tokenEndpoint: m.tokenEndpoint };
}
