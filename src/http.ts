/**
 * The guarded HTTP client — the technical enforcement of "official APIs only."
 *
 * Every request is checked against the calling adapter's manifest:
 *   - the host MUST be on the adapter's allowlist (no UI origins, no undocumented
 *     hosts, no scraping some random domain);
 *   - the ONLY write permitted is the single declared OAuth token endpoint —
 *     everything else is GET (read-only by construction, so the tool provably
 *     cannot mutate the source system);
 *   - responses MUST be JSON (we consume documented REST APIs, not scraped HTML).
 *
 * A violation throws before any network call, so "official, documented,
 * read-only" is verifiable in code rather than promised in docs.
 */

export interface HttpPolicy {
  /** Hostnames this adapter is allowed to contact, e.g. ['api.vanta.com']. */
  allowedHosts: string[];
  /**
   * The one URL permitted for a POST (OAuth token exchange), or `null` for
   * adapters that authenticate with a static API key — those perform no POST at
   * all, so the guarded client rejects every write.
   */
  tokenEndpoint: string | null;
}

export class PolicyViolation extends Error {}
export class HttpError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

export class GuardedHttp {
  constructor(private readonly policy: HttpPolicy) {}

  private assertHost(url: string): URL {
    const u = new URL(url);
    if (u.protocol !== 'https:') {
      throw new PolicyViolation(`Refusing non-HTTPS request to ${url}`);
    }
    if (!this.policy.allowedHosts.includes(u.hostname)) {
      throw new PolicyViolation(
        `Host ${u.hostname} is not in this adapter's official-API allowlist (${this.policy.allowedHosts.join(', ')}).`,
      );
    }
    return u;
  }

  /** Read-only GET against an allowlisted host; returns parsed JSON. */
  async getJson<T>(url: string, headers: Record<string, string> = {}): Promise<T> {
    this.assertHost(url);
    const res = await fetch(url, { method: 'GET', headers: { Accept: 'application/json', ...headers } });
    if (!res.ok) {
      throw new HttpError(`GET ${url} → HTTP ${res.status}: ${(await res.text().catch(() => '')).slice(0, 200)}`, res.status);
    }
    return (await res.json()) as T;
  }

  /** The ONLY permitted write: exchange OAuth credentials at the declared token endpoint. */
  async postToken<T>(url: string, body: unknown, headers: Record<string, string> = {}): Promise<T> {
    this.assertHost(url);
    if (this.policy.tokenEndpoint === null) {
      throw new PolicyViolation(
        'This adapter authenticates with a static API key and performs no POST; writes are refused.',
      );
    }
    if (url !== this.policy.tokenEndpoint) {
      throw new PolicyViolation(
        `POST is only permitted to the declared token endpoint (${this.policy.tokenEndpoint}), not ${url}.`,
      );
    }
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json', ...headers },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      throw new HttpError(`Token request → HTTP ${res.status}: ${(await res.text().catch(() => '')).slice(0, 200)}`, res.status);
    }
    return (await res.json()) as T;
  }
}
