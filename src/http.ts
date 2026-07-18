/**
 * The guarded HTTP client — the technical enforcement of "official APIs only."
 *
 * Every request is checked against the calling adapter's manifest:
 *   - the host MUST be on the adapter's allowlist (no UI origins, no undocumented
 *     hosts, no scraping some random domain);
 *   - writes are near-eliminated: the only POSTs permitted are the single
 *     declared OAuth token endpoint and an explicit allowlist of documented
 *     read-query paths (`readPostPaths`) — some enterprise APIs (e.g. OneTrust)
 *     paginate/filter their reads over POST. Everything else is GET. The read
 *     guarantee is thus "GET, plus a small set of manifest-declared, audited
 *     read-query paths" — the guard trusts the declaration for those paths, and
 *     the conformance test requires each is also declared as an endpoint;
 *   - API responses MUST be JSON (we consume documented REST APIs, not scraped
 *     HTML). The one exception is `getBinary`, used to download a document the
 *     API references (a policy PDF): still GET-only, still HTTPS, still against
 *     an allowlisted host, and size-capped — bytes rather than JSON.
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
  /**
   * Exact pathnames where a POST is a documented READ query (pagination/filter),
   * e.g. OneTrust's '/api/risk/v2/risks/pages'. POST is permitted only to these
   * exact paths on an allowlisted host. Empty/absent for GET-only adapters.
   */
  readPostPaths?: string[];
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

/** Transient statuses worth retrying: rate limit + gateway/unavailable. */
function isRetryableStatus(status: number): boolean {
  return status === 429 || status === 502 || status === 503 || status === 504;
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

export class GuardedHttp {
  // Read requests retry transient failures (esp. Vanta's 429s during a large
  // evidence pull) with backoff, honoring Retry-After. Bounded so a persistently
  // rate-limited host eventually surfaces the error instead of hanging.
  private readonly maxRetries = 6;
  private readonly maxBackoffMs = 30_000;

  constructor(private readonly policy: HttpPolicy) {}

  /** How long to wait before retry `attempt` (0-based): Retry-After, else backoff. */
  private retryDelayMs(res: Response, attempt: number): number {
    const ra = res.headers.get('retry-after');
    if (ra) {
      const secs = Number(ra);
      if (Number.isFinite(secs)) return Math.min(Math.max(0, secs) * 1000, this.maxBackoffMs);
      const when = Date.parse(ra);
      if (Number.isFinite(when)) return Math.min(Math.max(0, when - Date.now()), this.maxBackoffMs);
    }
    // Exponential backoff (1s, 2s, 4s, …) capped, with a little jitter to avoid
    // synchronized retries hammering the API in lockstep.
    const base = Math.min(1000 * 2 ** attempt, this.maxBackoffMs);
    return base + Math.floor(Math.random() * 250);
  }

  /** GET with bounded retry on transient statuses. Non-retryable errors return immediately. */
  private async fetchWithRetry(url: string, init: RequestInit): Promise<Response> {
    let res = await fetch(url, init);
    for (let attempt = 0; isRetryableStatus(res.status) && attempt < this.maxRetries; attempt++) {
      const delay = this.retryDelayMs(res, attempt);
      // Drain the body so the socket is released before we wait and retry.
      await res.arrayBuffer().catch(() => undefined);
      await sleep(delay);
      res = await fetch(url, init);
    }
    return res;
  }

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
    const res = await this.fetchWithRetry(url, { method: 'GET', headers: { Accept: 'application/json', ...headers } });
    if (!res.ok) {
      throw new HttpError(`GET ${url} → HTTP ${res.status}: ${(await res.text().catch(() => '')).slice(0, 200)}`, res.status);
    }
    return (await res.json()) as T;
  }

  /**
   * Read-only binary GET for a document the API references (e.g. a policy PDF).
   * Same guarantees as getJson — allowlisted host, HTTPS, GET — but returns raw
   * bytes and enforces a hard size cap (checked against Content-Length up front
   * and again after reading, so a lying/absent header can't blow past it).
   */
  async getBinary(
    url: string,
    headers: Record<string, string> = {},
    maxBytes = 25 * 1024 * 1024,
  ): Promise<{ bytes: Uint8Array; contentType: string }> {
    this.assertHost(url);
    const res = await this.fetchWithRetry(url, { method: 'GET', headers });
    if (!res.ok) {
      throw new HttpError(
        `GET ${url} → HTTP ${res.status}: ${(await res.text().catch(() => '')).slice(0, 200)}`,
        res.status,
      );
    }
    const declared = Number(res.headers.get('content-length') ?? '');
    if (Number.isFinite(declared) && declared > maxBytes) {
      throw new HttpError(`Document at ${url} exceeds the ${maxBytes}-byte cap.`, 413);
    }
    const ab = await res.arrayBuffer();
    if (ab.byteLength > maxBytes) {
      throw new HttpError(`Document at ${url} exceeds the ${maxBytes}-byte cap.`, 413);
    }
    const contentType = (res.headers.get('content-type') ?? 'application/octet-stream')
      .split(';')[0]
      .trim();
    return { bytes: new Uint8Array(ab), contentType };
  }

  /**
   * The ONLY permitted write: exchange OAuth credentials at the declared token
   * endpoint. Body is JSON by default; pass `{ form: true }` for the
   * `application/x-www-form-urlencoded` grant some providers require (OneTrust).
   */
  async postToken<T>(
    url: string,
    body: Record<string, unknown>,
    opts: { headers?: Record<string, string>; form?: boolean } = {},
  ): Promise<T> {
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
    const contentType = opts.form ? 'application/x-www-form-urlencoded' : 'application/json';
    const encoded = opts.form
      ? new URLSearchParams(body as Record<string, string>).toString()
      : JSON.stringify(body);
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': contentType, Accept: 'application/json', ...opts.headers },
      body: encoded,
    });
    if (!res.ok) {
      throw new HttpError(`Token request → HTTP ${res.status}: ${(await res.text().catch(() => '')).slice(0, 200)}`, res.status);
    }
    return (await res.json()) as T;
  }

  /**
   * A POST that is a documented READ query (pagination/filter). Permitted only
   * to a path on the manifest's `readPostPaths` allowlist, on an allowlisted
   * host — so it can't reach an arbitrary (mutating) endpoint. Returns JSON.
   */
  async postRead<T>(url: string, body: unknown, headers: Record<string, string> = {}): Promise<T> {
    const u = this.assertHost(url);
    const paths = this.policy.readPostPaths ?? [];
    // Exact pathname match only — no substring/prefix comparison on the URL.
    const permitted = paths.includes(u.pathname);
    if (!permitted) {
      throw new PolicyViolation(
        `POST is only permitted to a declared read-query path (${paths.join(', ') || 'none'}), not ${u.pathname}.`,
      );
    }
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json', ...headers },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      throw new HttpError(
        `POST ${url} → HTTP ${res.status}: ${(await res.text().catch(() => '')).slice(0, 200)}`,
        res.status,
      );
    }
    return (await res.json()) as T;
  }
}
