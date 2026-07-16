/**
 * Downloading the actual document bytes (Phase 2). Registers move as JSON, but a
 * policy's real value is the approved PDF — and a link to it dies the moment the
 * customer leaves the old platform. So where the source API hands us a document
 * URL on the adapter's own allowlisted host, we pull the bytes over the guarded
 * client and inline them (base64 + sha256) as BundleFile records.
 *
 * If the document is served from an off-allowlist host (a signed CDN/S3 URL the
 * adapter hasn't declared), we do NOT reach for it — the guarded client would
 * (correctly) refuse, and we keep the documentUrl link as the fallback rather
 * than widen the allowlist to an unverified host. That keeps "official APIs
 * only" intact; an adapter can opt a verified document host into its allowlist
 * later.
 */
import { createHash } from 'node:crypto';
import { GuardedHttp, PolicyViolation } from './http.js';
import type { BundleFile, BundlePolicy } from './bundle.js';

const EXT_BY_TYPE: Record<string, string> = {
  'application/pdf': 'pdf',
  'application/msword': 'doc',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'docx',
  'text/plain': 'txt',
  'text/markdown': 'md',
  'text/html': 'html',
  'application/json': 'json',
  'image/png': 'png',
  'image/jpeg': 'jpg',
};

function slug(s: string): string {
  return (
    s
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 60) || 'document'
  );
}

function fileName(policy: BundlePolicy, contentType: string): string {
  const ext = EXT_BY_TYPE[contentType] ?? 'bin';
  return `${slug(policy.name)}.${ext}`;
}

/** Build a BundleFile from downloaded bytes (computes sha256 + base64). */
export function fileFromBytes(
  input: {
    externalId: string;
    kind: BundleFile['kind'];
    refExternalId?: string | null;
    name: string;
    contentType: string;
    description?: string | null;
    collectedAt?: string | null;
  },
  bytes: Uint8Array,
): BundleFile {
  const buf = Buffer.from(bytes);
  return {
    externalId: input.externalId,
    kind: input.kind,
    refExternalId: input.refExternalId ?? null,
    name: input.name,
    contentType: input.contentType,
    sizeBytes: buf.byteLength,
    sha256: createHash('sha256').update(buf).digest('hex'),
    contentBase64: buf.toString('base64'),
    description: input.description ?? null,
    collectedAt: input.collectedAt ?? null,
  };
}

export interface PolicyDocResult {
  files: BundleFile[];
  /** Documents referenced but not pulled (off-allowlist host, HTTP error, too large). */
  skipped: number;
}

/**
 * Download each policy's document where its URL host is on the adapter's
 * allowlist. `headers` carries the adapter's auth (e.g. the Bearer token) since
 * document endpoints are authenticated. Never throws for a single bad document —
 * it's counted as skipped and the policy keeps its documentUrl link.
 */
export async function fetchPolicyDocuments(
  http: GuardedHttp,
  policies: BundlePolicy[],
  headers: Record<string, string> = {},
  opts: { maxBytes?: number } = {},
): Promise<PolicyDocResult> {
  const files: BundleFile[] = [];
  let skipped = 0;
  const collectedAt = new Date().toISOString();

  for (const policy of policies) {
    const url = policy.documentUrl;
    if (!url) continue;
    try {
      const { bytes, contentType } = await http.getBinary(url, headers, opts.maxBytes);
      if (bytes.byteLength === 0) {
        skipped++;
        continue;
      }
      files.push(
        fileFromBytes(
          {
            externalId: `${policy.externalId}:document`,
            kind: 'policy',
            refExternalId: policy.externalId,
            name: fileName(policy, contentType),
            contentType,
            description: `Policy document for "${policy.name}".`,
            collectedAt,
          },
          bytes,
        ),
      );
    } catch (e) {
      // Off-allowlist host (PolicyViolation) or an HTTP/size error — keep the
      // link, don't fail the whole export over one document.
      void (e instanceof PolicyViolation);
      skipped++;
    }
  }

  return { files, skipped };
}
