/**
 * The migration bundle — a vendor-neutral, documented interchange format for GRC
 * data portability. A source adapter maps its platform's API into these canonical
 * records; any destination (Keel or otherwise) reads them. Keeping the format
 * neutral is deliberate: this is a "get your data out" utility, not a proprietary
 * pipe, and the neutrality is what lets a destination-agnostic tool exist.
 *
 * The bundle is the stable contract: adapters absorb upstream API change and keep
 * emitting this shape, so a destination importer never breaks when a source
 * platform shifts. Bump BUNDLE_VERSION only on a breaking change to these types.
 */

export const BUNDLE_VERSION = 1 as const;

export type Criticality = 'low' | 'medium' | 'high' | 'critical';

export interface BundleVendor {
  externalId: string;
  name: string;
  website?: string | null;
  /** Inherent (pre-control) criticality. */
  criticality?: Criticality | null;
  /** Residual (post-control) criticality, when the source scores it separately. */
  residualCriticality?: Criticality | null;
  status?: string | null;
  reviewLastAt?: string | null;
  reviewNextAt?: string | null;
  notes?: string | null;
  /** Untouched source fields, for lossless round-trip / debugging. */
  raw?: Record<string, unknown>;
}

export interface BundleRisk {
  externalId: string;
  title: string;
  description?: string | null;
  category?: string | null;
  /** 1–5 scale. */
  likelihood?: number | null;
  impact?: number | null;
  residualLikelihood?: number | null;
  residualImpact?: number | null;
  treatment?: string | null;
  /** Opaque source owner reference (id/email); destinations resolve it. */
  ownerRef?: string | null;
  status?: string | null;
  raw?: Record<string, unknown>;
}

export interface BundlePerson {
  externalId: string;
  email: string;
  fullName?: string | null;
  jobTitle?: string | null;
  department?: string | null;
  managerEmail?: string | null;
  active: boolean;
  groups?: string[];
  raw?: Record<string, unknown>;
}

export interface BundlePolicy {
  externalId: string;
  name: string;
  description?: string | null;
  status?: string | null;
  approvedAt?: string | null;
  version?: string | null;
  /**
   * Source download URL for the policy document. Kept as a fallback link even
   * when the bytes are also inlined (see BundleFile) — and the only reference
   * when the document host is off the adapter's allowlist so it can't be pulled.
   */
  documentUrl?: string | null;
  raw?: Record<string, unknown>;
}

export type BundleFileKind = 'policy' | 'evidence';

/**
 * A binary document (policy PDF, evidence artifact) the adapter downloaded from
 * the source over its official, allowlisted API and inlined as base64 — so the
 * actual bytes travel with the bundle instead of a link that dies when the
 * customer leaves the old platform. The destination verifies `sha256` on import.
 */
export interface BundleFile {
  externalId: string;
  kind: BundleFileKind;
  /** For kind='policy': externalId of the policy this document belongs to. */
  refExternalId?: string | null;
  name: string;
  contentType: string;
  sizeBytes: number;
  /** Hex SHA-256 of the decoded bytes. */
  sha256: string;
  /** Base64-encoded file bytes. */
  contentBase64: string;
  description?: string | null;
  collectedAt?: string | null;
}

export interface BundleRecords {
  vendors: BundleVendor[];
  risks: BundleRisk[];
  people: BundlePerson[];
  policies: BundlePolicy[];
  files: BundleFile[];
}

export interface MigrationBundle {
  bundleVersion: typeof BUNDLE_VERSION;
  /** Source platform key, e.g. 'vanta'. */
  source: string;
  /** ISO timestamp the export ran. */
  exportedAt: string;
  tool: { name: string; version: string };
  counts: Record<string, number>;
  /**
   * Position of this shard in its export, 1-based. OPTIONAL and ADDITIVE:
   * BUNDLE_VERSION stays 1, and a bundle written before these fields existed —
   * or by any other producer — must still import. Present on every bundle this
   * tool writes, including a single-shard export (1 of 1).
   *
   * Their reason to exist is completeness verification at the destination. A
   * sharded export is only meaningful as a set: shard 2 alone is a valid bundle
   * carrying a third of an evidence library and no registers, and an importer
   * with no way to know that will happily report success. With these two fields
   * an importer can assert it holds exactly 1..shardCount before writing a
   * single row, and refuse otherwise. A silent partial import is much worse than
   * a rejection — the customer believes they have migrated.
   */
  shardIndex?: number;
  /** Total number of shards this export was split into. See `shardIndex`. */
  shardCount?: number;
  records: BundleRecords;
}

export function makeBundle(
  source: string,
  toolVersion: string,
  records: BundleRecords,
  exportedAt: string,
): MigrationBundle {
  return {
    bundleVersion: BUNDLE_VERSION,
    source,
    exportedAt,
    tool: { name: 'keel-migrate', version: toolVersion },
    counts: {
      vendors: records.vendors.length,
      risks: records.risks.length,
      people: records.people.length,
      policies: records.policies.length,
      files: records.files.length,
    },
    records,
  };
}

/**
 * Split one bundle into a set of independently-importable shards so a large
 * evidence library fits within the destination's per-file limits without dropping
 * anything. Every shard is itself a valid MigrationBundle (same version/shape):
 *
 *   - Shard 0 carries the registers (vendors/risks/people/policies) plus as many
 *     inlined files as fit under the cap (minus a reserve for the registers).
 *   - Shards 1..N carry EMPTY registers plus the remaining files, batched so each
 *     shard's inlined bytes stay under the cap.
 *
 * The importer already imports any bundle's files idempotently (matched by source
 * id) and skips empty registers, so a customer just imports each shard file, in
 * any order, with no dedupe or ordering concern. If everything fits in one shard,
 * a single bundle is returned (unchanged behavior for small exports).
 *
 * `maxBytes` bounds each shard's inlined (base64) file bytes.
 */
export function shardBundle(bundle: MigrationBundle, maxBytes: number): MigrationBundle[] {
  const files = bundle.records.files;
  // Reserve headroom in shard 0 for the registers so their bytes plus the first
  // file group stay under the cap. Registers are small in practice; measure them.
  const registersBytes = Buffer.byteLength(
    JSON.stringify({ ...bundle.records, files: [] }),
  );
  const firstCap = Math.max(1, maxBytes - registersBytes);

  const groups: BundleFile[][] = [];
  let cur: BundleFile[] = [];
  let curBytes = 0;
  for (const f of files) {
    const sz = f.contentBase64.length;
    const cap = groups.length === 0 ? firstCap : maxBytes;
    if (cur.length > 0 && curBytes + sz > cap) {
      groups.push(cur);
      cur = [];
      curBytes = 0;
    }
    cur.push(f);
    curBytes += sz;
  }
  if (cur.length > 0) groups.push(cur);
  if (groups.length === 0) groups.push([]); // registers-only export -> one shard

  // Every shard is stamped with its position, including the 1-of-1 case, so a
  // destination never has to infer completeness from filenames. See the field
  // docs on MigrationBundle for why an unstamped shard set is dangerous.
  const shardCount = groups.length;
  return groups.map((group, i): MigrationBundle => {
    if (i === 0) {
      return {
        ...bundle,
        counts: {
          vendors: bundle.records.vendors.length,
          risks: bundle.records.risks.length,
          people: bundle.records.people.length,
          policies: bundle.records.policies.length,
          files: group.length,
        },
        shardIndex: 1,
        shardCount,
        records: { ...bundle.records, files: group },
      };
    }
    return {
      bundleVersion: bundle.bundleVersion,
      source: bundle.source,
      exportedAt: bundle.exportedAt,
      tool: bundle.tool,
      counts: { vendors: 0, risks: 0, people: 0, policies: 0, files: group.length },
      shardIndex: i + 1,
      shardCount,
      records: { vendors: [], risks: [], people: [], policies: [], files: group },
    };
  });
}

/** Filename for shard `index` (1-based) — the loose file and the zip entry share it. */
export function shardFileName(index: number): string {
  return index === 1 ? 'migration-bundle.json' : `migration-bundle-${String(index).padStart(3, '0')}.json`;
}

/** Name of the single-file archive written alongside a sharded export. */
export const ARCHIVE_FILE_NAME = 'keel-migration-bundle.zip';
