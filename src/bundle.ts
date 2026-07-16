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
  /** Source download URL for the policy document (fetched separately, Phase 2). */
  documentUrl?: string | null;
  raw?: Record<string, unknown>;
}

export interface BundleRecords {
  vendors: BundleVendor[];
  risks: BundleRisk[];
  people: BundlePerson[];
  policies: BundlePolicy[];
}

export interface MigrationBundle {
  bundleVersion: typeof BUNDLE_VERSION;
  /** Source platform key, e.g. 'vanta'. */
  source: string;
  /** ISO timestamp the export ran. */
  exportedAt: string;
  tool: { name: string; version: string };
  counts: Record<string, number>;
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
    },
    records,
  };
}
