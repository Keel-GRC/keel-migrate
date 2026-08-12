/**
 * Hyperproof adapter tests.
 *
 * The manifest is covered by the conformance suite. What is pinned here is the
 * mapping and the two places this adapter reasons about API limits: the proof
 * cursor walk (including a server that stops advancing its token) and the
 * unpaginated-endpoint cap warning. Both have the same failure mode a migration
 * tool must never have — an export that is partial and looks whole.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { GuardedHttp } from '../src/http.js';
import { hyperproofAdapter } from '../src/adapters/hyperproof.js';

const CREDS = { HYPERPROOF_CLIENT_ID: 'client', HYPERPROOF_CLIENT_SECRET: 'secret' };

/**
 * A GuardedHttp stand-in driven by a URL→payload function. The real guard is
 * tested in conformance.test.ts; here we only need the adapter's request shape
 * and its handling of the responses.
 */
function stubHttp(
  handler: (url: URL) => unknown,
  binary?: (url: URL) => { bytes: Uint8Array; contentType: string },
): { http: GuardedHttp; urls: string[] } {
  const urls: string[] = [];
  const http = {
    async postToken<T>(): Promise<T> {
      return { access_token: 'jwt-token' } as T;
    },
    async getJson<T>(url: string): Promise<T> {
      urls.push(url);
      return handler(new URL(url)) as T;
    },
    async getBinary(url: string): Promise<{ bytes: Uint8Array; contentType: string }> {
      urls.push(url);
      if (!binary) throw new Error('no binary in these fixtures');
      return binary(new URL(url));
    },
  } as unknown as GuardedHttp;
  return { http, urls };
}

/**
 * True when a recorded request URL is exactly this path on Hyperproof's API host.
 *
 * Compares the parsed `origin` and `pathname` rather than searching the URL for a
 * substring. A substring check is the classic incomplete-sanitization bug: it also
 * matches `https://evil.test/?next=https://api.hyperproof.app/v1/proof`, so a test
 * written that way would keep passing if the adapter started calling the wrong
 * host. Query strings are deliberately ignored — pagination cursors vary per call.
 */
function matches(recordedUrl: string, pathname: string): boolean {
  const u = new URL(recordedUrl);
  return u.origin === 'https://api.hyperproof.app' && u.pathname === pathname;
}

/** Every endpoint empty, so a test can override just the one it cares about. */
function emptyDefaults(u: URL): unknown {
  if (u.pathname === '/v1/proof') return { data: [] };
  return [];
}

/** The five-step custom scale from the Risks API spec's own example. */
const FIVE_STEP = [
  { name: 'Very Low', value: 1 },
  { name: 'Low', value: 2 },
  { name: 'Moderate', value: 5 },
  { name: 'High', value: 8 },
  { name: 'Very High', value: 10 },
];

test('hyperproof: maps vendors, users, risks and policies into the neutral bundle', async () => {
  const { http, urls } = stubHttp((u) => {
    if (u.pathname === '/v1/vendors') {
      return [
        {
          id: 'v-1',
          name: 'Example Inc',
          category: 'Compliance',
          vendorStatus: 'approved',
          assessedRiskLevel: 'veryHigh',
          riskLevel: 'moderate',
          freshAsOfDate: '2026-05-01T00:00:00Z',
          freshAsOfNote: 'Reviewed by security.',
          contractStartDate: '2026-01-01T00:00:00Z',
          contractEndDate: '2027-01-01T00:00:00Z',
          status: 'active',
        },
      ];
    }
    if (u.pathname === '/v1/users') {
      return [
        {
          id: 'u-1',
          userId: 'global-1',
          email: 'ada@example.com',
          givenName: 'Ada',
          surname: 'Lovelace',
          title: 'Compliance Manager',
          type: 'activeUser',
          status: 'active',
        },
        {
          id: 'u-2',
          email: 'gone@example.com',
          givenName: 'Former',
          surname: 'Person',
          type: 'deactivatedUser',
          status: 'active',
        },
        // A service account with no email — must be dropped, not emitted blank.
        { id: 'u-3', type: 'serviceAccount', status: 'active' },
      ];
    }
    if (u.pathname === '/v1/risks') {
      return [
        {
          id: 'r-1',
          riskIdentifier: 'FGSC-RA1',
          name: 'Unpatched dependency',
          description: 'A known CVE remains unpatched.',
          category: 'Security',
          response: 'mitigate',
          ownerId: 'u-1',
          status: 'active',
          likelihoodLevel: 3,
          impactLevel: 4,
          overrideResidualLikelihood: true,
          residualLikelihoodLevel: 1,
          // Residual impact is NOT overridden, so its level must not be read as
          // a residual score even though the field is populated.
          overrideResidualImpact: false,
          residualImpactLevel: 2,
          customRiskScales: { likelihood: FIVE_STEP, impact: FIVE_STEP },
        },
        {
          id: 'r-2',
          name: 'No scales published',
          // No customRiskScales: the number of steps is unknown, so no score.
          likelihoodLevel: 2,
          impactLevel: 2,
          response: 'notSet',
          ownerId: 'not-a-known-user',
        },
      ];
    }
    if (u.pathname === '/v1/policies') {
      return [
        {
          id: 'p-1',
          name: 'Access Control Policy',
          description: 'How access is granted.',
          policyApprovalStatus: 'approved',
          effectiveDate: '2026-01-01T00:00:00Z',
          effectiveDocumentId: 'doc-1',
        },
      ];
    }
    if (u.pathname === '/v1/policyversions') {
      assert.equal(u.searchParams.get('policyId'), 'p-1');
      return [
        {
          id: 'pv-old',
          policyId: 'p-1',
          revisionStatus: 'retired',
          effectiveDate: '2025-01-01T00:00:00Z',
          status: 'active',
        },
        {
          id: 'pv-1',
          policyId: 'p-1',
          revisionStatus: 'effective',
          approvedDate: '2026-04-02T00:00:00Z',
          effectiveDate: '2026-04-05T00:00:00Z',
          // Hyperproof's own example is scheme-less; it must not become a link.
          shareLink: 'www.hyperproof.io',
          publishedUrl: 'https://policies.example.com/access-control',
          status: 'active',
        },
      ];
    }
    return emptyDefaults(u);
  });

  const r = await hyperproofAdapter.export(CREDS, http);

  assert.equal(r.vendors.length, 1);
  const vendor = r.vendors[0]!;
  assert.equal(vendor.name, 'Example Inc');
  // Inherent (assessedRiskLevel) and residual (riskLevel) are kept apart.
  assert.equal(vendor.criticality, 'critical');
  assert.equal(vendor.residualCriticality, 'medium');
  assert.equal(vendor.status, 'approved');
  assert.equal(vendor.reviewLastAt, '2026-05-01T00:00:00Z');
  // The Vendor schema carries no website field, so none is invented.
  assert.equal(vendor.website, null);
  assert.match(vendor.notes ?? '', /Category: Compliance/);

  // The user with no email is dropped rather than emitted unusable.
  assert.equal(r.people.length, 2);
  assert.deepEqual(
    r.people.map((p) => [p.email, p.active]),
    [
      ['ada@example.com', true],
      ['gone@example.com', false],
    ],
  );
  assert.equal(r.people[0]!.fullName, 'Ada Lovelace');
  assert.equal(r.people[0]!.jobTitle, 'Compliance Manager');

  assert.equal(r.risks.length, 2);
  const risk = r.risks[0]!;
  // A 0-based level into a 5-step scale is that position on the bundle's 1-5.
  assert.equal(risk.likelihood, 4);
  assert.equal(risk.impact, 5);
  assert.equal(risk.residualLikelihood, 2);
  // Populated but not overridden: not a residual score, so not exported as one.
  assert.equal(risk.residualImpact, null);
  assert.equal(risk.treatment, 'mitigate');
  // The owner uuid resolves to an email through the users list.
  assert.equal(risk.ownerRef, 'ada@example.com');
  assert.equal(risk.title, 'Unpatched dependency');

  const unscored = r.risks[1]!;
  // No published scale means the step count is unknown — null, not a guess.
  assert.equal(unscored.likelihood, null);
  assert.equal(unscored.impact, null);
  // 'notSet' is not a treatment.
  assert.equal(unscored.treatment, null);
  // An unresolvable owner falls back to the opaque id rather than being dropped.
  assert.equal(unscored.ownerRef, 'not-a-known-user');

  assert.equal(r.policies.length, 1);
  const policy = r.policies[0]!;
  // The effective version wins over the retired one.
  assert.equal(policy.status, 'effective');
  assert.equal(policy.approvedAt, '2026-04-02T00:00:00Z');
  assert.equal(policy.documentUrl, 'https://policies.example.com/access-control');
  // PolicyVersion has no version number, so none is manufactured.
  assert.equal(policy.version, null);

  // Documented completeness parameters are actually sent.
  assert.ok(urls.some((u) => u.includes('/v1/risks?status=active%2Carchived')));
  assert.ok(urls.some((u) => u.includes('/v1/users?includeDeactivated=true')));
  // No policy document bytes are fetched: no documented endpoint resolves a
  // document id, and the published link is off-host.
  assert.deepEqual(r.files, []);
});

test('hyperproof: a scheme-less published link is not exported as a document URL', async () => {
  const { http } = stubHttp((u) => {
    if (u.pathname === '/v1/policies') return [{ id: 'p-1', name: 'Policy' }];
    if (u.pathname === '/v1/policyversions') {
      return [{ id: 'pv-1', revisionStatus: 'effective', shareLink: 'www.hyperproof.io' }];
    }
    return emptyDefaults(u);
  });

  const r = await hyperproofAdapter.export(CREDS, http);
  assert.equal(r.policies[0]!.documentUrl, null);
});

test('hyperproof: follows the proof nextToken cursor and downloads the bytes', async () => {
  const { http, urls } = stubHttp(
    (u) => {
      if (u.pathname !== '/v1/proof') return emptyDefaults(u);
      assert.equal(u.searchParams.get('limit'), '500');
      const token = u.searchParams.get('nextToken');
      if (!token) {
        return {
          data: [
            {
              id: 'pf-1',
              filename: 'access-review.pdf',
              contentType: 'application/pdf',
              status: 'active',
              uploadedOn: '2026-03-01T00:00:00Z',
              source: 'localComputer',
              version: 2,
            },
          ],
          nextToken: 'tok-2',
        };
      }
      return {
        data: [
          // Archived proof is skipped: not what the customer is carrying forward.
          { id: 'pf-old', filename: 'stale.pdf', status: 'archived' },
          {
            id: 'pf-2',
            nameOverride: 'Board minutes',
            filename: 'minutes.pdf',
            contentType: 'application/pdf',
            status: 'active',
          },
        ],
      };
    },
    (u) => ({
      bytes: new TextEncoder().encode(`bytes for ${u.pathname}`),
      contentType: 'application/pdf',
    }),
  );

  const r = await hyperproofAdapter.export(CREDS, http);

  assert.equal(r.files.length, 2);
  assert.deepEqual(
    r.files.map((f) => [f.externalId, f.name, f.kind]),
    [
      ['pf-1', 'access-review.pdf', 'evidence'],
      // No extension on the override name, so one is derived from the content type.
      ['pf-2', 'board-minutes.pdf', 'evidence'],
    ],
  );
  // Real bytes, hashed — not an empty shell standing in for evidence.
  assert.ok(r.files[0]!.sizeBytes > 0);
  assert.match(r.files[0]!.sha256, /^[0-9a-f]{64}$/);
  assert.match(r.files[0]!.description ?? '', /Source: localComputer/);
  // Exactly the documented contents path is used for the download — asserted on
  // the parsed origin and pathname, never on a substring of the URL. (A substring
  // test would pass for `https://evil.test/?x=https://api.hyperproof.app/...`,
  // which is why CodeQL objects to the shape even where, as here, the receiver is
  // an array and the comparison is already exact.)
  assert.ok(urls.some((u) => matches(u, '/v1/proof/pf-1/contents')));
  // Two list pages, and no third once the cursor is exhausted.
  assert.equal(urls.filter((u) => matches(u, '/v1/proof')).length, 2);
});

test('hyperproof: stops and warns when the proof cursor stops advancing', async () => {
  // The server keeps handing back the same token. Without the repeat-token guard
  // this loops to MAX_PAGES, re-downloading the same evidence 500 times over.
  const { http, urls } = stubHttp(
    (u) => {
      if (u.pathname !== '/v1/proof') return emptyDefaults(u);
      return {
        data: [{ id: 'pf-1', filename: 'a.pdf', status: 'active' }],
        nextToken: 'same-token',
      };
    },
    () => ({ bytes: new TextEncoder().encode('x'), contentType: 'application/pdf' }),
  );

  const warnings: string[] = [];
  const realWarn = console.warn;
  console.warn = (...a: unknown[]) => void warnings.push(a.join(' '));
  try {
    const r = await hyperproofAdapter.export(CREDS, http);
    // Two list calls (the first, then the one that repeats) — not 500.
    assert.equal(urls.filter((u) => u.includes('/v1/proof?')).length, 2);
    // The repeated page is deduplicated, so the same proof is not exported twice.
    assert.equal(r.files.length, 1);
  } finally {
    console.warn = realWarn;
  }

  assert.ok(
    warnings.some((w) => w.includes('INCOMPLETE') && w.includes('pagination token')),
    `expected an explicit incompleteness warning, got: ${JSON.stringify(warnings)}`,
  );
});

test('hyperproof: warns when an unpaginated list lands exactly on a page-size cap', async () => {
  // 25 is Hyperproof's own documented default page size. Vendors documents no
  // pagination at all, so exactly-25 rows is the only visible sign of a silent
  // server-side cap — and the export must not pass for complete.
  const { http } = stubHttp((u) => {
    if (u.pathname === '/v1/vendors') {
      return Array.from({ length: 25 }, (_, i) => ({ id: `v-${i}`, name: `Vendor ${i}` }));
    }
    return emptyDefaults(u);
  });

  const warnings: string[] = [];
  const realWarn = console.warn;
  console.warn = (...a: unknown[]) => void warnings.push(a.join(' '));
  try {
    const r = await hyperproofAdapter.export(CREDS, http);
    assert.equal(r.vendors.length, 25);
  } finally {
    console.warn = realWarn;
  }

  assert.ok(
    warnings.some((w) => w.includes('INCOMPLETE') && w.includes('vendors')),
    `expected a cap warning for vendors, got: ${JSON.stringify(warnings)}`,
  );
});

test('hyperproof: a normal row count produces no truncation warning', async () => {
  const { http } = stubHttp((u) => {
    if (u.pathname === '/v1/vendors') {
      return Array.from({ length: 7 }, (_, i) => ({ id: `v-${i}`, name: `Vendor ${i}` }));
    }
    return emptyDefaults(u);
  });

  const warnings: string[] = [];
  const realWarn = console.warn;
  console.warn = (...a: unknown[]) => void warnings.push(a.join(' '));
  try {
    await hyperproofAdapter.export(CREDS, http);
  } finally {
    console.warn = realWarn;
  }
  assert.deepEqual(warnings, []);
});

test('hyperproof: refuses to run without both credentials', async () => {
  const { http } = stubHttp(emptyDefaults);
  await assert.rejects(
    () => hyperproofAdapter.export({ HYPERPROOF_CLIENT_ID: 'id' }, http),
    /HYPERPROOF_CLIENT_SECRET is required/,
  );
  await assert.rejects(
    () => hyperproofAdapter.export({ HYPERPROOF_CLIENT_SECRET: 'secret' }, http),
    /HYPERPROOF_CLIENT_ID is required/,
  );
});
