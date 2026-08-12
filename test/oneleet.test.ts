/**
 * Oneleet adapter tests.
 *
 * The manifest is already covered by the conformance suite. What is tested here
 * is the mapping and, above all, the PAGINATION PROBE — the one piece of this
 * adapter that reasons about an undocumented parameter. Its failure mode
 * (silently exporting page 1 of N as if it were the whole tenant) is exactly the
 * kind of bug a migration tool must never have, so it is pinned by a test rather
 * than trusted to a comment.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { GuardedHttp } from '../src/http.js';
import { oneleetAdapter } from '../src/adapters/oneleet.js';

const CREDS = { ONELEET_API_KEY: 'service_x_y', ONELEET_TENANT_ID: 'tenant-1' };

/**
 * A GuardedHttp stand-in driven by a URL→payload function. The real guard is
 * tested in conformance.test.ts; here we only need the adapter's request shape
 * and its handling of the responses.
 */
function stubHttp(handler: (url: URL) => unknown): {
  http: GuardedHttp;
  urls: string[];
} {
  const urls: string[] = [];
  const http = {
    async getJson<T>(url: string): Promise<T> {
      urls.push(url);
      return handler(new URL(url)) as T;
    },
    async getBinary(): Promise<never> {
      throw new Error('no binary in these fixtures');
    },
  } as unknown as GuardedHttp;
  return { http, urls };
}

/** Every list endpoint empty, so a test can override just the one it cares about. */
function emptyDefaults(u: URL): unknown {
  if (u.pathname.endsWith('/risk-assessments')) return [];
  return { rows: [], pagination: { current_page: 1, next_page: 1, num_pages: 1 } };
}

test('oneleet: maps vendors, members, policies and risks into the neutral bundle', async () => {
  const { http } = stubHttp((u) => {
    if (u.pathname.endsWith('/vendors')) {
      return {
        rows: [
          {
            id: 'tv-1',
            risk: 'HIGH',
            isCompleted: true,
            reviewedAt: '2026-05-01T00:00:00Z',
            notes: 'Processes customer PII.',
            services: ['Email delivery', 'Analytics'],
            vendorUrl: 'https://example.com',
            vendor: { id: 'v-1', name: 'Example Inc', url: 'https://vendor.example' },
          },
        ],
        pagination: { current_page: 1, next_page: 1, num_pages: 1 },
      };
    }
    if (u.pathname.endsWith('/members')) {
      return {
        rows: [
          {
            id: 'm-1',
            name: 'Ada Lovelace',
            status: 'CURRENT',
            groups: [{ name: 'Engineering' }, { name: 'Admins' }],
            user: { email: 'ada@example.com', name: 'Ada Lovelace' },
          },
          {
            id: 'm-2',
            name: 'Former Person',
            status: 'FORMER',
            userPublic: { email: 'gone@example.com', name: 'Former Person' },
          },
          // No email anywhere — must be dropped, not emitted with a blank email.
          { id: 'm-3', name: 'Ghost', status: 'CURRENT' },
        ],
        pagination: { current_page: 1, next_page: 1, num_pages: 1 },
      };
    }
    if (u.pathname.endsWith('/policies')) {
      return {
        rows: [
          {
            id: 'p-1',
            name: 'Access Control Policy',
            description: 'How access is granted.',
            currentVersion: {
              versionNumber: 3,
              minorVersionNumber: 2,
              status: 'PUBLISHED',
              publishedAt: '2026-04-02T00:00:00Z',
              // Deliberately absent fileUrl: no document to fetch, no download attempt.
            },
          },
        ],
        pagination: { current_page: 1, next_page: 1, num_pages: 1 },
      };
    }
    if (u.pathname.endsWith('/risk-assessments')) return [{ id: 'ra-1' }];
    if (u.pathname.startsWith('/api/v1/risks-assessments/')) {
      return {
        id: 'ra-1',
        title: '2026 Annual Assessment',
        risks: [
          {
            id: 'r-1',
            title: 'Unpatched dependency',
            description: 'A known CVE remains unpatched.',
            category: 'LEGAL_AND_COMPLIANCE',
            likelihood: 'LIKELY',
            impact: 'MAJOR',
            residualLikelihood: 'UNLIKELY',
            residualImpact: 'MINOR',
            response: 'MITIGATE',
            owner: { email: 'owner@example.com' },
          },
        ],
      };
    }
    return emptyDefaults(u);
  });

  const r = await oneleetAdapter.export(CREDS, http);

  assert.equal(r.vendors.length, 1);
  assert.equal(r.vendors[0].name, 'Example Inc');
  assert.equal(r.vendors[0].criticality, 'high');
  assert.equal(r.vendors[0].status, 'active');
  assert.match(r.vendors[0].notes ?? '', /Services: Email delivery, Analytics/);

  // The person with no email is dropped rather than emitted unusable.
  assert.equal(r.people.length, 2);
  assert.deepEqual(
    r.people.map((p) => [p.email, p.active]),
    [
      ['ada@example.com', true],
      ['gone@example.com', false],
    ],
  );
  assert.deepEqual(r.people[0].groups, ['Engineering', 'Admins']);

  assert.equal(r.policies.length, 1);
  assert.equal(r.policies[0].version, '3.2');
  assert.equal(r.policies[0].status, 'published');

  assert.equal(r.risks.length, 1);
  const risk = r.risks[0];
  // The five-point ordinal enums must land on the bundle's 1-5 scale, not 0 or null.
  assert.equal(risk.likelihood, 4);
  assert.equal(risk.impact, 4);
  assert.equal(risk.residualLikelihood, 2);
  assert.equal(risk.residualImpact, 2);
  assert.equal(risk.treatment, 'mitigate');
  assert.equal(risk.category, 'legal and compliance');
  assert.equal(risk.ownerRef, 'owner@example.com');
});

test('oneleet: follows pagination when the API honours ?page=', async () => {
  const { http, urls } = stubHttp((u) => {
    if (!u.pathname.endsWith('/vendors')) return emptyDefaults(u);
    const page = Number(u.searchParams.get('page') ?? 1);
    return {
      rows: [{ id: `tv-${page}`, vendor: { name: `Vendor ${page}` } }],
      pagination: { current_page: page, next_page: page + 1, num_pages: 3 },
    };
  });

  const r = await oneleetAdapter.export(CREDS, http);

  assert.equal(r.vendors.length, 3);
  assert.deepEqual(
    r.vendors.map((v) => v.name),
    ['Vendor 1', 'Vendor 2', 'Vendor 3'],
  );
  assert.equal(urls.filter((u) => u.includes('/vendors')).length, 3);
});

test('oneleet: stops and warns when the API ignores ?page= instead of looping', async () => {
  // The endpoint claims three pages but always returns page 1 — the real risk.
  // Without the non-advancement check this either loops to MAX_PAGES emitting
  // the same rows repeatedly, or quietly reports a third of the tenant as all of it.
  const { http, urls } = stubHttp((u) => {
    if (!u.pathname.endsWith('/vendors')) return emptyDefaults(u);
    return {
      rows: [{ id: 'tv-1', vendor: { name: 'Only Vendor' } }],
      pagination: { current_page: 1, next_page: 2, num_pages: 3 },
    };
  });

  const warnings: string[] = [];
  const realWarn = console.warn;
  console.warn = (...a: unknown[]) => void warnings.push(a.join(' '));
  try {
    const r = await oneleetAdapter.export(CREDS, http);
    // One page's worth of rows, and exactly one probe beyond page 1 — not 200.
    assert.equal(r.vendors.length, 1);
    assert.equal(urls.filter((u) => u.includes('/vendors')).length, 2);
  } finally {
    console.warn = realWarn;
  }

  assert.ok(
    warnings.some((w) => w.includes('INCOMPLETE') && w.includes('vendors')),
    `expected an explicit incompleteness warning, got: ${JSON.stringify(warnings)}`,
  );
});

test('oneleet: refuses to run without both credentials', async () => {
  const { http } = stubHttp(emptyDefaults);
  await assert.rejects(
    () => oneleetAdapter.export({ ONELEET_API_KEY: 'k' }, http),
    /ONELEET_TENANT_ID is required/,
  );
  await assert.rejects(
    () => oneleetAdapter.export({ ONELEET_TENANT_ID: 't' }, http),
    /ONELEET_API_KEY is required/,
  );
});
