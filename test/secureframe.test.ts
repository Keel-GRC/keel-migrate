/**
 * Secureframe adapter tests.
 *
 * The manifest is covered by the conformance suite. What is pinned here is the
 * mapping, the page/per_page walk (including the case where the API reports more
 * records than it hands back), the auth header — which is a space-separated
 * key/secret pair rather than a Bearer token and is easy to regress into the
 * wrong shape — and the two registers this adapter deliberately leaves empty.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { GuardedHttp } from '../src/http.js';
import { secureframeAdapter } from '../src/adapters/secureframe.js';

const CREDS = { SECUREFRAME_API_KEY: 'key-abc', SECUREFRAME_API_SECRET: 'secret-xyz' };

/**
 * A GuardedHttp stand-in driven by a URL→payload function, recording the headers
 * it was called with. The real guard is tested in conformance.test.ts.
 */
function stubHttp(handler: (url: URL) => unknown): {
  http: GuardedHttp;
  urls: string[];
  headers: Record<string, string>[];
} {
  const urls: string[] = [];
  const headers: Record<string, string>[] = [];
  const http = {
    async getJson<T>(url: string, h: Record<string, string> = {}): Promise<T> {
      urls.push(url);
      headers.push(h);
      return handler(new URL(url)) as T;
    },
    async getBinary(): Promise<never> {
      throw new Error('Secureframe exposes no document bytes — nothing should call this');
    },
  } as unknown as GuardedHttp;
  return { http, urls, headers };
}

/** Wrap rows in the JSON:API envelope every Secureframe list endpoint returns. */
function envelope(type: string, rows: Record<string, unknown>[], total?: number): unknown {
  return {
    data: rows.map((attributes) => ({ id: attributes.id, type, attributes })),
    meta: total == null ? undefined : { total },
  };
}

/** Every endpoint empty, so a test can override just the one it cares about. */
function emptyDefaults(): unknown {
  return { data: [], meta: { total: 0 } };
}

test('secureframe: maps TPRM vendors, risks and users into the neutral bundle', async () => {
  const { http, urls, headers } = stubHttp((u) => {
    if (u.pathname === '/tprm/vendors') {
      return envelope(
        'vendor',
        [
          {
            id: 'v-1',
            name: 'Example Inc',
            website: 'https://example.com',
            risk_level: 'High',
            vendor_status: 'accepted',
            archived: false,
            last_reviewed_at: '2026-05-01T00:00:00Z',
            services_provided: 'Email delivery',
            data_collected: 'Customer PII',
            environment_types: ['production'],
          },
          {
            id: 'v-2',
            name: 'Retired Vendor',
            risk_level: 'n_a',
            vendor_status: 'accepted',
            archived: true,
          },
        ],
        2,
      );
    }
    if (u.pathname === '/risks') {
      return envelope(
        'risk',
        [
          {
            id: 'r-1',
            custom_risk_id: 'RISK-14',
            description: 'A known CVE remains unpatched.',
            categories: ['Security', 'Operations'],
            treatment: 'mitigate',
            status: 'open',
            owner_id: 'user-uuid-1',
            notes: 'Reviewed at the March committee.',
            // The quantitative model Secureframe actually carries. None of it is
            // a 1-5 likelihood or impact, and none of it may become one.
            annualized_rate_of_occurrence: 0.4,
            asset_value: 250000,
            exposure_factor: 0.3,
            likelihood_justification: 'Exploit code is public.',
          },
        ],
        1,
      );
    }
    if (u.pathname === '/users') {
      return envelope(
        'user',
        [
          {
            id: 'u-1',
            email: 'ada@example.com',
            name: 'Ada Lovelace',
            title: 'Compliance Manager',
            active: true,
            employee_type: 'employee',
            manager_name: 'Grace Hopper',
            department_id: 'dept-1',
          },
          {
            id: 'u-2',
            email: 'gone@example.com',
            first_name: 'Former',
            last_name: 'Person',
            active: true,
            end_date: '2026-01-31T00:00:00Z',
          },
          // No email — must be dropped, not emitted with a blank one.
          { id: 'u-3', name: 'Ghost', active: true },
        ],
        3,
      );
    }
    return emptyDefaults();
  });

  const r = await secureframeAdapter.export(CREDS, http);

  // Auth is the space-separated pair, NOT a Bearer token.
  assert.ok(headers.length > 0);
  for (const h of headers) assert.equal(h.Authorization, 'key-abc secret-xyz');

  assert.equal(r.vendors.length, 2);
  const vendor = r.vendors[0]!;
  assert.equal(vendor.name, 'Example Inc');
  assert.equal(vendor.website, 'https://example.com');
  assert.equal(vendor.criticality, 'high');
  // Secureframe scores one level per vendor; residual is not duplicated from it.
  assert.equal(vendor.residualCriticality, null);
  assert.equal(vendor.status, 'accepted');
  assert.equal(vendor.reviewLastAt, '2026-05-01T00:00:00Z');
  assert.match(vendor.notes ?? '', /Services: Email delivery/);
  // Archived outranks the review outcome, and an off-scale risk level is null.
  assert.equal(r.vendors[1]!.status, 'archived');
  assert.equal(r.vendors[1]!.criticality, null);

  assert.equal(r.risks.length, 1);
  const risk = r.risks[0]!;
  assert.equal(risk.title, 'RISK-14');
  assert.match(risk.description ?? '', /A known CVE remains unpatched\./);
  assert.match(risk.description ?? '', /March committee/);
  assert.equal(risk.category, 'Security');
  assert.equal(risk.treatment, 'mitigate');
  assert.equal(risk.status, 'open');
  // The owner reference stays the opaque id — no email is manufactured for it.
  assert.equal(risk.ownerRef, 'user-uuid-1');
  // Secureframe models no likelihood/impact at all, so nothing is coerced.
  assert.equal(risk.likelihood, null);
  assert.equal(risk.impact, null);
  assert.equal(risk.residualLikelihood, null);
  assert.equal(risk.residualImpact, null);
  // The ALE inputs survive untouched for a destination that understands them.
  assert.equal((risk.raw as Record<string, unknown>).annualized_rate_of_occurrence, 0.4);

  // The person with no email is dropped rather than emitted unusable.
  assert.equal(r.people.length, 2);
  assert.deepEqual(
    r.people.map((p) => [p.email, p.active]),
    [
      ['ada@example.com', true],
      // active: true, but a past end_date means offboarded.
      ['gone@example.com', false],
    ],
  );
  assert.equal(r.people[0]!.jobTitle, 'Compliance Manager');
  // manager_name is a display name, not an email, so it is not put in an email field.
  assert.equal(r.people[0]!.managerEmail, null);
  assert.equal(r.people[1]!.fullName, 'Former Person');

  // The deprecated /vendors endpoint is not called — it would duplicate every
  // vendor under a second id.
  assert.ok(!urls.some((u) => new URL(u).pathname === '/vendors'));
});

test('secureframe: leaves policies and evidence files empty, and says so', async () => {
  const { http, urls } = stubHttp(emptyDefaults);

  const warnings: string[] = [];
  const realWarn = console.warn;
  console.warn = (...a: unknown[]) => void warnings.push(a.join(' '));
  let r;
  try {
    r = await secureframeAdapter.export(CREDS, http);
  } finally {
    console.warn = realWarn;
  }

  // Under-delivering visibly beats mapping /ssp_policies onto the policy register:
  // an SSP policy row is not a policy document, and the wrong mapping would import
  // cleanly and read plausibly.
  assert.deepEqual(r.policies, []);
  assert.deepEqual(r.files, []);
  assert.ok(!urls.some((u) => new URL(u).pathname.startsWith('/ssp_policies')));
  assert.ok(!urls.some((u) => new URL(u).pathname.startsWith('/evidences')));
  assert.ok(
    warnings.some((w) => w.includes('policies and evidence files are NOT part of this export')),
    `expected an explicit under-delivery warning, got: ${JSON.stringify(warnings)}`,
  );
});

test('secureframe: pages through page/per_page until a short page', async () => {
  const { http, urls } = stubHttp((u) => {
    if (u.pathname !== '/users') return emptyDefaults();
    const page = Number(u.searchParams.get('page') ?? 1);
    assert.equal(u.searchParams.get('per_page'), '100');
    // Two full pages of 100, then a short third page ends the walk.
    const size = page <= 2 ? 100 : 30;
    return envelope(
      'user',
      Array.from({ length: size }, (_, i) => ({
        id: `u-${page}-${i}`,
        email: `p${page}-${i}@example.com`,
        active: true,
      })),
      230,
    );
  });

  const r = await secureframeAdapter.export(CREDS, http);

  assert.equal(r.people.length, 230);
  assert.equal(urls.filter((u) => new URL(u).pathname === '/users').length, 3);
});

test('secureframe: warns when fewer records come back than the API says exist', async () => {
  // The API reports 500 users and hands back one short page. Without the
  // reconciliation this exports 40 people and reports success — a migration that
  // silently loses 92% of the personnel register.
  const { http } = stubHttp((u) => {
    if (u.pathname !== '/users') return emptyDefaults();
    return envelope(
      'user',
      Array.from({ length: 40 }, (_, i) => ({
        id: `u-${i}`,
        email: `p${i}@example.com`,
        active: true,
      })),
      500,
    );
  });

  const warnings: string[] = [];
  const realWarn = console.warn;
  console.warn = (...a: unknown[]) => void warnings.push(a.join(' '));
  try {
    const r = await secureframeAdapter.export(CREDS, http);
    assert.equal(r.people.length, 40);
  } finally {
    console.warn = realWarn;
  }

  assert.ok(
    warnings.some((w) => w.includes('INCOMPLETE') && w.includes('500') && w.includes('users')),
    `expected an explicit incompleteness warning, got: ${JSON.stringify(warnings)}`,
  );
});

test('secureframe: refuses to run without both credentials', async () => {
  const { http } = stubHttp(emptyDefaults);
  await assert.rejects(
    () => secureframeAdapter.export({ SECUREFRAME_API_KEY: 'k' }, http),
    /SECUREFRAME_API_SECRET is required/,
  );
  await assert.rejects(
    () => secureframeAdapter.export({ SECUREFRAME_API_SECRET: 's' }, http),
    /SECUREFRAME_API_KEY is required/,
  );
});
