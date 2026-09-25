/**
 * Vanta adapter tests.
 *
 * The manifest is covered by the conformance suite. What is pinned here is the risk
 * score mapping: an unscored Vanta risk (likelihood/impact null or absent) must export
 * as null, not as 1 x 1. `Number(null)` is 0 and the 1-5 clamp lifted it to 1, so the
 * bundle carried an assessment nobody made.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { GuardedHttp } from '../src/http.js';
import { vantaAdapter } from '../src/adapters/vanta.js';

const CREDS = { VANTA_CLIENT_ID: 'id', VANTA_CLIENT_SECRET: 'secret' };

function stubHttp(risks: unknown[]): GuardedHttp {
  return {
    async postToken<T>(): Promise<T> {
      return { access_token: 'tok' } as T;
    },
    async getJson<T>(url: string): Promise<T> {
      const path = new URL(url).pathname;
      const data = path === '/v1/risk-scenarios' ? risks : [];
      return { results: { data, pageInfo: { hasNextPage: false } } } as T;
    },
    async getBinary(): Promise<never> {
      throw new Error('no binary in these fixtures');
    },
  } as unknown as GuardedHttp;
}

test('vanta: an unscored risk exports null scores, not 1 x 1', async () => {
  const out = await vantaAdapter.export(
    CREDS,
    stubHttp([
      { riskId: 'r-null', description: 'Null scores', likelihood: null, impact: null },
      { riskId: 'r-absent', description: 'No score fields' },
      { riskId: 'r-blank', description: 'Blank strings', likelihood: '', impact: '  ' },
      { riskId: 'r-junk', description: 'Not numbers', likelihood: 'high', impact: true },
    ]),
  );
  for (const r of out.risks) {
    assert.equal(r.likelihood, null, `${r.externalId} likelihood`);
    assert.equal(r.impact, null, `${r.externalId} impact`);
    assert.equal(r.residualLikelihood, null, `${r.externalId} residualLikelihood`);
    assert.equal(r.residualImpact, null, `${r.externalId} residualImpact`);
  }
  assert.equal(out.risks.length, 4);
});

test('vanta: a scored risk keeps its scores, clamped and rounded to 1-5', async () => {
  const out = await vantaAdapter.export(
    CREDS,
    stubHttp([
      {
        riskId: 'r-1',
        description: 'Scored',
        likelihood: 4,
        impact: '2',
        residualLikelihood: 9,
        residualImpact: 2.6,
      },
    ]),
  );
  const [r] = out.risks;
  assert.equal(r.likelihood, 4);
  assert.equal(r.impact, 2);
  assert.equal(r.residualLikelihood, 5);
  assert.equal(r.residualImpact, 3);
});
