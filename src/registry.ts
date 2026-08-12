import type { Adapter } from './adapter.js';
import { vantaAdapter } from './adapters/vanta.js';
import { drataAdapter } from './adapters/drata.js';
import { onetrustAdapter } from './adapters/onetrust.js';
import { oneleetAdapter } from './adapters/oneleet.js';
import { hyperproofAdapter } from './adapters/hyperproof.js';
import { secureframeAdapter } from './adapters/secureframe.js';

/**
 * All source adapters, keyed by source name. Add new platforms here.
 *
 * An adapter can only exist where the platform publishes endpoint-level
 * documentation: every manifest declares an `officialDocsUrl` and a `docUrl` per
 * endpoint, and the conformance test enforces it. That is not bureaucracy — an
 * adapter built on a guessed path fails against a real customer's credentials,
 * at the moment they are trying to leave, with their data on the line.
 *
 * Platforms surveyed and NOT added, so the next person does not repeat the search:
 * Sprinto (GraphQL; schema needs a key to introspect, no documented read queries),
 * Scrut (no API documentation exists publicly), Thoropass (developer portal
 * returns 401 /inactive), Conveyor (documented, but a questionnaire/trust-centre
 * product with no risks, people or policies), Apptega (api host 403s, no docs or
 * developer subdomain, knowledge base 404s, sitemap carries no API page — the
 * "open API" is a sales statement routing you to their team).
 */
export const adapters: Record<string, Adapter> = {
  vanta: vantaAdapter,
  drata: drataAdapter,
  onetrust: onetrustAdapter,
  oneleet: oneleetAdapter,
  hyperproof: hyperproofAdapter,
  secureframe: secureframeAdapter,
};
