import type { Adapter } from './adapter.js';
import { vantaAdapter } from './adapters/vanta.js';
import { drataAdapter } from './adapters/drata.js';

/** All source adapters, keyed by source name. Add new platforms here. */
export const adapters: Record<string, Adapter> = {
  vanta: vantaAdapter,
  drata: drataAdapter,
};
