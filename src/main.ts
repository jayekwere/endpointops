import { readFileSync } from 'node:fs';
import { z } from 'zod';
import { configuration } from './config.js';
import { Store } from './store.js';
import { createApp } from './app.js';
import { seed } from './lab.js';
const c = await configuration('endpointops', 4420),
  store = new Store(c.db, c.key);
let fleet;
if (process.env.FLEET_CONFIG) {
  const config = z
    .object({
      tenant: z.string(),
      endpoint: z.url(),
      tokenEnv: z.string().regex(/^[A-Z][A-Z0-9_]+$/),
      bindings: z.record(z.string(), z.number().int().positive()),
      policyIds: z
        .object({
          diskEncrypted: z.number().int().positive(),
          firewallEnabled: z.number().int().positive(),
          patchAgeDays: z.number().int().positive(),
          localAdminCount: z.number().int().positive(),
          mdmEnrolled: z.number().int().positive(),
        })
        .strict(),
    })
    .strict()
    .parse(JSON.parse(readFileSync(process.env.FLEET_CONFIG, 'utf8')));
  const token = process.env[config.tokenEnv];
  if (!token || c.demo) throw new Error('Fleet requires configured mode and a dedicated token');
  fleet = {
    tenant: config.tenant,
    config: { endpoint: config.endpoint, token, policyIds: config.policyIds },
    bindings: config.bindings,
  };
}
const { app, service } = createApp({
  auth: c.auth,
  store,
  baseUrl: c.baseUrl,
  ...(fleet ? { fleet } : {}),
});
if (c.demo) seed(service, store.now());
await app.listen({ port: c.port, host: c.host });
console.log(`EndpointOps listening at ${c.baseUrl}`);
if (c.demo)
  console.log('Ephemeral demo tokens (15 minutes):\n' + JSON.stringify(c.tokens, null, 2));
for (const signal of ['SIGINT', 'SIGTERM'] as const)
  process.on(signal, () => {
    void app.close().then(() => {
      store.close();
      process.exit(0);
    });
  });
