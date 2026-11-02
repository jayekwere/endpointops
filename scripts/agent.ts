import { randomUUID } from 'node:crypto';
import { collect } from '../src/collector.js';
import { diagnoseNetwork } from '../src/diagnostics.js';
import { Id } from '../src/security.js';
import { fixedUrl, boundedJson } from '../src/net.js';
const deviceId = Id.parse(process.env.DEVICE_ID),
  tenant = Id.parse(process.env.TENANT_ID),
  token = process.env.DEVICE_TOKEN;
if (!token || token.length < 32) throw new Error('A private enrolled device token is required');
const base = fixedUrl(process.env.SERVER_URL ?? 'http://127.0.0.1:4420', true);
if (base.pathname !== '/') throw new Error('SERVER_URL must be an origin');
const snapshot = collect(deviceId);
if (process.env.PROBE_HOST)
  snapshot.diagnostics.network = await diagnoseNetwork(process.env.PROBE_HOST);
const result = await boundedJson(new URL('/ingest/device', base), {
  method: 'POST',
  headers: { authorization: 'Bearer ' + token },
  body: { tenant, deviceId, nonce: randomUUID(), sentAt: new Date().toISOString(), snapshot },
});
console.log(JSON.stringify(result.data, null, 2));
