import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { environment } from './environment.js';
import { collect } from '../src/collector.js';
import { SnapshotSchema } from '../src/policies.js';
const e = await environment();
const headers = (role: string) => ({
  host: new URL('http://127.0.0.1:4420').host,
  authorization: 'Bearer ' + e.tokens[role],
});
async function call(path: string, role: string, body?: unknown) {
  const response = await e.app.inject({
    method: body === undefined ? 'GET' : 'POST',
    url: path,
    headers: headers(role),
    ...(body !== undefined ? { payload: body as Record<string, unknown> } : {}),
  });
  return { status: response.statusCode, body: response.json() };
}
async function planAndApprove(data: unknown) {
  const p = await call('/api/plans', 'requester', data);
  assert.equal(p.status, 201);
  const reviewed = await call('/api/plans/' + p.body.id + '/review', 'reviewer', {
    digest: p.body.digest,
    approve: true,
  });
  assert.equal(reviewed.status, 200);
  return p.body;
}
try {
  const ticket = (await call('/api/tickets', 'operator')).body.tickets[0];
  const premature = await call('/api/tickets/' + ticket.id, 'operator', { status: 'resolved' });
  assert.equal(premature.status, 409);
  const p = await planAndApprove({ deviceId: 'lab-laptop', action: 'enable-lab-firewall' });
  const repaired = await call('/api/plans/' + p.id + '/execute', 'operator', {
    digest: p.digest,
    key: 'demo-firewall-repair',
  });
  assert.equal(repaired.body.status, 'completed');
  const before = e.store.need<{ version: number }>('sandbox', 'device', 'lab-laptop').version;
  await call('/api/plans/' + p.id + '/execute', 'operator', {
    digest: p.digest,
    key: 'demo-firewall-repair',
  });
  assert.equal(
    e.store.need<{ version: number }>('sandbox', 'device', 'lab-laptop').version,
    before,
  );
  const resolved = await call('/api/tickets/' + ticket.id, 'operator', { status: 'resolved' });
  assert.equal(resolved.body.status, 'resolved');
  const support = (await call('/api/devices/lab-laptop/support', 'operator')).body;
  assert.equal(SnapshotSchema.safeParse(collect('local-collector-validation')).success, true);
  const output = {
    scope: 'synthetic device remediation, real read-only collector contract checked separately',
    prematureClosureStatus: premature.status,
    repair: repaired.body.result,
    duplicateMutation: false,
    ticketStatus: resolved.body.status,
    passingChecks: support.findings.filter((f: { state: string }) => f.state === 'pass').length,
    collector: {
      schemaValidated: true,
      publicReadings: 'omitted to avoid publishing workstation posture',
    },
    supportBundlePrivacy: support.privacy,
    auditIntegrity: e.store.verify(),
  };
  if (process.argv.includes('--write'))
    writeFileSync('evidence/demo.json', JSON.stringify(output, null, 2) + '\n');
  console.log(JSON.stringify(output, null, 2));
} finally {
  await e.close();
}
