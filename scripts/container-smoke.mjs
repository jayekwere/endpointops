import { execFileSync } from 'node:child_process';
import assert from 'node:assert/strict';
const image = process.argv[2] ?? 'endpointops:local',
  name = 'endpointops-smoke-' + process.pid,
  base = 'http://127.0.0.1:4420';
const docker = (args) =>
  execFileSync('docker', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
try {
  docker([
    'run',
    '--rm',
    '-d',
    '--name',
    name,
    '--read-only',
    '--cap-drop=ALL',
    '--security-opt=no-new-privileges',
    '--memory=512m',
    '--pids-limit=128',
    '--tmpfs',
    '/tmp:rw,noexec,nosuid,size=32m',
    '-e',
    'DEMO=1',
    '-e',
    'BASE_URL=' + base,
    '-p',
    '127.0.0.1:4420:4420',
    image,
  ]);
  let ready = false;
  for (let n = 0; n < 60; n++) {
    try {
      if ((await fetch(base + '/health')).ok) {
        ready = true;
        break;
      }
    } catch {}
    await new Promise((r) => setTimeout(r, 250));
  }
  assert.ok(ready, 'Container became healthy');
  assert.equal(docker(['exec', name, 'id', '-u']), '1000');
  const logs = docker(['logs', name]),
    tokens = JSON.parse(logs.split('Ephemeral demo tokens (15 minutes):\n')[1]);
  const call = async (path, role, body) => {
    const r = await fetch(base + path, {
      method: body === undefined ? 'GET' : 'POST',
      headers: {
        authorization: 'Bearer ' + tokens[role],
        ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
      },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    return { status: r.status, body: await r.json() };
  };
  assert.equal((await fetch(base + '/api/overview')).status, 401);
  assert.equal((await call('/api/overview', 'outsider')).status, 200);
  const p = (
    await call('/api/plans', 'requester', { deviceId: 'lab-laptop', action: 'enable-lab-firewall' })
  ).body;
  await call('/api/plans/' + p.id + '/review', 'reviewer', { digest: p.digest, approve: true });
  assert.equal(
    (
      await call('/api/plans/' + p.id + '/execute', 'operator', {
        digest: p.digest,
        key: 'container-repair',
      })
    ).body.status,
    'completed',
  );
  const data = (await call('/api/overview', 'operator')).body;
  assert.ok(data.devices[0].findings.every((f) => f.state === 'pass'));
  const ticket = data.tickets[0];
  assert.equal(
    (await call('/api/tickets/' + ticket.id, 'operator', { status: 'resolved' })).body.status,
    'resolved',
  );
  assert.equal((await call('/api/overview', 'outsider')).body.devices.length, 0);
  console.log(
    'PASS: UID 1000, read-only container, authentication, approved lab repair, persisted readback, ticket closure and tenant isolation',
  );
} finally {
  try {
    docker(['rm', '-f', name]);
  } catch {}
}
