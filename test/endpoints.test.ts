import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { Store } from '../src/store.js';
import { Endpoints, type Ticket } from '../src/endpoints.js';
import { evaluate, type Snapshot, type Device } from '../src/policies.js';
import { seed } from '../src/lab.js';
import { demoAuth, type Identity } from '../src/security.js';
import { createApp } from '../src/app.js';
import { fetchFleet } from '../src/fleet.js';
import { collect } from '../src/collector.js';
const op: Identity = { subject: 'operator', tenant: 'sandbox', roles: ['operator'] },
  req: Identity = { subject: 'requester', tenant: 'sandbox', roles: ['requester'] },
  rev: Identity = { subject: 'reviewer', tenant: 'sandbox', roles: ['reviewer'] };
function setup() {
  let now = Date.now();
  const store = new Store(':memory:', 'k'.repeat(32), () => now),
    service = new Endpoints(store);
  seed(service, now);
  return {
    store,
    service,
    advance: (n: number) => {
      now += n;
    },
  };
}
function snapshot(id: string, now = Date.now()): Snapshot {
  return {
    deviceId: id,
    observedAt: new Date(now).toISOString(),
    platform: 'linux',
    source: 'device-agent',
    checks: {
      diskEncrypted: null,
      firewallEnabled: null,
      patchAgeDays: null,
      localAdminCount: null,
      mdmEnrolled: null,
    },
    diagnostics: { osRelease: 'Synthetic Linux', uptimeSeconds: 10, freeDiskBytes: 1000 },
  };
}
function enrolled(s: ReturnType<typeof setup>, id = 'managed-001') {
  return s.service.enroll(op, {
    id,
    label: 'Synthetic managed device',
    platform: 'linux',
    region: 'EU',
    serialAlias: 'serial-' + id,
    mode: 'managed-observation',
  });
}
function approved(s: ReturnType<typeof setup>) {
  const p = s.service.plan(req, { deviceId: 'lab-laptop', action: 'enable-lab-firewall' });
  s.service.book.review(rev, p.id, p.digest, true);
  return p;
}
test('known failures, missing data and stale data are distinct from passing posture', () => {
  const s = setup();
  try {
    const states = s.service.list(op)[0]!.findings;
    assert.equal(states.filter((f) => f.state === 'fail').length, 1);
    assert.equal(evaluate(undefined)[0]!.state, 'unknown');
    assert.ok(evaluate(snapshot('test')).every((f) => f.state === 'unknown'));
    s.advance(86400001);
    assert.equal(s.service.list(op)[0]!.findings[0]!.id, 'stale-observation');
  } finally {
    s.store.close();
  }
});
test('approved local remediation verifies changed posture and replay causes no second mutation', () => {
  const s = setup();
  try {
    const p = approved(s),
      before = s.store.need<Device>('sandbox', 'device', 'lab-laptop').version;
    const done = s.service.execute(op, p.id, p.digest, 'repair-key');
    assert.equal(done.status, 'completed');
    assert.equal(
      s.service.list(op)[0]!.findings.find((f) => f.id === 'firewallEnabled')!.state,
      'pass',
    );
    s.service.execute(op, p.id, p.digest, 'repair-key');
    assert.equal(s.store.need<Device>('sandbox', 'device', 'lab-laptop').version, before + 1);
    assert.equal(s.store.verify(), true);
  } finally {
    s.store.close();
  }
});
test('ticket closure requires a fresh passing observation and preserves its evidence digest', () => {
  const s = setup();
  try {
    const t = s.service.tickets(op)[0]!;
    assert.throws(() => s.service.ticket(op, t.id, { status: 'resolved' }), {
      code: 'passing_readback_required',
    });
    s.service.ticket(op, t.id, { status: 'in-progress' });
    const p = approved(s);
    s.service.execute(op, p.id, p.digest, 'ticket-repair');
    const done = s.service.ticket(op, t.id, { status: 'resolved' });
    assert.equal(done.status, 'resolved');
    assert.equal(done.resolutionEvidence?.length, 64);
    assert.throws(() => s.service.ticket(op, t.id, { status: 'resolved' }), {
      code: 'ticket_already_resolved',
    });
  } finally {
    s.store.close();
  }
});
test('changed target, changed observation, stale snapshot and wrong digest prevent mutation', () => {
  for (const kind of ['device', 'observation', 'stale', 'digest']) {
    const s = setup();
    try {
      const p = approved(s);
      if (kind === 'device')
        s.service.transition(op, 'lab-laptop', {
          version: 1,
          state: 'assigned',
          ownerAlias: 'worker-001',
        });
      if (kind === 'observation') {
        const old = s.store.need<Snapshot>('sandbox', 'snapshot', 'lab-laptop');
        s.store.put('sandbox', 'snapshot', 'lab-laptop', {
          ...old,
          diagnostics: { ...old.diagnostics, freeDiskBytes: 2 },
        });
      }
      if (kind === 'stale') s.advance(86400001);
      assert.throws(() =>
        s.service.execute(op, p.id, kind === 'digest' ? 'f'.repeat(64) : p.digest, 'reject-key'),
      );
      assert.equal(
        s.store.need<Snapshot>('sandbox', 'snapshot', 'lab-laptop').checks.firewallEnabled,
        false,
      );
      assert.equal(s.service.book.get(op, p.id).status, 'approved');
    } finally {
      s.store.close();
    }
  }
});
test('physical devices cannot receive the synthetic remediation', () => {
  const s = setup();
  try {
    enrolled(s);
    const observation = {
      ...snapshot('managed-001'),
      source: 'manual-import' as const,
      checks: { ...snapshot('managed-001').checks, firewallEnabled: false },
    };
    s.service.ingest(op, observation);
    assert.throws(
      () => s.service.plan(req, { deviceId: 'managed-001', action: 'enable-lab-firewall' }),
      { code: 'physical_device_remediation_not_supported' },
    );
  } finally {
    s.store.close();
  }
});
test('device credentials are shown once, scoped, hashed in storage and omitted from exports', () => {
  const s = setup();
  try {
    const issued = enrolled(s);
    assert.ok(issued.deviceToken);
    const body = {
      tenant: 'sandbox',
      deviceId: 'managed-001',
      nonce: randomUUID(),
      sentAt: new Date().toISOString(),
      snapshot: snapshot('managed-001'),
    };
    assert.equal(s.service.agent(body, 'Bearer ' + issued.deviceToken).accepted, true);
    const raw = JSON.stringify(s.store.list('sandbox', 'device'));
    assert.equal(raw.includes(issued.deviceToken!), false);
    assert.equal(JSON.stringify(s.service.list(op)).includes('credentialHash'), false);
    assert.equal(
      JSON.stringify(s.service.support(op, 'managed-001')).includes('credentialHash'),
      false,
    );
    assert.throws(() => s.service.agent({ ...body, nonce: randomUUID() }, 'Bearer wrong'), {
      code: 'invalid_device_credential',
    });
    assert.throws(
      () => s.service.agent({ ...body, tenant: 'isolated' }, 'Bearer ' + issued.deviceToken),
      { code: 'invalid_device_credential' },
    );
  } finally {
    s.store.close();
  }
});
test('device ingestion rejects replay, forged device IDs, old envelopes and extra fields', () => {
  const s = setup();
  try {
    const issued = enrolled(s),
      body = {
        tenant: 'sandbox',
        deviceId: 'managed-001',
        nonce: randomUUID(),
        sentAt: new Date().toISOString(),
        snapshot: snapshot('managed-001'),
      };
    s.service.agent(body, 'Bearer ' + issued.deviceToken);
    assert.throws(() => s.service.agent(body, 'Bearer ' + issued.deviceToken), {
      code: 'device_replay',
    });
    assert.throws(
      () =>
        s.service.agent(
          { ...body, nonce: randomUUID(), snapshot: snapshot('another-device') },
          'Bearer ' + issued.deviceToken,
        ),
      { code: 'device_envelope_invalid' },
    );
    assert.throws(
      () =>
        s.service.agent(
          { ...body, nonce: randomUUID(), sentAt: '2020-01-01T00:00:00Z' },
          'Bearer ' + issued.deviceToken,
        ),
      { code: 'device_envelope_invalid' },
    );
    assert.throws(() =>
      s.service.agent({ ...body, username: 'personal-user' }, 'Bearer ' + issued.deviceToken),
    );
  } finally {
    s.store.close();
  }
});
test('manual credential rotation invalidates the old token immediately', () => {
  const s = setup();
  try {
    const old = enrolled(s),
      rotated = s.service.rotate(op, 'managed-001'),
      body = {
        tenant: 'sandbox',
        deviceId: 'managed-001',
        nonce: randomUUID(),
        sentAt: new Date().toISOString(),
        snapshot: snapshot('managed-001'),
      };
    assert.throws(() => s.service.agent(body, 'Bearer ' + old.deviceToken), {
      code: 'invalid_device_credential',
    });
    assert.equal(s.service.agent(body, 'Bearer ' + rotated.deviceToken).accepted, true);
  } finally {
    s.store.close();
  }
});
test('asset lifecycle checks versions, ownership and terminal retirement', () => {
  const s = setup();
  try {
    let d = s.service.transition(op, 'lab-laptop', {
      version: 1,
      state: 'assigned',
      ownerAlias: 'worker-001',
    });
    assert.equal(d.ownerAlias, 'worker-001');
    assert.throws(
      () => s.service.transition(op, d.id, { version: 1, state: 'returned', ownerAlias: null }),
      { code: 'asset_state_or_version_conflict' },
    );
    d = s.service.transition(op, d.id, { version: d.version, state: 'returned', ownerAlias: null });
    d = s.service.transition(op, d.id, { version: d.version, state: 'retired', ownerAlias: null });
    assert.throws(
      () =>
        s.service.transition(op, d.id, {
          version: d.version,
          state: 'assigned',
          ownerAlias: 'worker-001',
        }),
      { code: 'asset_state_or_version_conflict' },
    );
    assert.throws(() => s.service.plan(req, { deviceId: d.id, action: 'enable-lab-firewall' }), {
      code: 'device_retired',
    });
  } finally {
    s.store.close();
  }
});
test('stale or malformed observations cannot overwrite evidence and duplicates do not open duplicate tickets', () => {
  const s = setup();
  try {
    const before = s.store.need<Snapshot>('sandbox', 'snapshot', 'lab-laptop');
    const n = s.service.tickets(op).length;
    assert.equal(s.service.ingest(op, before).duplicate, true);
    assert.equal(s.service.tickets(op).length, n);
    assert.throws(() => s.service.ingest(op, { ...before, observedAt: '2020-01-01T00:00:00Z' }), {
      code: 'observation_contract_invalid',
    });
    assert.throws(() =>
      s.service.ingest(op, {
        ...before,
        observedAt: new Date(Date.parse(before.observedAt) + 1).toISOString(),
        credentials: 'private',
      }),
    );
  } finally {
    s.store.close();
  }
});
test('Fleet adapter validates the pinned host and retains unknown numeric checks', async () => {
  const config = {
    endpoint: 'https://fleet.invalid',
    token: 'dedicated-secret',
    policyIds: {
      diskEncrypted: 1,
      firewallEnabled: 2,
      patchAgeDays: 3,
      localAdminCount: 4,
      mdmEnrolled: 5,
    },
  };
  let authorization = '';
  const fetcher: typeof fetch = async (url, init) => {
    assert.equal(String(url), 'https://fleet.invalid/api/v1/fleet/hosts/7');
    authorization = (init?.headers as Record<string, string>).authorization ?? '';
    return new Response(
      JSON.stringify({
        host: {
          id: 7,
          platform: 'ubuntu',
          seen_time: new Date().toISOString(),
          policies: [
            { id: 1, response: 'pass' },
            { id: 2, response: 'fail' },
            { id: 5, response: null },
          ],
          password: 'must-not-be-retained',
        },
      }),
      { headers: { 'content-type': 'application/json' } },
    );
  };
  const result = await fetchFleet(config, 7, 'managed-001', false, fetcher);
  assert.equal(authorization, 'Bearer dedicated-secret');
  assert.equal(result.checks.diskEncrypted, true);
  assert.equal(result.checks.firewallEnabled, false);
  assert.equal(result.checks.patchAgeDays, null);
  assert.equal(result.diagnostics.freeDiskBytes, null);
  assert.equal(JSON.stringify(result).includes('must-not-be-retained'), false);
  await assert.rejects(
    fetchFleet(
      config,
      8,
      'managed-001',
      false,
      async () =>
        new Response(JSON.stringify({ host: { id: 7 } }), {
          headers: { 'content-type': 'application/json' },
        }),
    ),
  );
});
test('read-only local collector produces the strict contract without serials or account names', () => {
  const result = collect('collector-test');
  assert.equal(result.source, 'device-agent');
  assert.ok(['linux', 'darwin', 'windows'].includes(result.platform));
  assert.equal(result.checks.patchAgeDays, null);
  assert.equal('username' in result, false);
  assert.equal('serial' in result, false);
});
test('device observation budgets preserve control actions, other devices and tenant capacity', () => {
  const s = setup();
  const enrolledDevice = enrolled(s);
  const send = (id: string, token: string, now: number) =>
    s.service.agent(
      {
        tenant: 'sandbox',
        deviceId: id,
        nonce: randomUUID(),
        sentAt: new Date(now).toISOString(),
        snapshot: {
          ...snapshot(id, now),
          checks: {
            diskEncrypted: true,
            firewallEnabled: true,
            patchAgeDays: 1,
            localAdminCount: 1,
            mdmEnrolled: true,
          },
        },
      },
      'Bearer ' + token,
    );
  try {
    let now = s.store.now();
    for (let i = 0; i < 1000; i++) {
      s.advance(1);
      now = s.store.now();
      send('managed-001', enrolledDevice.deviceToken!, now);
    }
    assert.equal(s.store.auditCount('sandbox', 'device.observed', 'device:managed-001'), 1000);
    const before = s.store.need<Snapshot>('sandbox', 'snapshot', 'managed-001');
    const nonceCount = s.store.count('sandbox', 'nonce');
    s.advance(600001);
    assert.throws(() => send('managed-001', enrolledDevice.deviceToken!, s.store.now()), {
      code: 'device_observation_capacity_reached',
    });
    assert.deepEqual(s.store.need('sandbox', 'snapshot', 'managed-001'), before);
    assert.equal(s.store.count('sandbox', 'nonce'), nonceCount);
    // Pruning replay state does not reset the persisted observation budget.
    // Exact duplicate observations spend no audit budget; nonce replay state is still recorded.
    assert.equal(
      s.service.agent(
        {
          tenant: 'sandbox',
          deviceId: 'managed-001',
          nonce: randomUUID(),
          sentAt: new Date(s.store.now()).toISOString(),
          snapshot: before,
        },
        'Bearer ' + enrolledDevice.deviceToken,
      ).duplicate,
      true,
    );
    const rotated = s.service.rotate(op, 'managed-001');
    assert.throws(() => send('managed-001', rotated.deviceToken, s.store.now()), {
      code: 'device_observation_capacity_reached',
    });
    const second = enrolled(s, 'managed-002');
    for (let i = 0; i < 1000; i++) {
      s.advance(1);
      send('managed-002', second.deviceToken!, s.store.now());
    }
    const third = enrolled(s, 'managed-003');
    assert.throws(() => send('managed-003', third.deviceToken!, s.store.now()), {
      code: 'device_observation_capacity_reached',
    });
    const other = { ...op, tenant: 'isolated' };
    assert.ok(
      s.service.enroll(other, {
        id: 'foreign-device',
        label: 'Synthetic isolated device',
        platform: 'linux',
        region: 'EU',
        serialAlias: 'foreign-serial',
        mode: 'managed-observation',
      }).deviceToken,
    );
    const p = approved(s);
    assert.equal(s.service.execute(op, p.id, p.digest, 'budget-repair').status, 'completed');
    s.service.transition(op, 'managed-003', { version: 1, state: 'retired', ownerAlias: null });
    assert.equal(s.store.verify(), true);
  } finally {
    s.store.close();
  }
});
test('one device cannot fill the shared replay cache using duplicate observations', () => {
  const s = setup();
  const first = enrolled(s),
    second = enrolled(s, 'managed-002');
  const report = snapshot('managed-001', s.store.now());
  const send = () =>
    s.service.agent(
      {
        tenant: 'sandbox',
        deviceId: 'managed-001',
        nonce: randomUUID(),
        sentAt: new Date(s.store.now()).toISOString(),
        snapshot: report,
      },
      'Bearer ' + first.deviceToken,
    );
  try {
    for (let i = 0; i < 1000; i++) send();
    const count = s.store.count('sandbox', 'nonce');
    assert.throws(send, { code: 'device_nonce_capacity_reached' });
    assert.equal(s.store.count('sandbox', 'nonce'), count);
    assert.equal(
      s.service.agent(
        {
          tenant: 'sandbox',
          deviceId: 'managed-002',
          nonce: randomUUID(),
          sentAt: new Date(s.store.now()).toISOString(),
          snapshot: snapshot('managed-002', s.store.now()),
        },
        'Bearer ' + second.deviceToken,
      ).accepted,
      true,
    );
    s.service.rotate(op, 'managed-001');
    s.advance(600001);
    const rotated = s.service.rotate(op, 'managed-001');
    assert.equal(
      s.service.agent(
        {
          tenant: 'sandbox',
          deviceId: 'managed-001',
          nonce: randomUUID(),
          sentAt: new Date(s.store.now()).toISOString(),
          snapshot: report,
        },
        'Bearer ' + rotated.deviceToken,
      ).duplicate,
      true,
    );
    assert.equal(s.store.count('sandbox', 'nonce'), 1);
    assert.equal(s.store.verify(), true);
  } finally {
    s.store.close();
  }
});
test('older open support cases remain visible and do not duplicate beyond 200 retained cases', () => {
  const s = setup();
  try {
    for (let i = 0; i < 220; i++) {
      const id = randomUUID();
      s.store.put('sandbox', 'ticket', id, {
        id,
        deviceId: 'fixture-' + i,
        finding: 'firewallEnabled',
        status: 'open',
        createdAt: new Date(s.store.now()).toISOString(),
      });
    }
    const before = s.store.count('sandbox', 'ticket');
    s.advance(1);
    const old = s.store.need<Snapshot>('sandbox', 'snapshot', 'lab-laptop');
    s.service.ingest(op, { ...old, observedAt: new Date(s.store.now()).toISOString() });
    assert.equal(s.store.count('sandbox', 'ticket'), before);
    assert.equal(s.service.tickets(op).length, before);
    assert.equal(s.service.tickets(op).filter((t) => t.deviceId === 'lab-laptop').length, 1);
  } finally {
    s.store.close();
  }
});
test('HTTP authorization separates tenants, enrollment credentials, observations and remediation', async () => {
  const s = setup(),
    { auth, tokens } = await demoAuth('endpointops'),
    { app } = createApp({ auth, store: s.store, baseUrl: 'http://127.0.0.1:4420' });
  const headers = (r: string) => ({ host: '127.0.0.1:4420', authorization: 'Bearer ' + tokens[r] });
  try {
    assert.equal(
      (await app.inject({ url: '/api/overview', headers: headers('outsider') })).json().devices
        .length,
      0,
    );
    assert.equal(
      (
        await app.inject({
          method: 'POST',
          url: '/api/observations',
          headers: headers('viewer'),
          payload: s.store.need('sandbox', 'snapshot', 'lab-laptop'),
        })
      ).statusCode,
      403,
    );
    assert.equal(
      (
        await app.inject({
          method: 'POST',
          url: '/api/plans',
          headers: headers('requester'),
          payload: { deviceId: 'lab-laptop', action: 'run-shell-command' },
        })
      ).statusCode,
      400,
    );
    assert.equal(
      (await app.inject({ url: '/api/devices/lab-laptop/support', headers: headers('outsider') }))
        .statusCode,
      404,
    );
    assert.equal(
      (await app.inject({ url: '/api/audit', headers: headers('viewer') })).json().integrity,
      true,
    );
  } finally {
    await app.close();
    s.store.close();
  }
});
test('network diagnostics use real local DNS/TCP and report an unsupported TLS endpoint as failure', async () => {
  const { createServer } = await import('node:net');
  const { diagnoseNetwork } = await import('../src/diagnostics.js');
  const server = createServer((socket) => socket.destroy());
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Bind failed');
  try {
    const result = await diagnoseNetwork('localhost', address.port, 500);
    assert.equal(result.dns, 'pass');
    assert.equal(result.tcp, 'pass');
    assert.equal(result.tls, 'fail');
    assert.ok(result.durationMs >= 0);
    await assert.rejects(diagnoseNetwork('https://not-a-host', 443));
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
test('failed persisted readback rolls back remediation, approval consumption and idempotency', () => {
  const s = setup();
  const original = s.store.get.bind(s.store);
  try {
    const p = approved(s);
    s.store.get = function <T>(tenant: string, kind: string, id: string): T | undefined {
      const value = original<T>(tenant, kind, id);
      if (kind === 'snapshot' && value && (value as unknown as Snapshot).checks.firewallEnabled)
        return {
          ...(value as unknown as Snapshot),
          checks: { ...(value as unknown as Snapshot).checks, firewallEnabled: false },
        } as T;
      return value;
    };
    assert.throws(() => s.service.execute(op, p.id, p.digest, 'readback-fault'), {
      code: 'readback_failed',
    });
    s.store.get = original;
    assert.equal(
      s.store.need<Snapshot>('sandbox', 'snapshot', 'lab-laptop').checks.firewallEnabled,
      false,
    );
    assert.equal(s.service.book.get(op, p.id).status, 'approved');
    assert.equal(s.store.get('sandbox', 'idempotency', 'readback-fault'), undefined);
  } finally {
    s.store.get = original;
    s.store.close();
  }
});
