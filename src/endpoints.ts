import { randomBytes, randomUUID } from 'node:crypto';
import { z } from 'zod';
import { Store } from './store.js';
import { Approvals } from './approvals.js';
import { Id, digest, Fault, requireRole, equal, type Identity } from './security.js';
import {
  DeviceInput,
  SnapshotSchema,
  evaluate,
  policyHash,
  type Snapshot,
  type Device,
} from './policies.js';
interface Remediation {
  deviceId: string;
  version: number;
  before: string;
  action: 'enable-lab-firewall';
  observation: string;
}
export interface Ticket {
  id: string;
  deviceId: string;
  finding: string;
  status: 'open' | 'in-progress' | 'resolved';
  createdAt: string;
  resolutionEvidence?: string;
}
export class Endpoints {
  readonly book: Approvals<Remediation>;
  constructor(readonly store: Store) {
    this.book = new Approvals(store, policyHash);
  }
  enroll(actor: Identity, input: unknown) {
    requireRole(actor, 'operator');
    const data = DeviceInput.parse(input);
    return this.store.tx(() => {
      if (this.store.get(actor.tenant, 'device', data.id)) throw new Fault(409, 'device_exists');
      if (this.store.count(actor.tenant, 'device') >= 200)
        throw new Fault(409, 'device_capacity_reached');
      if (
        this.store
          .list<Device>(actor.tenant, 'device')
          .some((d) => d.serialAlias === data.serialAlias)
      )
        throw new Fault(409, 'serial_alias_exists');
      const token = randomBytes(32).toString('base64url');
      const device: Device = {
        ...data,
        version: 1,
        state: 'received',
        ownerAlias: null,
        ...(data.mode === 'managed-observation' ? { credentialHash: digest(token) } : {}),
      };
      this.store.put(actor.tenant, 'device', data.id, device);
      this.store.audit(actor, 'device.enrolled', 'completed', {
        deviceId: data.id,
        mode: data.mode,
      });
      return {
        device: this.publicDevice(device),
        ...(data.mode === 'managed-observation' ? { deviceToken: token } : {}),
      };
    });
  }
  private publicDevice(d: Device) {
    const { credentialHash: _secret, lastNonce: _nonce, ...safe } = d;
    return safe;
  }
  list(actor: Identity) {
    requireRole(actor, 'viewer', 'requester', 'reviewer', 'operator');
    return this.store.list<Device>(actor.tenant, 'device').map((d) => {
      const s = this.store.get<Snapshot>(actor.tenant, 'snapshot', d.id);
      return {
        ...this.publicDevice(d),
        snapshot: s ?? null,
        findings: evaluate(s, this.store.now()),
      };
    });
  }
  ingest(actor: Identity, input: unknown) {
    requireRole(actor, 'operator');
    const snapshot = SnapshotSchema.parse(input);
    const device = this.store.need<Device>(actor.tenant, 'device', snapshot.deviceId);
    if (device.mode === 'lab-simulation' && snapshot.source !== 'lab-simulation')
      throw new Fault(409, 'source_mode_mismatch');
    if (
      device.mode === 'managed-observation' &&
      !['manual-import', 'fleet-export'].includes(snapshot.source)
    )
      throw new Fault(409, 'use_device_ingestion');
    return this.accept(actor, device, snapshot);
  }
  private accept(actor: Identity, device: Device, snapshot: Snapshot) {
    if (device.state === 'retired') throw new Fault(409, 'device_retired');
    if (
      snapshot.platform !== device.platform ||
      Date.parse(snapshot.observedAt) > this.store.now() + 30000 ||
      this.store.now() - Date.parse(snapshot.observedAt) > 86400000
    )
      throw new Fault(400, 'observation_contract_invalid');
    return this.store.tx(() => {
      const old = this.store.get<Snapshot>(actor.tenant, 'snapshot', device.id);
      if (old && Date.parse(snapshot.observedAt) <= Date.parse(old.observedAt)) {
        if (digest(old) === digest(snapshot))
          return { accepted: false, duplicate: true, digest: digest(old) };
        throw new Fault(409, 'observation_not_newer');
      }
      this.store.put(actor.tenant, 'snapshot', device.id, snapshot);
      const hash = digest(snapshot);
      this.store.audit(actor, 'device.observed', 'completed', {
        deviceId: device.id,
        source: snapshot.source,
        digest: hash,
      });
      for (const f of evaluate(snapshot, this.store.now()).filter((f) => f.state !== 'pass')) {
        const existing = this.store
          .list<Ticket>(actor.tenant, 'ticket')
          .find((t) => t.deviceId === device.id && t.finding === f.id && t.status !== 'resolved');
        if (!existing) {
          if (this.store.count(actor.tenant, 'ticket') >= 1000)
            throw new Fault(409, 'ticket_capacity_reached');
          const t: Ticket = {
            id: randomUUID(),
            deviceId: device.id,
            finding: f.id,
            status: 'open',
            createdAt: new Date(this.store.now()).toISOString(),
          };
          this.store.put(actor.tenant, 'ticket', t.id, t);
        }
      }
      return { accepted: true, digest: hash, findings: evaluate(snapshot, this.store.now()) };
    });
  }
  agent(input: unknown, token: string | undefined) {
    const b = z
      .object({
        tenant: Id,
        deviceId: Id,
        nonce: z.string().uuid(),
        sentAt: z.iso.datetime({ offset: true }),
        snapshot: SnapshotSchema,
      })
      .strict()
      .parse(input);
    const d = this.store.get<Device>(b.tenant, 'device', b.deviceId);
    if (
      !d ||
      d.mode !== 'managed-observation' ||
      !d.credentialHash ||
      !token?.startsWith('Bearer ') ||
      token.length > 200 ||
      !equal(d.credentialHash, digest(token.slice(7)))
    )
      throw new Fault(401, 'invalid_device_credential');
    if (
      b.snapshot.deviceId !== d.id ||
      b.snapshot.source !== 'device-agent' ||
      Math.abs(this.store.now() - Date.parse(b.sentAt)) > 300000
    )
      throw new Fault(400, 'device_envelope_invalid');
    const actor: Identity = { tenant: b.tenant, subject: 'device:' + d.id, roles: ['operator'] };
    return this.store.tx(() => {
      if (this.store.get(b.tenant, 'nonce', b.nonce)) throw new Fault(409, 'device_replay');
      for (const entry of this.store.list<{ id: string; at: string }>(b.tenant, 'nonce', 10000))
        if (this.store.now() - Date.parse(entry.at) > 600000)
          this.store.remove(b.tenant, 'nonce', entry.id);
      if (this.store.count(b.tenant, 'nonce') >= 10000)
        throw new Fault(409, 'device_nonce_capacity_reached');
      this.store.put(b.tenant, 'nonce', b.nonce, { id: b.nonce, at: b.sentAt });
      return this.accept(actor, d, b.snapshot);
    });
  }
  rotate(actor: Identity, id: string) {
    requireRole(actor, 'operator');
    return this.store.tx(() => {
      const d = this.store.need<Device>(actor.tenant, 'device', id);
      if (d.mode !== 'managed-observation' || d.state === 'retired')
        throw new Fault(409, 'device_credential_not_rotatable');
      const token = randomBytes(32).toString('base64url');
      d.credentialHash = digest(token);
      d.version++;
      this.store.put(actor.tenant, 'device', id, d);
      this.store.audit(actor, 'device.credential-rotated', 'completed', {
        deviceId: id,
        version: d.version,
      });
      return { device: this.publicDevice(d), deviceToken: token };
    });
  }

  transition(actor: Identity, id: string, input: unknown) {
    requireRole(actor, 'operator');
    const b = z
      .object({
        version: z.number().int().positive(),
        state: z.enum(['received', 'assigned', 'in-transit', 'returned', 'retired']),
        ownerAlias: Id.nullable(),
      })
      .strict()
      .parse(input);
    return this.store.tx(() => {
      const d = this.store.need<Device>(actor.tenant, 'device', id);
      const edges: Record<Device['state'], Device['state'][]> = {
        received: ['assigned', 'in-transit', 'retired'],
        assigned: ['in-transit', 'returned'],
        'in-transit': ['assigned', 'returned'],
        returned: ['assigned', 'retired'],
        retired: [],
      };
      if (d.version !== b.version || !edges[d.state].includes(b.state))
        throw new Fault(409, 'asset_state_or_version_conflict');
      if (b.state === 'assigned' && !b.ownerAlias) throw new Fault(400, 'owner_alias_required');
      d.state = b.state;
      d.ownerAlias = b.state === 'assigned' ? b.ownerAlias : null;
      d.version++;
      this.store.put(actor.tenant, 'device', id, d);
      this.store.audit(actor, 'asset.transition', 'completed', {
        deviceId: id,
        version: d.version,
        state: d.state,
      });
      return this.publicDevice(d);
    });
  }
  plan(actor: Identity, input: unknown) {
    const b = z
      .object({ deviceId: Id, action: z.literal('enable-lab-firewall') })
      .strict()
      .parse(input);
    const device = this.store.need<Device>(actor.tenant, 'device', b.deviceId),
      snapshot = this.store.need<Snapshot>(actor.tenant, 'snapshot', b.deviceId);
    if (device.state === 'retired') throw new Fault(409, 'device_retired');
    if (device.mode !== 'lab-simulation' || snapshot.source !== 'lab-simulation')
      throw new Fault(403, 'physical_device_remediation_not_supported');
    if (
      !evaluate(snapshot, this.store.now()).some(
        (f) => f.id === 'firewallEnabled' && f.state === 'fail',
      )
    )
      throw new Fault(409, 'supported_failure_required');
    return this.book.plan(actor, {
      deviceId: device.id,
      version: device.version,
      before: digest(device),
      action: b.action,
      observation: digest(snapshot),
    });
  }
  execute(actor: Identity, id: string, hash: string, key: string) {
    return this.store.tx(() => {
      const claim = this.book.claim(actor, id, hash, key);
      if (!claim.claimed) return claim.plan;
      const p = claim.plan,
        d = this.store.need<Device>(actor.tenant, 'device', p.binding.data.deviceId),
        before = this.store.need<Snapshot>(actor.tenant, 'snapshot', d.id);
      if (
        d.mode !== 'lab-simulation' ||
        digest(d) !== p.binding.data.before ||
        digest(before) !== p.binding.data.observation
      )
        throw new Fault(409, 'device_or_observation_changed');
      if (
        !evaluate(before, this.store.now()).some(
          (f) => f.id === 'firewallEnabled' && f.state === 'fail',
        )
      )
        throw new Fault(409, 'fresh_supported_failure_required');
      const after = SnapshotSchema.parse({
        ...before,
        observedAt: new Date(
          Math.max(this.store.now(), Date.parse(before.observedAt) + 1),
        ).toISOString(),
        checks: { ...before.checks, firewallEnabled: true },
      });
      this.accept(actor, d, after);
      const observed = this.store.need<Snapshot>(actor.tenant, 'snapshot', d.id);
      if (
        digest(observed) !== digest(after) ||
        !evaluate(observed, this.store.now()).some(
          (f) => f.id === 'firewallEnabled' && f.state === 'pass',
        )
      )
        throw new Fault(500, 'readback_failed');
      d.version++;
      this.store.put(actor.tenant, 'device', d.id, d);
      return this.book.save(actor, p, 'completed', {
        scope: 'local-simulation',
        deviceId: d.id,
        action: p.binding.data.action,
        before: digest(before),
        after: digest(after),
        verified: true,
      });
    });
  }
  tickets(actor: Identity) {
    requireRole(actor, 'viewer', 'requester', 'reviewer', 'operator');
    return this.store.list<Ticket>(actor.tenant, 'ticket');
  }
  ticket(actor: Identity, id: string, input: unknown) {
    requireRole(actor, 'operator');
    const b = z
      .object({ status: z.enum(['in-progress', 'resolved']) })
      .strict()
      .parse(input);
    return this.store.tx(() => {
      const t = this.store.need<Ticket>(actor.tenant, 'ticket', id);
      if (t.status === 'resolved') throw new Fault(409, 'ticket_already_resolved');
      if (b.status === 'resolved') {
        const s = this.store.get<Snapshot>(actor.tenant, 'snapshot', t.deviceId);
        if (
          !s ||
          !evaluate(s, this.store.now()).some((f) => f.id === t.finding && f.state === 'pass')
        )
          throw new Fault(409, 'passing_readback_required');
        t.resolutionEvidence = digest(s);
      }
      t.status = b.status;
      this.store.put(actor.tenant, 'ticket', id, t);
      this.store.audit(actor, 'ticket.' + b.status, 'completed', {
        id,
        deviceId: t.deviceId,
        evidence: t.resolutionEvidence ?? null,
      });
      return t;
    });
  }
  support(actor: Identity, id: string) {
    requireRole(actor, 'viewer', 'operator');
    const d = this.store.need<Device>(actor.tenant, 'device', id),
      s = this.store.get<Snapshot>(actor.tenant, 'snapshot', id);
    return {
      schemaVersion: 1,
      device: this.publicDevice(d),
      diagnostics: s?.diagnostics ?? null,
      source: s?.source ?? 'unavailable',
      observedAt: s?.observedAt ?? null,
      findings: evaluate(s, this.store.now()),
      evidence: s ? digest(s) : null,
      privacy: 'No usernames, addresses, process lists, recovery keys, or credentials collected',
    };
  }
}
