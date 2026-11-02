import { z } from 'zod';
import { Id, Text, digest } from './security.js';
export const SnapshotSchema = z
  .object({
    deviceId: Id,
    observedAt: z.iso.datetime({ offset: true }),
    platform: z.enum(['linux', 'darwin', 'windows']),
    source: z.enum(['lab-simulation', 'device-agent', 'fleet-export', 'manual-import']),
    checks: z
      .object({
        diskEncrypted: z.boolean().nullable(),
        firewallEnabled: z.boolean().nullable(),
        patchAgeDays: z.number().int().min(0).max(3650).nullable(),
        localAdminCount: z.number().int().min(0).max(100).nullable(),
        mdmEnrolled: z.boolean().nullable(),
      })
      .strict(),
    diagnostics: z
      .object({
        osRelease: z.string().max(120),
        uptimeSeconds: z.number().min(0).max(1e10).nullable(),
        freeDiskBytes: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).nullable(),
        network: z
          .object({
            dns: z.enum(['pass', 'fail']),
            tcp: z.enum(['pass', 'fail', 'unknown']),
            tls: z.enum(['pass', 'fail', 'unknown']),
            durationMs: z.number().min(0).max(60000),
          })
          .strict()
          .optional(),
      })
      .strict(),
  })
  .strict();
export type Snapshot = z.infer<typeof SnapshotSchema>;
export const policy = {
  version: '1.0.0',
  maxPatchAgeDays: 14,
  maxLocalAdmins: 1,
  maxSnapshotAgeSeconds: 86400,
  required: ['diskEncrypted', 'firewallEnabled', 'patchAgeDays', 'localAdminCount', 'mdmEnrolled'],
};
export const policyHash = digest(policy);
export interface Finding {
  id: string;
  title: string;
  state: 'pass' | 'fail' | 'unknown';
  observed: unknown;
  required: unknown;
}
export function evaluate(snapshot: Snapshot | undefined, now = Date.now()): Finding[] {
  if (!snapshot)
    return [
      {
        id: 'no-observation',
        title: 'No device observation',
        state: 'unknown',
        observed: null,
        required: 'fresh observation',
      },
    ];
  if (
    Date.parse(snapshot.observedAt) > now + 30000 ||
    now - Date.parse(snapshot.observedAt) > policy.maxSnapshotAgeSeconds * 1000
  )
    return [
      {
        id: 'stale-observation',
        title: 'Observation is stale or future-dated',
        state: 'unknown',
        observed: snapshot.observedAt,
        required: 'within the last 24 hours',
      },
    ];
  const desired: Record<string, unknown> = {
    diskEncrypted: true,
    firewallEnabled: true,
    patchAgeDays: policy.maxPatchAgeDays,
    localAdminCount: policy.maxLocalAdmins,
    mdmEnrolled: true,
  };
  return Object.entries(snapshot.checks).map(([id, value]) => ({
    id,
    title: (
      {
        diskEncrypted: 'Disk encryption',
        firewallEnabled: 'Host firewall',
        patchAgeDays: 'Patch freshness',
        localAdminCount: 'Local administrator count',
        mdmEnrolled: 'Management enrollment',
      } as Record<string, string>
    )[id]!,
    state:
      value === null
        ? 'unknown'
        : typeof value === 'boolean'
          ? value
            ? 'pass'
            : 'fail'
          : value <= Number(desired[id])
            ? 'pass'
            : 'fail',
    observed: value,
    required: desired[id],
  }));
}
export const DeviceInput = z
  .object({
    id: Id,
    label: Text,
    platform: z.enum(['linux', 'darwin', 'windows']),
    region: z.enum(['EU', 'NA', 'APAC']),
    serialAlias: Id,
    mode: z.enum(['lab-simulation', 'managed-observation']),
  })
  .strict();
export type Device = z.infer<typeof DeviceInput> & {
  version: number;
  state: 'received' | 'assigned' | 'in-transit' | 'returned' | 'retired';
  ownerAlias: string | null;
  credentialHash?: string;
  lastNonce?: string;
};
