import { z } from 'zod';
import { fixedUrl, boundedJson } from './net.js';
import { SnapshotSchema, type Snapshot } from './policies.js';
export const FleetHost = z.object({
  id: z.number().int().positive(),
  platform: z.enum(['darwin', 'windows', 'ubuntu', 'centos', 'debian', 'linux']),
  seen_time: z.iso.datetime({ offset: true }),
  policies: z
    .array(
      z.object({ id: z.number().int().positive(), response: z.enum(['pass', 'fail']).nullable() }),
    )
    .max(1000),
});
export interface FleetConfig {
  endpoint: string;
  token: string;
  policyIds: {
    diskEncrypted: number;
    firewallEnabled: number;
    patchAgeDays: number;
    localAdminCount: number;
    mdmEnrolled: number;
  };
}
export async function fetchFleet(
  config: FleetConfig,
  hostId: number,
  deviceId: string,
  allowLocal = false,
  fetcher = fetch,
): Promise<Snapshot> {
  const base = fixedUrl(config.endpoint, allowLocal);
  const u = new URL(
    base.origin + '/api/v1/fleet/hosts/' + z.number().int().positive().parse(hostId),
  );
  const { data } = await boundedJson(u, {
    headers: { authorization: 'Bearer ' + config.token },
    fetcher,
  });
  const host = FleetHost.parse(z.object({ host: FleetHost }).parse(data).host);
  if (host.id !== hostId) throw new Error('Fleet identity mismatch');
  const result = (name: keyof FleetConfig['policyIds']) => {
    const p = host.policies.find((p) => p.id === config.policyIds[name]);
    return p?.response === 'pass' ? true : p?.response === 'fail' ? false : null;
  };
  // Policies establish thresholds, not actual patch age or administrator counts.
  // Only boolean checks can be faithfully projected without separate raw observations.
  return SnapshotSchema.parse({
    deviceId,
    observedAt: host.seen_time,
    platform:
      host.platform === 'darwin' ? 'darwin' : host.platform === 'windows' ? 'windows' : 'linux',
    source: 'fleet-export',
    checks: {
      diskEncrypted: result('diskEncrypted'),
      firewallEnabled: result('firewallEnabled'),
      patchAgeDays: null,
      localAdminCount: null,
      mdmEnrolled: result('mdmEnrolled'),
    },
    diagnostics: { osRelease: 'Fleet policy projection', uptimeSeconds: null, freeDiskBytes: null },
  });
}
