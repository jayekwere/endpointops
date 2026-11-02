import { platform, uptime, release } from 'node:os';
import { statfsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { SnapshotSchema, type Snapshot } from './policies.js';
/** Fixed read-only commands only. Missing permissions or tools yield unknown. */
export function collect(deviceId: string, now = Date.now()): Snapshot {
  const p = platform();
  if (!['linux', 'darwin', 'win32'].includes(p)) throw new Error('Unsupported platform');
  let encrypted: boolean | null = null,
    firewall: boolean | null = null,
    admins: number | null = null;
  if (p === 'darwin') {
    try {
      const output = execFileSync('/usr/bin/fdesetup', ['status'], {
        encoding: 'utf8',
        timeout: 2000,
        maxBuffer: 4096,
      });
      encrypted = output.includes('FileVault is On.')
        ? true
        : output.includes('FileVault is Off.')
          ? false
          : null;
    } catch {}
    try {
      const output = execFileSync(
        '/usr/libexec/ApplicationFirewall/socketfilterfw',
        ['--getglobalstate'],
        { encoding: 'utf8', timeout: 2000, maxBuffer: 4096 },
      );
      firewall = /State = 1/.test(output) ? true : /State = 0/.test(output) ? false : null;
    } catch {}
  }
  let free: number | null = null;
  try {
    const f = statfsSync('/');
    free = f.bavail * f.bsize;
  } catch {}
  return SnapshotSchema.parse({
    deviceId,
    observedAt: new Date(now).toISOString(),
    platform: p === 'win32' ? 'windows' : p,
    source: 'device-agent',
    checks: {
      diskEncrypted: encrypted,
      firewallEnabled: firewall,
      patchAgeDays: null,
      localAdminCount: admins,
      mdmEnrolled: null,
    },
    diagnostics: { osRelease: p + ' ' + release(), uptimeSeconds: uptime(), freeDiskBytes: free },
  });
}
