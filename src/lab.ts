import type { Identity } from './security.js';
import { Endpoints } from './endpoints.js';
export function seed(service: Endpoints, now = Date.now()) {
  const operator: Identity = {
    tenant: 'sandbox',
    subject: 'fixture-bootstrap',
    roles: ['operator'],
  };
  if (service.store.get('sandbox', 'device', 'lab-laptop')) return;
  service.enroll(operator, {
    id: 'lab-laptop',
    label: 'Synthetic laptop 01',
    platform: 'linux',
    region: 'EU',
    serialAlias: 'synthetic-serial-001',
    mode: 'lab-simulation',
  });
  service.ingest(operator, {
    deviceId: 'lab-laptop',
    observedAt: new Date(now - 1000).toISOString(),
    platform: 'linux',
    source: 'lab-simulation',
    checks: {
      diskEncrypted: true,
      firewallEnabled: false,
      patchAgeDays: 3,
      localAdminCount: 1,
      mdmEnrolled: true,
    },
    diagnostics: {
      osRelease: 'Synthetic Linux fixture',
      uptimeSeconds: 3600,
      freeDiskBytes: 64000000000,
    },
  });
}
