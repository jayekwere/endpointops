import { z } from 'zod';
import { secureApp, planRoutes, idParam, ExecuteSchema } from './http.js';
import { Auth, Id, requireRole, Fault } from './security.js';
import { Store } from './store.js';
import { Endpoints } from './endpoints.js';
import { fetchFleet, type FleetConfig } from './fleet.js';
export function createApp(o: {
  auth: Auth;
  store: Store;
  baseUrl: string;
  webRoot?: string;
  fleet?: { tenant: string; config: FleetConfig; bindings: Record<string, number> };
}) {
  const app = secureApp(o.auth, o.store, o.baseUrl, o.webRoot),
    service = new Endpoints(o.store);
  planRoutes(app, service.book);
  app.get('/api/devices', async (req) => ({ devices: service.list(req.identity) }));
  app.post('/api/devices', async (req, reply) =>
    reply.status(201).send(service.enroll(req.identity, req.body)),
  );
  app.post('/api/observations', async (req) => service.ingest(req.identity, req.body));
  app.post('/ingest/device', async (req) => service.agent(req.body, req.headers.authorization));
  app.post('/api/devices/:deviceId/rotate-credential', async (req) => {
    z.object({}).strict().parse(req.body);
    return service.rotate(req.identity, z.object({ deviceId: Id }).parse(req.params).deviceId);
  });
  app.post('/api/devices/:deviceId/transition', async (req) =>
    service.transition(
      req.identity,
      z.object({ deviceId: Id }).parse(req.params).deviceId,
      req.body,
    ),
  );
  app.get('/api/devices/:deviceId/support', async (req) =>
    service.support(req.identity, z.object({ deviceId: Id }).parse(req.params).deviceId),
  );
  app.post('/api/devices/:deviceId/fleet', async (req) => {
    requireRole(req.identity, 'operator');
    const { deviceId } = z.object({ deviceId: Id }).parse(req.params);
    if (!o.fleet || o.fleet.tenant !== req.identity.tenant || !o.fleet.bindings[deviceId])
      throw new Fault(403, 'fleet_binding_not_configured');
    const snapshot = await fetchFleet(o.fleet.config, o.fleet.bindings[deviceId]!, deviceId);
    return service.ingest(req.identity, snapshot);
  });
  app.post('/api/plans', async (req, reply) =>
    reply.status(201).send(service.plan(req.identity, req.body)),
  );
  app.post('/api/plans/:id/execute', async (req) => {
    const b = ExecuteSchema.parse(req.body);
    return service.execute(req.identity, idParam(req), b.digest, b.key);
  });
  app.get('/api/tickets', async (req) => ({ tickets: service.tickets(req.identity) }));
  app.post('/api/tickets/:id', async (req) => service.ticket(req.identity, idParam(req), req.body));
  app.get('/api/overview', async (req) => ({
    devices: service.list(req.identity),
    tickets: service.tickets(req.identity),
    plans: service.book.list(req.identity),
    audit: o.store.audits(req.identity.tenant, 30),
    integrity: o.store.verify(),
  }));
  return { app, service };
}
