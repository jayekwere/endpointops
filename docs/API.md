# API

Human `/api/*` routes require signed access tokens. Device ingestion uses its separate enrollment credential. JSON bodies are strict. Tenant and roles are never accepted from human request bodies.

| Route                                               | Role                       | Contract                                                                                     |
| --------------------------------------------------- | -------------------------- | -------------------------------------------------------------------------------------------- |
| `GET /api/overview`, `/api/devices`, `/api/tickets` | Workflow/view roles        | Tenant-scoped inventory, findings, cases and plans                                           |
| `POST /api/devices`                                 | Operator                   | `{id,label,platform,region,serialAlias,mode}`; observation mode returns one-time deviceToken |
| `POST /api/observations`                            | Operator                   | Strict manual, Fleet or lab snapshot consistent with device mode                             |
| `POST /ingest/device`                               | Device credential          | `{tenant,deviceId,nonce,sentAt,snapshot}`                                                    |
| `POST /api/devices/:deviceId/rotate-credential`     | Operator                   | Empty object; new one-time token, old token invalidated                                      |
| `POST /api/devices/:deviceId/transition`            | Operator                   | `{version,state,ownerAlias}`                                                                 |
| `GET /api/devices/:deviceId/support`                | Viewer, operator           | Whitelisted support bundle                                                                   |
| `POST /api/devices/:deviceId/fleet`                 | Operator                   | Fetch the preconfigured bound host, not a caller-selected target                             |
| `POST /api/plans`                                   | Requester                  | `{deviceId,action:"enable-lab-firewall"}`                                                    |
| `POST /api/plans/:id/review`                        | Independent reviewer       | `{digest,approve}`                                                                           |
| `POST /api/plans/:id/execute`                       | Independent operator       | `{digest,key}`                                                                               |
| `POST /api/tickets/:id`                             | Operator                   | `{status: in-progress/resolved}`; closure requires passing readback                          |
| `GET /api/audit`                                    | Viewer, reviewer, operator | Tenant events and full database verification                                                 |

A snapshot has deviceId, timezone-aware observedAt, platform, source, five strict nullable checks and diagnostic fields. Sources are lab-simulation, device-agent, fleet-export and manual-import. Platforms are linux, darwin and windows. Checks are diskEncrypted, firewallEnabled, patchAgeDays, localAdminCount and mdmEnrolled. OS release is capped at 120 characters; numeric observations are bounded. Optional network diagnostics carry only dns/tcp/tls state and duration. Unknown fields fail rather than enter evidence.

Device envelopes must be within five minutes, have a fresh UUID nonce, match device ID/platform, and use device-agent source. A key cannot enroll other devices or access a human operation. There is no arbitrary remote execution endpoint. Device IDs are safe 1 to 64-character aliases, and owner/serial fields are aliases rather than personal records. Standard errors distinguish invalid contract, token/role failure, foreign/unknown record, stale state, replay, oversized input and rate limits. Credential values appear only in the one-time enrollment/rotation response and are omitted from all subsequent reads and audits.
