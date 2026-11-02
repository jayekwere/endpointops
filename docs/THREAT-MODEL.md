# Threat model

Protect tenant device records, observation credentials, exact remediation authority, asset history, support evidence and audit integrity. Treat device agents, manual imports and upstream responses as potentially wrong. Trust the configured issuer, server registry, service host and authorized operator configuration. A compromised physical endpoint can lie even when its transport credential is valid.

| Threat                                      | Enforced control                                                                              | Residual boundary                                                    |
| ------------------------------------------- | --------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| Cross-tenant device/case access             | Identity-derived tenant on every record, negative API tests                                   | Host administrators can read local state                             |
| Forged human roles or tokens                | Signature/claim verification and server role registry                                         | Stolen valid bearer credential remains usable until expiry           |
| Device key disclosed or replayed            | Random device-bound key, hash storage, timestamp/nonce, explicit rotation, no plaintext reads | A key holder can create new false telemetry; no hardware attestation |
| False compliance from missing or stale data | Nullable strict fields, explicit unknown, age checks and newer-only observations              | Reports are observations and assertions, not independent proof       |
| Arbitrary shell or real device mutation     | Fixed local synthetic action only; bounded read-only collector; no command payload            | Physical MDM and EDR operations are absent                           |
| Unauthorized or stale repair                | Independent identities, exact device/snapshot/policy/expiry binding                           | Issuer/registry and trusted host remain critical                     |
| Duplicate or unverifiable success           | Local transaction and persisted readback, rollback and durable idempotency tests              | Local atomicity does not establish external side effects             |
| Closure hides a failing check               | Fresh passing observation required for the case's exact check                                 | A fabricated authorized report can still mislead                     |
| Private data leaks in support export        | Field whitelist, hashed credentials, no raw processes/accounts/targets                        | Operators must keep actual local readings private                    |
| Malicious UI label or upstream payload      | Text-node rendering, CSP, bounded strict contracts and no redirects                           | No independent browser penetration-test claim                        |

Use the local simulation for mutation demonstrations. Never attach demo identities to real privileged management systems. Map roles to separately controlled people and use an appropriately restricted Fleet credential. Retain independent audit checkpoints when stronger history protection is needed. Native MDM enforcement, remote attestation, provider tenant acceptance and real shipping are outside this implementation.
