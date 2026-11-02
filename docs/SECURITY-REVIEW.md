# Security review and remediation

Source release: **1.0.1**. Reviewed baseline: [9ee06ac](https://github.com/jayekwere/endpointops/tree/9ee06ac380855aec41d741eee805547861b1fc4b).

The review covered application source, API and browser boundaries, startup/configuration, storage, tests, fixtures, container and CI definitions. It used a fresh independent baseline reviewer and architecture reviewer, parent source validation, a pre-patch compatibility investigation and one fresh patch-review cycle. This was an agent-assisted source review with synthetic validation. No independent external penetration test or live provider acceptance was performed. Third-party package internals were not fully audited; generated receipts and visual assets received targeted review.

| Confirmed issue                                                                                   | Severity                        | Remediation                                                                                                                                           |
| ------------------------------------------------------------------------------------------------- | ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| Device observations could exhaust the global audit cap and block every tenant's control mutations | Medium                          | Persisted per-device and agent-source tenant budgets reserve control capacity; a lower per-tenant audit quota bounds one tenant's global consumption. |
| Repeated duplicate envelopes could consume the shared tenant replay cache                         | Low, identified in patch review | Store device ownership with each new nonce, cap live nonces per device, retain tenant cap and expiry pruning.                                         |

An isolated v1.0.0 reproduction generated a valid synthetic near-cap audit history, accepted one device observation, then observed same-tenant rotation and foreign-tenant enrollment fail with audit_capacity_reached. It used no live device or service. Patched tests exhaust actual observation budgets and preserve rotation, retirement, approved synthetic repair and another tenant's operation. Credential rotation and replay expiry do not reset historical consumption. The duplicate-envelope test failed before the replay partition and passes afterward. Case lookup/dedup now includes all 1,000 retained cases; unavailable local disk inspection now remains null.

## Validation

The patched source passed formatting, strict types, build, 42 automated tests, 2 browser workflows and its restricted container demo. Containers independently repeat the suite under Node 24; host runs use Node 26. The recorded locked-dependency query reports zero advisories, which is time-sensitive and does not scan every base-image package. [Validation record](../evidence/VALIDATION.md), [test/coverage transcript](../evidence/coverage.txt), [browser results](../evidence/browser.txt), [container results](../evidence/container-smoke.txt) and [source fingerprints](../evidence/source-manifest.json) retain the evidence. Hosted CI is linked from the README and must be assessed for its exact commit.

## Capacity and deployment limits

Audit history retains a 100,000-entry global cap and a 10,000-entry tenant cap. Counts derive from complete persisted history, so restart cannot clear them. The existing audit body/HMAC format is retained and indexes are additive. A database already beyond a new limit remains readable and verifiable but refuses affected new audited mutations. One tenant cannot consume an otherwise empty global budget, but many tenants or legacy history can still reach the shared bound. This is bounded reference-service storage, without automatic archive, quota reset or state migration. Preserve authenticated history and operational state during reviewed maintenance. External effects cannot be undone by a later SQLite capacity failure. See [operations](OPERATIONS.md).

Authenticated devices can still fabricate their own telemetry. Fleet is contract-tested without live server acceptance. The local collector is read-only and the repair remains explicitly synthetic.

The issuer, host, trusted configuration, TLS termination, private credentials and independent audit checkpoints remain deployment responsibilities. Coverage and passing tests establish the checked behavior; they do not certify every possible input or deployment. Copied documentation claims were corrected to match this repository's implemented interfaces.
