# Security Posture

This project is designed as a defensive, lab-scoped security assistant. It deliberately avoids hidden execution paths, shell command tools, unrestricted network access, and public-target defaults.

## Security Guarantees Implemented

- Deny-by-default target scope
- Arbitrary DNS targets disabled by default
- Explicit hostname allowlist for names such as `localhost`
- CIDR allowlist for IP targets
- Blocked port policy
- Maximum ports per scan
- Bounded concurrent workers
- Bounded HTTP response reads
- Redirects reported but not followed
- URL credentials, fragments, params, invalid ports, and control characters rejected
- Path-like targets and target strings containing embedded ports rejected
- Artifact storage restricted to project-local relative directories
- Symlink artifact directories rejected
- UUID-only run lookup
- Atomic writes for JSON, Markdown, and SARIF artifacts
- Tamper-evident audit log with hash chaining
- Schema-versioned audit events
- Durable workflow state records for crash/restart recovery
- Local durable queue records with workflow leases
- Append-only queue event stream for operational recovery
- SQLite index uses parameterized queries
- Server internal errors do not echo raw exception details to clients
- No shell execution tool is exposed
- Execution manifests include schema version, policy hash, contract hash, worker attestation, quotas, output hash, and detached signature metadata
- Evidence lineage records are append-only, hash-chained, and signed
- Structured failure taxonomy exists for worker, governance, replay, lineage, attestation, policy, queue, lease, signature, reasoning, quota, and recovery failures

## Security Boundaries

The assistant is intended for owned labs, local services, CTF environments, and explicitly authorized private ranges. It is not configured to scan arbitrary internet hosts.

## Residual Risk

No software can honestly guarantee zero vulnerabilities. Current residual areas to review before production deployment:

- Run the suite in CI on every change.
- Add OS-level sandboxing around the process.
- Add container sandboxing for workers before hostile multi-tenant use.
- Put the MCP server behind authenticated transport if exposed beyond stdin/stdout.
- Rotate and protect filesystem permissions for artifact directories.
- Move local signing keys and secret references into an encrypted secret provider before production use.
- Add signed release builds and dependency scanning when external dependencies are introduced.

## Verification

Run:

```powershell
python -m unittest discover -s tests
```
