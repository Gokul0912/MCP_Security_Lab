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
- SQLite index uses parameterized queries
- Server internal errors do not echo raw exception details to clients
- No shell execution tool is exposed

## Security Boundaries

The assistant is intended for owned labs, local services, CTF environments, and explicitly authorized private ranges. It is not configured to scan arbitrary internet hosts.

## Residual Risk

No software can honestly guarantee zero vulnerabilities. Current residual areas to review before production deployment:

- Run the suite in CI on every change.
- Add OS-level sandboxing around the process.
- Put the MCP server behind authenticated transport if exposed beyond stdin/stdout.
- Rotate and protect filesystem permissions for artifact directories.
- Add signed release builds and dependency scanning when external dependencies are introduced.

## Verification

Run:

```powershell
python -m unittest discover -s tests
```
