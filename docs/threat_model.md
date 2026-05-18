# Threat Model

## Product Category

The product is a Trustworthy Autonomous Security Runtime: a governed runtime for bounded, explainable, replayable, auditable, policy-constrained security workflows.

It does not claim to be generically secure. It claims specific controls: bounded execution, signed lineage, deterministic governance, isolated runtime roles, policy-first execution, and forensic replay checks.

## Attacker Assumptions

- A user may request out-of-scope targets or unsafe actions.
- A worker may crash, hang, return malformed output, or produce misleading evidence.
- Local artifacts may be modified after a run.
- Replay records may be poisoned or truncated.
- Policy files may drift between original execution and verification.
- An insider with filesystem access may attempt to forge, remove, or rewrite artifacts.

## Security Boundaries

- Governance authorizes but does not execute tools.
- Workflow coordinates state transitions but does not perform direct network IO.
- Tool runtime executes bounded workers and signs manifests.
- Evidence runtime owns append-only lineage and verification.
- Reasoning runtime reads evidence and produces confidence states, contradictions, and hypotheses.

## Controls

- Deny-by-default scope policy
- Explicit worker capability contracts
- Schema-versioned records
- Signed reports, manifests, benchmarks, lineage, and run artifacts
- Hash-chained audit and lineage records
- Durable workflow state, queue records, and leases
- Deep forensic verification with quarantine on failure
- Secret references and redaction instead of raw secret persistence

## Residual Risk

- Subprocess isolation is not equivalent to a container or kernel sandbox.
- Local encrypted secrets depend on filesystem permissions and local key protection.
- A fully compromised host can tamper with code and runtime keys.
- External authentication, remote workers, and distributed execution are intentionally deferred.
- Human review is still required for policy changes, risky workflow expansion, and forensic decisions.
