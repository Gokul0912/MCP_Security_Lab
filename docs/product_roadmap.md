# Trustworthy Autonomous Security Runtime Roadmap

## Product Identity

This product is a **Trustworthy Autonomous Security Runtime**.

It can also be described as an **Explainable Security Workflow Runtime** when the audience is governance, compliance, platform engineering, or enterprise security operations.

It should not be positioned as an AI hacking platform, autonomous exploitation agent, or AI pentesting bot. Those categories increase legal exposure, reduce enterprise trust, and pull the architecture toward unsafe unrestricted autonomy.

The product category is:

- Bounded execution for authorized security workflows
- Explainable reasoning over evidence
- Deterministic replay of workflow and reasoning state
- Forensic lineage for every important artifact
- Governance enforcement before risky action
- Runtime isolation across authority domains
- Benchmarkable trust instead of vague intelligence claims

The product is not trying to become more aggressive. It is trying to become more trustworthy.

## Non-Negotiable Product Principles

- **Replayability:** every workflow, evidence transition, reasoning transition, and governance decision must be replayable.
- **Determinism:** replay must reproduce state transitions, confidence changes, contradictions, and outputs.
- **Governance:** policy and authority checks happen before tool execution, not after.
- **Evidence lineage:** every claim traces back to structured evidence and signed artifacts.
- **Isolation:** governance, workflow, tool, evidence, and reasoning runtimes remain separate.
- **Auditability:** decisions, approvals, refusals, failures, and outputs are durable and inspectable.
- **Explainability:** users can ask why an action happened, why confidence changed, and why an action was refused.
- **Least privilege:** workers cannot gain capabilities implicitly.
- **Append-only integrity:** audit logs, lineage, manifests, checkpoints, and replay states are hash-linked.
- **Human control:** risky actions require explicit approval and role authorization.

## Target Users

- Security engineers running authorized lab and internal workflows
- Blue-team analysts validating evidence-backed findings
- Security platform teams evaluating safe autonomous workflows
- Auditors reviewing lineage, policy, and signed execution records
- Researchers testing agent safety, replay, and benchmark correctness
- Educators building controlled security labs

## Product Boundaries

The runtime supports authorized, bounded, explainable security workflows.

It does not support:

- Public-target scanning by default
- Unrestricted exploitation
- Malware generation or deployment
- Credential theft
- Hidden shell execution
- Covert persistence
- Evasion tooling
- Autonomous scope expansion
- Unsigned final artifacts
- Non-replayable decision paths

## Roadmap Overview

| Phase | Name | Goal | Exit Criteria |
| --- | --- | --- | --- |
| 0 | Product Identity | Define what the product is and is not | Naming, category, threat posture, and language are consistent |
| 1 | Core Platform Stabilization | Deterministic trustworthy core | Runtime contracts, signed artifacts, append-only evidence, deterministic replay |
| 2 | Operational Resilience | Real-world survivability | Durable workflow state, leases, local queue, recovery semantics |
| 3 | Execution Security | Hostile-environment safety | Hardened workers, resource limits, secret handling, attestation, tamper detection |
| 4 | Governance and Trust | Enterprise trustworthiness | Strong RBAC, approvals, policy versioning, audit trails, trust boundary docs |
| 5 | Reasoning Runtime | Trustworthy intelligence | Formal reasoning graphs, contradiction handling, replayable confidence propagation |
| 6 | Observability | Inspectability everywhere | Dashboard, visualizers, metrics, tracing, failure taxonomy, explainability APIs |
| 7 | Benchmarking and Verification | Measurable trust | Replay validation, adversarial tests, benchmark suite, simulation worlds |
| 8 | Platform Engineering | Product maturity | Packaging, stable APIs, docs, security policy, architecture diagrams |
| 9 | Advanced Infrastructure | Scale only after maturity | Container workers, distributed execution, remote nodes, enterprise auth, plugin SDK |

## Phase 0: Product Identity

### Goal

Define the product category before adding more capability.

### Product Name Direction

Preferred category names:

- Trustworthy Autonomous Security Runtime
- Explainable Security Workflow Runtime
- Governed Security Automation Runtime

Avoid:

- AI hacking platform
- AI pentester
- Autonomous exploit agent
- Offensive AI assistant

### Required Work

- Update primary project language to emphasize runtime trust, governance, replayability, and evidence.
- Keep offensive capability language out of top-level positioning.
- Define a short product one-liner:

  `A governed runtime for bounded, explainable, replayable security workflows.`

- Define a longer product statement:

  `The platform executes authorized security workflows through isolated runtimes, signed manifests, append-only evidence, deterministic replay, and explainable reasoning graphs so every action and conclusion can be governed, audited, and reproduced.`

### Acceptance Criteria

- README, blueprint, security docs, and generated guides use consistent positioning.
- The product is described by trust properties, not by autonomy hype.
- The threat model explicitly rejects unrestricted security actions.
- Enterprise readers can understand why the system is safe to evaluate.

## Phase 1: Core Platform Stabilization

### Goal

Establish a deterministic trustworthy core that all later features must preserve.

### 1. Runtime Isolation

Maintain strict runtime separation:

- **Governance Runtime:** policy, RBAC, approvals, quotas, signature verification, audit verification
- **Workflow Runtime:** state transitions, orchestration, checkpointing, event emission
- **Tool Runtime:** bounded tool invocation and worker execution
- **Evidence Runtime:** append-only evidence, lineage, artifact storage, signatures
- **Reasoning Runtime:** hypotheses, contradictions, confidence, critique, reasoning replay

Rules:

- Governance can authorize execution but cannot execute tools.
- Reasoning can interpret evidence but cannot mutate evidence.
- Tools can collect evidence but cannot change policy.
- Workflow can coordinate runtimes but cannot bypass governance.
- Evidence can persist records but cannot invent claims.

### 2. Capability Contracts

Every worker and tool must declare a capability contract before execution.

Minimum contract fields:

- Tool name and version
- Allowed operations
- Network scope
- Filesystem access
- Maximum runtime duration
- Maximum response bytes
- Maximum concurrency
- Maximum retries
- Secret access requirements
- Approval requirements
- Output schema
- Failure modes

Rules:

- No implicit capability expansion.
- A missing capability is denied.
- Runtime policy must compare requested execution against declared contract.
- Contract hash must be included in execution manifests.

### 3. Append-Only Evidence

The following must be append-only and hash-linked:

- Lineage records
- Execution manifests
- Audit logs
- Workflow checkpoints
- Replay states
- Reasoning graph snapshots
- Benchmark records
- Worker outputs

Minimum append-only record fields:

- Record id
- Record type
- Created timestamp
- Previous record hash
- Payload hash
- Actor or runtime id
- Policy version
- Runtime version
- Signature id

### 4. Signed Everything

Sign all product-critical artifacts:

- Reports
- SARIF files
- Run JSON
- Execution manifests
- Worker outputs
- Reasoning graphs
- Replay checkpoints
- Lineage records
- Benchmark records
- Visualizers
- Audit snapshots

Signature records should include:

- Artifact path
- Artifact hash
- Signature algorithm
- Signing key id
- Created timestamp
- Runtime version
- Policy hash

### 5. Deterministic Replay

Replay must reproduce:

- Workflow transitions
- Governance decisions
- Evidence states
- Reasoning states
- Confidence propagation
- Contradictions
- Refusals
- Final outputs

Replay should support:

- Full replay
- Step replay
- Diff against original
- Tamper detection
- Replay cursor persistence
- Replay failure taxonomy

### Phase 1 Exit Criteria

- Runtime contracts are represented in code and tests.
- Every worker execution has a manifest.
- Evidence and audit records are hash-linked.
- Product-critical artifacts are signed.
- Replay correctness is tested with `replay == original` fixtures.
- Runtime boundary tests prevent authority leakage.

## Phase 2: Operational Resilience

### Goal

Make workflows survive real operational conditions: crashes, retries, partial execution, approvals, and restarts.

### 6. Persistent Workflow State Machine

Workflows must persist:

- Workflow id
- Current state
- Previous state
- State transition history
- Pending approvals
- Retry counters
- Checkpoint ids
- Replay cursor
- Lineage pointer
- Lease owner
- Last heartbeat
- Terminal status

Recommended states:

- `created`
- `scope_validating`
- `awaiting_approval`
- `queued`
- `leased`
- `running`
- `checkpointing`
- `retrying`
- `completed`
- `failed`
- `cancelled`
- `dead_lettered`

### 7. Recovery Semantics

Define recovery behavior for:

- Process crash during tool execution
- Crash after worker output before lineage append
- Crash after lineage append before workflow checkpoint
- Crash during signature creation
- Crash during approval transition
- Crash during replay
- Manifest exists without terminal worker output
- Worker output exists without signed manifest
- Queue task leased but heartbeat expired

Recovery rules:

- Prefer append-only compensation over mutation.
- Never silently delete partial artifacts.
- Mark orphaned records with recovery status.
- Re-run only idempotent tasks.
- Require approval before replaying risky operations.
- Preserve original failed manifests.

### 8. Durable Local Queue

Start with local durable execution before distributed infrastructure.

Required queue capabilities:

- Append-only task records
- Durable task status
- Leases
- Task locking
- Retry policy
- Dead-letter queue
- Priority
- Created/started/finished timestamps
- Failure reason
- Worker id

Recommended local implementation:

- SQLite table for task index and leases
- JSONL append-only event log for queue history
- Filesystem artifact storage for task payloads and outputs

### 9. Workflow Leases

Leases prevent:

- Duplicate execution
- Concurrent state corruption
- Replay races
- Multi-process checkpoint conflicts

Lease fields:

- Lease id
- Workflow id
- Owner id
- Acquired timestamp
- Expires timestamp
- Heartbeat timestamp
- Lease generation

Rules:

- A worker must hold a valid lease before advancing workflow state.
- Expired leases can be recovered by a supervisor.
- Lease generation prevents stale writes.
- Replay should use separate replay leases.

### 10. State Migration System

Schemas that need migration support:

- Manifests
- Reasoning graphs
- Lineage records
- Replay states
- Workflow checkpoints
- Queue records
- Policy records
- Benchmark records

Migration requirements:

- Version every schema.
- Store migration history.
- Keep migrations deterministic.
- Validate before and after migration.
- Support dry-run migration.
- Preserve original artifacts.
- Sign migrated outputs.

### Phase 2 Exit Criteria

- Workflows can resume after forced process termination.
- Leases prevent duplicate workflow advancement.
- Queue retries and dead-letter handling are tested.
- Recovery produces explicit audit events.
- Schema migrations are versioned, tested, and reversible by preservation.

## Phase 3: Execution Security

### Goal

Harden execution so the runtime remains safe when tools fail, outputs are malformed, or environments become hostile.

### 11. Harden Worker Isolation

Current subprocess isolation is a good starting point. The long-term direction is container sandboxing.

Progression:

1. Subprocess worker boundary
2. Restricted environment variables
3. Dedicated working directory
4. Read/write filesystem allowlists
5. Network allowlists
6. Container worker
7. Linux namespaces
8. seccomp
9. AppArmor or equivalent profile
10. Rootless execution

Worker isolation rules:

- No inherited broad environment by default.
- No access to project secrets unless explicitly granted.
- No write access outside assigned artifact directory.
- No network except declared and approved scope.
- No shell expansion for user-controlled input.

### 12. Resource Governance

Enforce per-worker limits:

- CPU time
- Wall-clock duration
- Memory
- Network bytes
- File descriptors
- Output bytes
- Number of files created
- Number of subprocesses
- Concurrent executions
- Retries

Quota outcomes:

- Soft warning
- Hard termination
- Quota violation artifact
- Audit event
- Reasoning confidence adjustment if evidence is incomplete

### 13. Secure Secret Handling

Never store plaintext secrets in manifests, logs, reports, reasoning graphs, or replay artifacts.

Add:

- Secret provider abstraction
- Local encrypted secret store
- Secret reference ids
- Secret redaction in logs
- Secret access audit events
- Secret scope declarations in capability contracts
- Future vault integration

Rules:

- Tools receive short-lived secret material only when approved.
- Replay uses secret references, not raw secrets.
- Secret access must affect execution manifest hash inputs without exposing secret values.

### 14. Execution Attestation

Persist attestation for every execution:

- Runtime version
- Worker version
- Tool version
- Platform
- Python version
- Policy hash
- Contract hash
- Worker code hash
- Environment metadata
- Dependency metadata
- Container image digest when available

Attestation should be signed and lineage-linked.

### 15. Tamper Detection

Detect:

- Modified manifests
- Replay divergence
- Lineage corruption
- Signature mismatch
- Missing audit links
- Worker output hash mismatch
- Checkpoint hash mismatch
- Policy hash mismatch
- Contract hash mismatch

Tamper outcomes:

- Mark run as integrity-compromised.
- Refuse replay unless explicitly forced in forensic mode.
- Emit governance audit event.
- Exclude compromised artifacts from benchmark trust scores.

### Phase 3 Exit Criteria

- Worker isolation tests cover filesystem, environment, timeout, and malformed-output behavior.
- Resource limits are enforced and audited.
- Secrets are referenced, redacted, and never stored raw.
- Execution attestation is persisted and signed.
- Tampering causes deterministic verification failure.

## Phase 4: Governance and Trust

### Goal

Make the runtime acceptable to enterprise security, compliance, and operations teams.

### 16. Strong RBAC

Required roles:

- `analyst`: run low-risk approved workflows
- `reviewer`: approve selected workflow transitions
- `auditor`: inspect runs, lineage, signatures, and replay records
- `admin`: manage policies, users, and configuration
- `operator`: manage queues, leases, recovery, and runtime operations
- `readonly`: inspect non-sensitive outputs only

RBAC should control:

- Workflow creation
- Workflow approval
- Scope expansion
- Tool execution
- Policy edits
- Secret access
- Replay execution
- Artifact verification
- Queue recovery
- Benchmark execution

### 17. Approval Workflows

Require human approval before:

- Risky network actions
- Expanded scope
- Local command execution
- Sensitive tools
- Secret access
- High-volume scans
- Replay of non-idempotent actions
- Policy override
- Worker contract expansion

Approval records must include:

- Approver identity
- Role
- Approved action
- Scope
- Expiration
- Policy version
- Reason
- Signature
- Audit link

### 18. Policy Versioning

Every run must be tied to:

- Policy version
- Policy hash
- Runtime version
- Contract version
- Tool version
- Reasoning schema version
- Replay schema version

Policy changes must produce:

- New version
- Diff
- Author
- Approval record when required
- Migration impact if schemas change

### 19. Formal Trust Boundaries

Document:

- What each runtime can do
- What each runtime cannot do
- Authority transitions
- Data flow
- Signature boundaries
- Trust assumptions
- Failure containment

Trust-boundary docs should include diagrams for:

- Workflow lifecycle
- Tool execution lifecycle
- Evidence lifecycle
- Replay lifecycle
- Governance decision flow

### 20. Governance Audit Trails

Every governance decision must be:

- Replayable
- Signed
- Lineage-linked
- Policy-versioned
- Role-attributed
- Queryable

Audit events should cover:

- Allow
- Deny
- Refuse
- Approve
- Expire approval
- Override
- Quota violation
- Signature verification
- Tamper detection
- Recovery action

### Phase 4 Exit Criteria

- RBAC tests cover every privileged operation.
- Approval gates are enforced before risky actions.
- Policy versions are embedded in all run records.
- Trust-boundary documentation matches implemented behavior.
- Governance audit trail is signed and replayable.

## Phase 5: Reasoning Runtime

### Goal

Build trustworthy intelligence, not vague AI confidence.

### 21. Formal Reasoning Graphs

Core structures:

- `ReasoningNode`
- `ReasoningEdge`
- `ConfidenceState`
- `Hypothesis`
- `Contradiction`
- `Assumption`
- `EvidenceReference`

Node types:

- Evidence
- Observation
- Claim
- Hypothesis
- Finding
- Assumption
- Contradiction
- Refusal
- Decision

Edge relations:

- `supports`
- `contradicts`
- `weakens`
- `assumes`
- `derived_from`
- `explains`
- `requires`

### 22. Confidence Propagation

Confidence must be derived from explicit factors:

- Evidence strength
- Evidence freshness
- Tool reliability
- Replayability
- Contradiction count
- Contradiction severity
- Assumption density
- Policy certainty
- Historical reliability

Rules:

- Contradictions reduce confidence.
- Missing evidence prevents high confidence.
- Unsupported claims are marked as unsupported.
- Replay divergence reduces trust.
- Confidence changes must be explainable and replayable.

### 23. Contradiction Engine

Contradictions should detect:

- Conflicting observations
- Unsupported findings
- Tool disagreement
- Replay divergence
- Policy mismatch
- Evidence mismatch
- Stale assumptions

Contradiction outputs:

- Contradiction id
- Conflicting nodes
- Severity
- Confidence impact
- Resolution status
- Required follow-up evidence

### 24. Self-Critique Runtime

The critique runtime challenges:

- Weak assumptions
- Unsupported conclusions
- Insufficient evidence
- Overconfident findings
- Tool reliability issues
- Policy ambiguity
- Missing replay state

Critique should produce structured records, not free-form commentary.

### 25. Probabilistic Hypotheses

Support competing interpretations:

- Multiple hypotheses can explain the same evidence.
- Hypotheses carry probabilities or weighted confidence.
- New evidence updates hypothesis weights.
- Contradictions weaken specific hypotheses.
- Final reports show uncertainty where appropriate.

### 26. Replayable Reasoning

Reasoning replay must reproduce:

- Node creation
- Edge creation
- Confidence changes
- Contradiction insertion
- Hypothesis probability shifts
- Critique outcomes
- Final finding confidence

### 27. Trust Calibration

Trust calibration should consider:

- Evidence quality
- Evidence completeness
- Replay correctness
- Contradiction density
- Tool reliability history
- Policy stability
- Benchmark performance

Calibration output:

- Trust score
- Confidence adjustment
- Explanation
- Inputs used
- Replay hash

### Phase 5 Exit Criteria

- Reasoning graph schema is stable and versioned.
- Confidence propagation is deterministic and tested.
- Contradictions lower confidence in predictable ways.
- Critique records are structured and signed.
- Reasoning replay matches original state.

## Phase 6: Observability

### Goal

Make the runtime inspectable everywhere.

### 28. Runtime Dashboard

The UI should show:

- Active workflows
- Workflow state
- Queue state
- Leases
- Execution manifests
- Evidence lineage
- Reasoning graphs
- Contradictions
- Metrics
- Audit events
- Signature verification status
- Replay status

Design principle:

This should feel like a security operations console, not a marketing dashboard.

### 29. Reasoning Visualizer

Visualize:

- Evidence flow
- Confidence shifts
- Contradictions
- Replay timeline
- Hypothesis competition
- Critique records
- Trust calibration

Required interactions:

- Click a finding and see supporting evidence.
- Click confidence and see propagation inputs.
- Click contradiction and see affected claims.
- Compare original run with replay.
- Filter by runtime, severity, role, or artifact type.

### 30. Metrics and Tracing

Track:

- Workflow latency
- Tool latency
- Replay latency
- Queue wait time
- Failure rates
- Retry counts
- Quota violations
- Approval wait time
- Signature verification failures
- Reasoning drift
- Contradiction density

Start local first:

- JSONL metrics stream
- SQLite index
- CLI inspection commands
- Later OpenTelemetry integration

### 31. Structured Failure Taxonomy

Define failure classes:

- `WorkerFailure`
- `GovernanceFailure`
- `ReplayFailure`
- `LineageFailure`
- `AttestationFailure`
- `PolicyFailure`
- `QueueFailure`
- `LeaseFailure`
- `SignatureFailure`
- `ReasoningFailure`
- `QuotaFailure`
- `RecoveryFailure`

Every failure should include:

- Failure code
- Human-readable message
- Retryability
- Severity
- Runtime
- Workflow id
- Artifact references
- Recovery suggestion

### 32. Explainability APIs

Expose query APIs for:

- Why did this action happen?
- Why was this refused?
- Why did confidence change?
- What evidence supports this finding?
- What contradicted this conclusion?
- Which policy authorized this tool?
- Which approval allowed this transition?
- Which runtime produced this artifact?
- Did replay match the original?

### Phase 6 Exit Criteria

- Operators can inspect live and completed workflows.
- Reasoning graphs are navigable.
- Metrics cover workflow, replay, governance, and tool execution.
- Failures use a stable taxonomy.
- Explainability APIs return structured answers.

## Phase 7: Benchmarking and Verification

### Goal

Make trust measurable.

### 33. Security Benchmark Suite

Benchmark categories:

- Hallucination resistance
- Policy bypass resistance
- Evidence integrity
- Unsafe action prevention
- Replay correctness
- Contradiction handling
- Scope enforcement
- Tool failure handling
- Signature verification
- RBAC enforcement

Benchmark records should be signed and reproducible.

### 34. Replay Correctness Validation

Core invariant:

```text
replay == original
```

Validate:

- Workflow state
- Evidence state
- Reasoning state
- Confidence state
- Contradictions
- Outputs
- Signatures
- Replay hashes

Replay mismatch should produce:

- Diff
- Failure class
- Affected artifacts
- Severity
- Reproduction instructions

### 35. Adversarial Testing

Test:

- Malformed worker output
- Policy corruption
- Replay poisoning
- Evidence tampering
- Contradiction injection
- Signature removal
- Manifest mutation
- Hash-chain truncation
- Lease race attempts
- Capability expansion attempts

### 36. Simulation Worlds

Create synthetic environments:

- Vulnerable labs
- Fake enterprises
- Fake incidents
- Fake attack chains
- Conflicting evidence scenarios
- Partial outage scenarios
- Ambiguous finding scenarios

Simulation requirements:

- Deterministic seeds
- Expected evidence
- Expected reasoning graph
- Expected confidence trajectory
- Expected refusal behavior

### 37. Reproducibility Testing

Every benchmark should define:

- Initial state
- Policy version
- Runtime version
- Input fixtures
- Expected artifacts
- Expected hashes when stable
- Allowed nondeterminism, if any

### Phase 7 Exit Criteria

- Benchmark suite runs locally in CI.
- Replay correctness has golden fixtures.
- Adversarial tests cover tampering and policy bypass attempts.
- Simulation worlds produce deterministic expected outputs.
- Benchmark results are signed and lineage-linked.

## Phase 8: Platform Engineering

### Goal

Turn the runtime into a durable product that can be installed, upgraded, documented, and trusted.

### 38. Packaging

Required:

- Installable package
- Clean CLI
- Semantic versioning
- Upgrade paths
- Changelog
- Release signing plan
- Dependency policy

CLI groups should remain product-oriented:

- `workflow`
- `run`
- `replay`
- `verify`
- `policy`
- `queue`
- `ops`
- `benchmark`
- `runtime`

### 39. API Stability

Stabilize:

- Manifest schema
- Lineage schema
- Reasoning graph schema
- Replay schema
- Worker contract schema
- Audit event schema
- Benchmark record schema
- Tool output schema

Compatibility policy:

- Patch releases do not break schemas.
- Minor releases can add optional fields.
- Major releases can introduce breaking migrations.
- Deprecated fields stay readable for a defined period.

### 40. Documentation

Required docs:

- Product overview
- Threat model
- Runtime contracts
- Governance model
- Replay model
- Evidence lineage model
- Signature model
- Failure semantics
- Recovery semantics
- RBAC model
- Operator guide
- Developer guide
- Benchmark guide

### 41. SECURITY.md

Expand security documentation:

- Supported environments
- Disclosure policy
- Threat assumptions
- Known limitations
- Security guarantees
- Unsupported use cases
- Secret handling
- Reported vulnerability process
- Safe testing guidance

### 42. Architecture Docs

Required diagrams:

- Runtime separation
- Trust boundaries
- Workflow lifecycle
- Tool execution lifecycle
- Evidence lifecycle
- Replay lifecycle
- Governance decision lifecycle
- Queue and lease lifecycle
- Reasoning graph lifecycle

### Phase 8 Exit Criteria

- Package installs cleanly in a fresh environment.
- CLI has stable command groups.
- Schema compatibility policy is documented.
- Security docs are complete enough for external review.
- Architecture diagrams match implementation.

## Phase 9: Optional Advanced Infrastructure

### Goal

Scale only after the local trustworthy runtime is mature.

### 43. Containerized Workers

Add Docker or Podman workers with:

- Rootless mode
- Read-only base filesystem
- Dedicated writable artifact mount
- Network policy
- CPU and memory limits
- Image digest attestation
- Signed worker metadata

### 44. Distributed Execution

Only after local queues, leases, and recovery are stable.

Requirements:

- Idempotent task model
- Distributed leases
- Worker identity
- Signed task payloads
- Signed outputs
- Replay-safe scheduling
- Dead-letter handling

### 45. Remote Execution Nodes

Remote workers require:

- Mutual authentication
- Worker registration
- Worker attestation
- Policy synchronization
- Signed capability contracts
- Signed outputs
- Network isolation
- Revocation support

### 46. Enterprise Auth

Later integrations:

- OIDC
- SAML
- SCIM
- Group-to-role mapping
- Session audit
- Break-glass admin process

### 47. OpenTelemetry

Add production observability when local metrics are stable:

- Traces
- Metrics
- Logs
- Span links to workflow ids
- Attribute redaction
- Exporter configuration

### 48. Plugin SDK

Controlled extensibility:

- Plugin manifest
- Capability contract
- Policy requirements
- Output schema
- Signing requirements
- Test harness
- Compatibility declaration
- Marketplace or registry later

### Phase 9 Exit Criteria

- Advanced infrastructure preserves all earlier trust guarantees.
- Distributed behavior does not weaken replayability.
- Remote execution cannot bypass governance.
- Plugins cannot expand capability without explicit policy approval.

## Engineering Sequence

### Implemented Local-First Foundation

The current project now has the first local product foundation for this roadmap:

- Product identity constants for Trustworthy Autonomous Security Runtime positioning
- Runtime and schema version constants
- Runtime contracts for governance, workflow, tool, evidence, and reasoning boundaries
- Schema-versioned audit, lineage, benchmark, queue, workflow-state, and execution-manifest records
- Signed execution manifests and signed evidence lineage records
- Persistent workflow state records
- Local durable queue task records
- Workflow leases with heartbeat and expired-lease recovery records
- Structured failure taxonomy
- Operational CLI/API inspection for platform metadata, runtime contracts, workflow states, queue records, metrics, events, and failures
- Formal replay validation with `replay(original_run) == original_output` checks over tool outputs, workflow hashes, reasoning graph hashes, replay hashes, findings, and execution manifests
- `security-lab-assistant verify --deep` for forensic runtime verification across signatures, lineage, manifests, replay, policy, benchmarks, and quarantine semantics
- Restricted worker subprocess environment with dedicated worker directories and output byte caps
- Local encrypted secret references with redaction and access audit events
- CI workflow plus strict mypy/pyright configuration

### Immediate Next Milestone

Stabilize the local runtime before adding scale.

Priority order:

1. Product identity cleanup across README, blueprint, and generated guide.
2. Formal schema versions for manifests, lineage, replay, and reasoning graphs.
3. Deterministic replay validation fixtures.
4. Persistent workflow state machine.
5. Local durable queue with leases.
6. Recovery semantics and tests.
7. Expanded RBAC and approval records.
8. Structured failure taxonomy.
9. Reasoning contradiction engine hardening.
10. Benchmark suite with signed records.

### First Enterprise-Grade Release Target

The first serious release should include:

- Clear product positioning
- Runtime contracts
- Signed execution manifests
- Append-only evidence lineage
- Deterministic replay validation
- RBAC and approval gates
- Local durable queue
- Workflow recovery
- Structured failure taxonomy
- Reasoning graph visualizer
- Security benchmark suite
- Expanded SECURITY.md
- Architecture documentation

### Defer Until Later

Defer these until the local runtime is stable:

- Distributed workers
- Remote execution nodes
- OIDC/SAML
- Plugin marketplace
- Cloud deployment
- Heavy LLM orchestration
- Autonomous exploitation workflows

## Product Moat

The moat is not raw model intelligence.

The moat is:

- Deterministic replay
- Evidence-backed reasoning
- Signed runtime artifacts
- Forensic lineage
- Formal governance
- Isolated execution
- Measurable trust
- Contradiction-aware confidence
- Operable recovery

Many AI-security products can produce plausible text. Far fewer can prove why an action happened, what evidence caused a conclusion, which policy authorized it, whether replay matched, and whether the artifacts were tampered with.

## Definition of Done for the Roadmap

This roadmap is complete when the product can answer, with signed evidence:

- What happened?
- Why did it happen?
- Who or what authorized it?
- Which policy version applied?
- Which runtime produced it?
- What evidence supports it?
- What contradicts it?
- What confidence is justified?
- Can it be replayed?
- Did replay match the original?
- Were any artifacts tampered with?
- What failed, and how was it recovered?

That is the standard for a durable, secure, operable product.
