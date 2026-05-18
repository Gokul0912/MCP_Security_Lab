# Trustworthy Autonomous Security Runtime Blueprint

## Product Goal

Build a governed runtime for bounded, explainable, replayable security workflows. The product should be understood as a Trustworthy Autonomous Security Runtime or Explainable Security Workflow Runtime, not an AI hacking platform.

For the complete product-engineering roadmap, see [product_roadmap.md](product_roadmap.md).

## Core Principles

- Scope is checked before action.
- Tools return structured evidence.
- Workflows are deterministic enough to test.
- Refusals are first-class outputs.
- Runs, reports, and audit events are first-class product artifacts.
- Reasoning claims are scored, replayable, and tied to evidence.
- Uncertainty, assumptions, contradictions, and tool reliability reduce confidence instead of being hidden.
- Risky capabilities are added behind explicit policy gates.
- Product operations are role-guarded, quota-bound, observable, and signed.

## Agent Loop

1. Parse the objective and target.
2. Validate scope.
3. Select tools from the registry.
4. Execute one bounded action at a time.
5. Store observations.
6. Analyze observations into findings.
7. Score reasoning quality and build a formal reasoning graph.
8. Run benchmark checks for hallucination resistance, policy bypass resistance, evidence integrity, unsafe action prevention, false positive control, and reasoning depth.
9. Persist the run and audit events.
10. Return a concise run report.

## Initial Threat Model

| Risk | Control |
| --- | --- |
| Scanning public infrastructure | CIDR and hostname allowlist |
| Large unintended scans | Maximum ports per scan |
| Abuse of mail infrastructure | Blocked SMTP submission ports |
| Unbounded downloads | Maximum HTTP bytes |
| Tool ambiguity | Structured tool schemas |
| Hidden failures | Explicit `ok` and refusal data |
| Redirect escape | Redirects reported but not followed |
| Audit gaps | JSONL audit events and persisted runs |
| Operator confusion | CLI run list/show commands |
| Toolchain isolation | SARIF export for downstream security platforms |
| Slow scans | Bounded concurrent TCP probes |
| Sci-fi reasoning claims | Quantified reasoning quality, graph hashes, replay manifests, and benchmark checks |
| Hallucinated findings | Evidence coverage and hallucination-risk scoring |
| Overconfidence | Contradiction pressure, assumption density, and dynamic trust calibration |
| Artifact tampering | Detached HMAC signatures for reports, SARIF, visualizers, benchmark records, and run JSON |
| Uncontrolled batch activity | Human approval gate, target quotas, and role checks |
| Blind operations | Workflow event stream, metrics stream, benchmark records, and audit verification |
| Compromised tool execution | Subprocess worker boundary, capability contracts, timeouts, signed execution manifests |

## Product Runtime Architecture

- Policy engine: validates targets, ports, URLs, batch sizes, and approval requirements.
- Workflow runtime: executes deterministic bounded workflows and emits event stream entries.
- Reasoning runtime: builds typed reasoning graphs, replay states, confidence propagation, and visualizer artifacts.
- Persistence layer: stores run JSON, reports, SARIF, visualizers, benchmark records, metrics, signatures, and audit logs.
- Governance layer: enforces role permissions for analyst, reviewer, admin, and auditor operations.
- Operations layer: exposes local metrics, workflow events, audit verification, and artifact signature verification.

## Runtime Contracts

| Runtime | Authority | Cannot Do | Integrity Guarantee |
| --- | --- | --- | --- |
| Governance | RBAC, approvals, quotas, policy checks, signature/audit verification | Execute tools, mutate policy during a run, make probabilistic claims | Deterministic decisions |
| Reasoning | Hypotheses, contradictions, confidence propagation, reasoning graphs | Execute tools, mutate policy, write evidence directly | Read-only evidence access |
| Tool | Bounded network IO and bounded analysis | Change policy, persist final artifacts, bypass governance | Timeout-constrained tool results |
| Evidence | Artifact storage, lineage, signatures, benchmark records | Execute tools, alter policy decisions | Append-only hash-chained lineage |
| Workflow | State transitions, event streaming, scheduling, orchestration | Direct network IO, direct policy mutation | Governance-before-tool execution |

## Capability Roadmap

### Phase 1: Foundation

- JSON-RPC MCP-style server
- Scope validation
- TCP connect scanner
- Header recon
- Basic workflow
- Tests
- Run store
- Audit log
- Markdown reports
- SARIF exports
- SQLite metadata index
- Risk scoring

### Phase 2: Lab Runtime

- Docker Compose vulnerable services
- Evidence database
- Local browser automation for web labs

### Phase 3: Agentic Orchestration

- Planner and critic roles
- Tool budget tracking
- Workflow state machine
- Human approval checkpoints

### Phase 4: Security Engineering Depth

- SBOM parsing
- Dependency advisories
- Static config review
- SARIF export
- Attack-tree style reporting for labs

### Phase 5: Security Reasoning Verification

- Formal `ReasoningNode`, `ReasoningEdge`, and `ReasoningState` data structures
- Evidence-to-hypothesis graphs with `supports`, `contradicts`, `weakens`, `derived_from`, and `assumes` relations
- Weighted confidence propagation with contradiction penalties
- Deterministic replay manifests with tool calls, graph states, confidence shifts, contradictions, graph hashes, state hashes, and replay hashes
- HTML explainability visualizer artifacts
- Reasoning quality scores
- Security agent benchmark suite
- Probabilistic hypothesis distributions
- AI safety resistance tests
- Cross-run intelligence correlation
- Dynamic trust calibration
- Synthetic security simulation worlds
- Reasoning replay diffing

### Phase 6: Product Operations

- Approval-gated batch orchestration
- Local queue-style batch records
- Workflow event streaming
- Local metrics and latency tracking
- Detached artifact signatures
- RBAC guard checks
- Resource quotas
- Artifact verification commands

### Phase 7: Runtime Isolation

- Runtime contract objects
- Governance runtime wrapper
- Reasoning runtime wrapper
- Tool runtime execution boundary
- Evidence runtime append-only lineage
- Workflow runtime event boundary
- Trust-boundary validation tests

### Phase 8: Secure Execution Runtime

- Subprocess sandbox worker for tool execution
- Worker capability contracts
- Execution manifests
- Worker attestation with runtime version, capability set, policy hash, Python version, and platform
- Signed worker output hashes
- Timeout, crash, and worker-error failure semantics
- Per-execution manifest persistence under `.security_lab_assistant/executions`
- Tests for subprocess execution, manifest signing, capability declarations, and worker error handling
