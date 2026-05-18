# Advanced Project Blueprint

## Product Goal

Build an Autonomous Security Lab Assistant that can reason over a lab objective, choose safe tools, collect evidence, and produce actionable findings without becoming an unrestricted attack agent.

## Core Principles

- Scope is checked before action.
- Tools return structured evidence.
- Workflows are deterministic enough to test.
- Refusals are first-class outputs.
- Risky capabilities are added behind explicit policy gates.

## Agent Loop

1. Parse the objective and target.
2. Validate scope.
3. Select tools from the registry.
4. Execute one bounded action at a time.
5. Store observations.
6. Analyze observations into findings.
7. Return a concise run report.

## Initial Threat Model

| Risk | Control |
| --- | --- |
| Scanning public infrastructure | CIDR and hostname allowlist |
| Large unintended scans | Maximum ports per scan |
| Abuse of mail infrastructure | Blocked SMTP submission ports |
| Unbounded downloads | Maximum HTTP bytes |
| Tool ambiguity | Structured tool schemas |
| Hidden failures | Explicit `ok` and refusal data |

## Capability Roadmap

### Phase 1: Foundation

- JSON-RPC MCP-style server
- Scope validation
- TCP connect scanner
- Header recon
- Basic workflow
- Tests

### Phase 2: Lab Runtime

- Docker Compose vulnerable services
- Report writer
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
