# Sentrix — EDR/XDR for AI Agents

> Architectural prevention, not just detection. A dual-LLM reference monitor
> enforces capability policy before every tool call — an instance of **classical
> Biba integrity protection + reference monitoring + least privilege** applied
> to LLM agents. Static taint analysis catches P2Xi vulnerabilities at design
> time. An adversarial classifier provides forensics and explanations. All
> layers feed session replay, attack DAGs, and incident reports.
>
> Built against **MCP spec 2026-07-28** (RC as of this writing; final release
> July 28, 2026). Provenance tracking uses **RFC 8707 Resource Indicators**,
> inheriting confused-deputy protection from the standard rather than
> reinventing it. Evaluated against **both AgentDojo and AgentDyn** (the harder,
> more current benchmark).

## Quick Start

```bash
pip install -e .
python -m examples.demo
```

Set `ANTHROPIC_API_KEY` for full dual-LLM functionality (offline mode runs without one):

```bash
export ANTHROPIC_API_KEY=sk-...
```

Run tests:

```bash
pip install -e ".[dev]"
python -m pytest tests/
```

Launch the dashboard:

```bash
pip install -e ".[dashboard]"
python -m sentrix.dashboard.server
```

Run dual-benchmark evaluation (AgentDojo + AgentDyn):

```bash
python -c "
from sentrix import Sentrix
from sentrix.harness.dual_benchmark import DualBenchmarkEvaluator

s = Sentrix()
e = DualBenchmarkEvaluator(reference_monitor=s.monitor, classifier=s.classifier)
print(e.evaluate())
"
```

## Architecture

```
         User Query (trusted)              Untrusted content
               |                                   |
               v                                   v
      Privileged LLM (plans)          Quarantined LLM (no tool access)
               |                                   |
               +----------------+------------------+
                                |
                                v
               Interpreter / Reference Monitor
       (provenance tracking via RFC 8707 Resource Indicators;
        capability policy enforced before every tool call;
        targets MCP spec 2026-07-28, stateless protocol model)
                                |
                  +-------------+--------------+
                  |                             |
                  v                             v
           Tool Execution                Blocked / Flagged
                  |                             |
                  v                             v
       Trace Stream (shared with          Adversarial Classifier
       AgentReflex's SDK)                 (forensics, explanation)
                  |                             |
                  +-------------+--------------+
                                |
                                v
        Session Replay + Attack DAG + Incident Report
                                |
                                v
         Adaptive Attack Test Harness (standard + obfuscated +
         MCP-specific: hit-and-run task abuse + header-leakage checks,
         run against the whole pipeline periodically)
                                |
                                v
         Dual-Benchmark Eval: AgentDojo (standard) +
         AgentDyn (harder, current) reported side by side

   (separate, pre-deployment)
   Static Taint Analysis of tool-integration code -> flags
   P2Xi vulnerabilities before the agent ever runs
```

## Classical Security Framing

The architecture is an instance of three classical security concepts applied to
LLM agents — **say this explicitly** rather than only calling it a
"capability-based policy":

1. **Biba Integrity Model** — no read down, no write up. The Privileged LLM
   (high integrity) plans from trusted user queries and never reads untrusted
   data directly. The Quarantined LLM (low integrity) processes untrusted
   content but has no tool access. The reference monitor prevents data from
   flowing from low-integrity to high-integrity domains without mediation.

2. **Reference Monitor** — a tamperproof, always-invoked, verifiable
   enforcement point (in the sense of 1970s security engineering: Anderson,
   Bell-LaPadula, Biba). Every tool call passes through the monitor, which
   checks the action against deterministic policy independent of what the
   model was talked into doing.

3. **Least Privilege** — each agent gets exactly the tool access it needs, no
   more. Capability rules are scoped by tool, data sensitivity, and (with
   RFC 8707) resource authority. Even a compromised quarantined context cannot
   escalate to privileged operations because the capability was never granted.

This framing directly follows the June 2026 adaptive-evaluation paper
(arXiv:2606.26479) that organizes the entire CaMeL/FIDES/Progent/RTBAS/FORGE
family as instances of these classical patterns.

## How It Works

### 1. Dual-LLM Reference Monitor (with RFC 8707 Provenance)

The core architectural defense. Two LLM instances with strict code-level isolation:

- **Privileged LLM** — receives trusted user queries, generates plans, has tool access. Never sees untrusted content directly.
- **Quarantined LLM** — processes untrusted content (emails, web pages, retrieved documents) with zero tool-calling capability.
- **Reference Monitor** — sits between planning and execution. Tracks data provenance via **RFC 8707 Resource Indicators** (URIs like `resource://sentrix/data/email/inbox/msg-123`), enforces a capability-based policy before every tool call. The RFC 8707 scheme provides confused-deputy protection: a resource indicator issued for one authority cannot authorize access to another.

```python
from sentrix import Sentrix
from sentrix.models.policy import AgentPolicy, DataSensitivity

s = Sentrix()
s.configure_agent(
    agent_id="my_agent",
    policy=AgentPolicy(
        allowed_tools=["read_file", "list_dir", "send_email"],
        blocked_tools=["exec_command", "delete_file", "modify_system"],
        max_sensitivity=DataSensitivity.INTERNAL,
    ),
)
```

Built against the **MCP protocol's stateless model** — no session ID is stored
in instance state. All public methods accept `session_id` as an optional
parameter. The protocol is forward-compatible with MCP 2026-07-28, which
removes session IDs and the `initialize`/`initialized` handshake entirely.

Toggles between legacy and RFC 8707 provenance tracking via `use_rfc8707`:

```python
s = Sentrix(use_rfc8707=True)  # RFC 8707 Resource Indicators
s = Sentrix(use_rfc8707=False)  # legacy TaintLabel scheme (default)
```

### 2. Static Taint Analysis

Pre-deployment AST-based scanner. Tracks taint from LLM output sources to sensitive sinks (shell execution, file writes, DB queries, outbound requests). Flags unvalidated paths as high severity; paths passing through validation functions (e.g. `sanitize_input`) as low severity.

```python
from sentrix.static_analysis.taint_tracker import TaintTracker

tracker = TaintTracker()
for result in tracker.scan_directory("src/"):
    for flaw in result.flaws:
        print(f"{flaw.severity}: {flaw.file_path}:{flaw.line_number} "
              f"{flaw.source} -> {flaw.sink} (validated={flaw.validated})")
```

### 3. Adversarial Classifier

Forensics layer (not primary defense). Two-stage detection:

- **Regex patterns** — prompt injection (ignore instructions, role-play, system prompt extraction, delimiter escape, hypotheticals), memory poisoning (identity rewrite, instruction injection, authority override), tool anomalies (privilege escalation, credential access)
- **TF-IDF embedding** — cosine similarity against 15 attack seed templates. Automatic fallback if `sentence-transformers` is unavailable.

The classifier explains *why* something was flagged — feeding the incident report with which pattern matched and the evidence.

### 4. Trace Stream

Event bus that decouples event producers from consumers. Thread-safe, supports pub/sub, session-scoped replay, configurable max buffer.

```python
from sentrix.core.trace_stream import TraceStream, StreamCollector

stream = TraceStream(max_buffer=5000)
collector = StreamCollector(stream)

stream.subscribe("my_consumer", lambda se: print(se.event))
```

Integrated automatically into the `Sentrix` class — all events are published to the trace stream.

### 5. Session Replay + Attack DAG

Timeline shows every event in chronological order with per-layer annotations. Attack DAG visualises the delegation chain as an ASCII tree with verdict and blocking layer.

### 6. Adaptive Attack Harness

Tests your defenses against obfuscated payloads designed to bypass detection:

| Technique | Description |
|-----------|-------------|
| `base64` | Encode payload, prefix with `DECODE:` |
| `braille` | Map ASCII to Unicode Braille range |
| `homoglyph` | Replace letters with visually similar Unicode |
| `zerowidth` | Interleave zero-width joiners/ non-joiners |
| `paraphrase` | Prepend polite/academic/urgent/confused phrasing |
| `split` | Shuffle word chunks |

Reports standard vs obfuscated block rates side by side.

**MCP-specific attack classes** (new in v2):

| Attack Class | Test Cases | What It Checks |
|---|---|---|
| Hit-and-run task abuse | 3 (email burst, file-read spam, search flood) | Whether the capability policy has a resource-quota dimension |
| Header-leakage check | 3 (API key, credentials, PII in headers) | Whether sensitive data leaks into `Mcp-Method`/`Mcp-Name` HTTP headers |

### 7. Incident Report Generator

Auto-drafts structured reports from all three layers, including static taint analysis findings:

```python
taint_results = s.scan_tool_code("src/")
report = s.generate_report("session_1", taint_results=taint_results)
print(s._reporter.render_markdown(report))
# → Root cause, blast radius, affected assets, verdicts by layer,
#   static taint findings, attack DAG, timeline, recommendations
```

### 8. Dual-Benchmark Evaluation

Run the reference monitor against **both** AgentDojo (standard, 30 tasks across
6 domains) and **AgentDyn** (harder, 24 dynamic tasks with mixed benign+malicious
context):

```python
from sentrix.harness.dual_benchmark import DualBenchmarkEvaluator

e = DualBenchmarkEvaluator(reference_monitor=s.monitor, classifier=s.classifier)
results = e.evaluate()
print(f"AgentDojo: {results['agentdojo']['block_rate']}")
print(f"AgentDyn:  {results['agentdyn']['block_rate']}")
print(f"Delta:     {results['comparison']['delta']}")
```

Why two benchmarks? Several 2026 papers report AgentDojo's undefended attack
success rate is near-zero on frontier models, which makes a "near-elimination
of attacks" claim against it alone less informative. AgentDyn adds
dynamic/open-ended tasks, helpful instructions mixed into untrusted content,
and delayed-reveal attacks — it is a harder, more realistic evaluation.

The real AgentDyn repo (`github.com/leolee99/AgentDyn`) can be used directly
by setting `AGENTDYN_REPO_PATH` — Sentrix will auto-discover its 201 injection
tasks. Without it, 24 representative simulated tasks are used.

### 9. Dashboard

FastAPI + Jinja2 + Bootstrap web UI with pages for stats overview, session timeline (table + raw), attack DAG, evaluation comparison, AgentDojo eval, dual-benchmark comparison, and incident reports.

## Demo

Run the interactive demo:

```bash
python -m examples.demo
```

Shows three attack scenarios:

| Scenario | Name | Defense Layer | Outcome |
|---|---|---|---|
| A | SARAH | Reference Monitor | Blocked — tool is in blocked list |
| B | MARCUS | Classifier | Flagged — injection detected on allowed tool |
| C | EVE | Obfuscation bypass | Base64 hides injection from regex; monitor still blocks the tool |

## Project Structure

```
sentrix/
├── src/sentrix/
│   ├── classifier/        # Adversarial classifier (regex + TF-IDF embedding)
│   ├── core/              # Reference monitor, provenance tracker (RFC 8707), trace stream
│   ├── dashboard/         # FastAPI web UI
│   ├── dual_llm/          # Privileged/Quarantined LLM isolation, Anthropic client
│   ├── harness/           # Obfuscator, evaluator, AgentDojo, AgentDyn, dual-benchmark
│   ├── models/            # Pydantic data models (events, policy)
│   ├── replay/            # Timeline, AttackDAG builder
│   ├── reporting/         # Incident report generator
│   ├── static_analysis/   # AST-based taint tracker
│   ├── sentrix.py         # Main orchestration class
│   └── __init__.py
├── examples/
│   └── demo.py            # Interactive demo (3 scenarios)
├── tests/                 # 116+ tests across all modules
└── pyproject.toml
```

## Dependencies

| Dependency | Required | Purpose |
|---|---|---|
| `pydantic>=2.0` | Yes | Data models |
| `anthropic>=0.30` | No (fallback) | Anthropic API client |
| `scikit-learn` | No (fallback) | TF-IDF embedding classifier |
| `fastapi`, `uvicorn`, `jinja2` | Dashboard only | Web UI |

## Tests

116+ tests covering every module:

```bash
python -m pytest tests/ -v
```

| Test file | Scope |
|---|---|
| `test_classifier.py` | Regex patterns, tool call analysis, memory diff |
| `test_embedding.py` | TF-IDF classifier, similarity, batch, thresholds |
| `test_dual_llm.py` | Context isolation, provenance labels |
| `test_reference_monitor.py` | Policy enforcement, provenance tracking, callbacks |
| `test_rfc8707_provenance.py` | RFC 8707 Resource Indicators, dual-mode, confused-deputy |
| `test_static_analysis.py` | Taint detection, validation awareness, severity |
| `test_replay.py` | Timeline, AttackDAG, summary stats |
| `test_harness.py` | Obfuscator techniques, evaluator, MCP-specific attacks |
| `test_trace_stream.py` | Pub/sub, replay, buffer, exception safety |
| `test_agentdojo.py` | Template conversion, evaluator, monitor integration |
| `test_agentdyn.py` | AgentDyn tasks, evaluator, dual-benchmark comparison |
| `test_anthropic_client.py` | Error classification, config, env vars |
| `test_integration.py` | Full pipeline, evaluator, report generation |

## Background

Built in the lineage of CaMeL, FIDES, Progent, RTBAS, Conseca, and FORGE — the
2024–2026 research consensus that security for LLM agents should be enforced
*outside* the model via a deterministic reference monitor, not left to the
model's instruction-following ability. This architecture is explicitly an
instance of **classical Biba integrity + reference monitoring + least
privilege** applied to a new substrate.

Key influences:
- CaMeL / FIDES — dual-LLM architecture with capability-based policy
- TaintP2X (ICSE 2026) — static taint analysis for P2Xi vulnerabilities
- AgentDojo (Debenedetti et al.) — standard dynamic evaluation benchmark
- AgentDyn (arXiv:2602.03117) — harder, dynamic benchmark with mixed context
- "Adaptive Evaluation of Out-of-Band Defenses" (arXiv:2606.26479, 2026) —
  adaptive attacker methodology, Biba/ref-monitor/least-privilege reframing
- MCP Specification 2026-07-28 — OAuth 2.1/OIDC authorization, RFC 8707
  Resource Indicators, stateless protocol model
- RFC 8707 (Resource Indicators for OAuth 2.0) — confused-deputy protection
- NSA CSI_MCP_SECURITY (PP-26-1834, May 2026) — data-classification zoning
- OWASP LLM Top 10 (LLM01), NIST AI 600-1 — regulatory framing
