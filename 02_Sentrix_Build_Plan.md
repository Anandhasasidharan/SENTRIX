# Sentrix — Upgraded Build Plan (Full Scope)

> **Replaces the scoped-down MVP version.** The MVP had Sentrix doing
> pattern + embedding classification for prompt injection — reasonable for
> a six-week build, but the field has moved past pure detection. This
> version builds the architecture 2026 research actually converged on.

**Build time:** 7–8 weeks · **Difficulty:** Hard · **GPU required:** No

## One-liner

EDR/XDR for AI agents, upgraded from "classify attacks after the fact" to
"architecturally prevent most of them" — a dual-LLM, capability-based
reference monitor (in the lineage of CaMeL/FIDES) sits in front of every
tool call and enforces a deterministic policy regardless of what the model
was talked into, while a forensics layer still gives you the Sentrix MVP's
session replay and incident reporting for whatever gets through.

## What Changed From the MVP Version, and Why

The MVP scoped Sentrix as a classifier: pattern + embedding matching on
trace data to flag prompt injection, tool hijacking, memory poisoning.
That's what most vendors ship, and it has a known, published weakness —
by 2025 the evidence against pure model/detector-level defenses was
already strong, with adaptive attackers recovering high success rates
against the very detectors they were tested against. Detection-only is
not where the state of the art sits anymore.

**What the field converged on instead:** stop trying to make the model
refuse malicious instructions, and instead enforce security *outside* the
model with a deterministic policy that mediates what the agent is
actually allowed to do — regardless of what it was talked into. This is
the shared structure behind a cluster of 2024–2026 systems: CaMeL, FIDES,
Progent, RTBAS, Conseca, and FORGE. They differ in mechanism (capabilities,
information-flow labels, symbolic privilege rules) but share the same
move security has used since the 1970s: a reference monitor enforcing
policy at the point an action takes effect, not a classifier hoping to
catch bad behavior after the model already decided on it.

The canonical version of this, CaMeL, uses a **dual-LLM pattern**: a
Privileged LLM plans the task from the trusted user query and never sees
untrusted data directly; a Quarantined LLM processes untrusted content
(web pages, emails, retrieved documents) with no tool access; a custom
interpreter sits between them, tracks data provenance, and enforces a
capability policy before every tool call. Several of these systems report
near-elimination of attacks on AgentDojo, the standard dynamic evaluation
benchmark for this exact problem (four domains: banking, Slack/browsing,
workspace, travel).

## Read This Before You Build: Honesty Is the Feature

Two things to be upfront about, because the field itself is upfront about
them:

- **Out-of-band defenses aren't a solved story either.** A June 2026 paper
  specifically stress-tests CaMeL, FIDES, Progent, RTBAS, and FORGE against
  *adaptive, defense-aware attackers* rather than the static attacks they
  were originally evaluated against — this is still an open question, not
  a closed one. A related paper (AgentDyn) questions whether these
  defenses hold up in real-world *dynamic* environments as opposed to the
  benchmark conditions they were designed for. Build the reference monitor,
  then explicitly test it against obfuscated payloads (e.g., attacker
  instructions encoded in Unicode Braille, which is documented as bypassing
  simple input/output "firewall" defenses even when they saturate standard
  benchmarks) and report where it holds and where it breaks.
- **Detection still matters — as forensics, not as your primary control.**
  Keep the MVP's classifier layer, but reframe its job: it's there to
  explain *why* the reference monitor blocked something, to catch the
  cases the monitor's policy doesn't cover, and to feed the session replay
  and incident report. It is not the thing standing between an attacker
  and a tool call anymore — the reference monitor is.

## Core Features

### 1. Dual-LLM Reference Monitor (the architectural core)
A Privileged LLM plans from the trusted user query only. A Quarantined
LLM processes untrusted content (retrieved documents, emails, web pages)
with zero tool access. A custom interpreter between them tracks data
provenance through the plan and enforces a capability policy — which
tools, on which data, under which conditions — before any tool call
executes, independent of what either LLM "decided."

### 2. Static Taint Analysis (pre-deployment layer)
Before an agent ever runs, statically analyze its tool-integration code
for Prompt-to-Anything Injection (P2Xi) vulnerabilities: model LLM-
generated output as a taint source, track its propagation through
sensitive sink functions (file writes, shell execution, DB queries,
outbound requests), and flag paths where untrusted LLM output reaches a
sink without validation. This is a design-time complement to the runtime
reference monitor — following the TaintP2X approach (ICSE 2026), which
reports meaningfully better recall than prior static methods on a labeled
vulnerability set.

### 3. Adversarial Classifier (forensics layer, not primary defense)
Retained from the MVP, reframed: prompt-injection phrase detection,
tool-call anomaly detection, memory-diff anomaly detection — now feeding
explanations into the incident report rather than being the last line of
defense.

### 4. Session Replay + Multi-Agent Attack DAG
Unchanged in spirit from the MVP: a Wireshark-style timeline and a
delegation-chain DAG, now annotated with *which layer* caught (or missed)
each step — reference monitor, static analysis, or classifier — which is
itself useful data for tuning the system.

### 5. Adaptive Attack Test Harness
Don't just test against the standard AgentDojo attack templates. Build (or
adapt) an obfuscation layer — encoding, paraphrase, indirection — and
re-run your reference monitor and classifier against it, following the
adaptive-evaluation methodology from the June 2026 stress-test paper.
Report your monitor's block rate against both the standard and the
obfuscated attack sets side by side.

### 6. Incident Response Report Generator
Unchanged from the MVP: auto-drafted root cause, affected agents/tools/
data, and blast radius — now sourced from all three layers (monitor,
static analysis, classifier) instead of just the classifier.

## Architecture

```
        User Query (trusted)              Untrusted content
        (web pages, retrieved docs, emails, tool outputs)
              |                                   |
              v                                   v
     Privileged LLM (plans)          Quarantined LLM (no tool access)
              |                                   |
              +----------------+------------------+
                               |
                               v
              Interpreter / Reference Monitor
      (tracks data provenance, enforces capability
       policy before every tool call)
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
        Adaptive Attack Test Harness (standard + obfuscated
        attacks, run against the whole pipeline periodically)

  (separate, pre-deployment)
  Static Taint Analysis of tool-integration code -> flags
  P2Xi vulnerabilities before the agent ever runs
```

## Tech Stack

| Component | Choice | Why |
|---|---|---|
| Reference monitor | Custom interpreter (Python), capability-based policy | No mature off-the-shelf library yet — this is genuinely novel engineering |
| Dual-LLM orchestration | Claude via Anthropic API for both roles, strict context isolation | Privileged/Quarantined separation must be enforced at the code level, not by prompting alone |
| Static analysis | Custom taint tracker over your agent's tool-integration code, or adapt TaintP2X's published approach | Design-time complement to runtime enforcement |
| Trace/collector | Shared with AgentReflex's SDK | No duplicated infrastructure |
| Eval | AgentDojo (standard benchmark) + a self-built obfuscation layer | Standard, citable numbers plus your own adaptive stress test |
| Dashboard | Same stack as AgentReflex | Shared UI investment |

## Implementation Plan

**Weeks 1–2 — Reference monitor core:** implement the Privileged/
Quarantined LLM split with true code-level isolation (the quarantined
model must have zero tool-calling capability, not just an instruction not
to use tools); build the interpreter's capability-policy enforcement point.

**Week 3 — Static taint analysis:** build the taint tracker for your
target agent framework's tool-integration code; validate against a small
set of intentionally vulnerable and intentionally safe examples you
construct yourself.

**Week 4 — Classifier + replay/DAG:** port the MVP's classifier to run as
the forensics layer; session replay timeline; multi-agent attack DAG.

**Week 5 — AgentDojo evaluation:** run your reference monitor against the
standard AgentDojo benchmark; report block rate by domain (banking,
Slack, workspace, travel).

**Week 6 — Adaptive attack harness:** build the obfuscation layer
(encoding, paraphrase, indirection); re-run the full pipeline; report the
delta between standard and obfuscated block rates, honestly.

**Weeks 7–8 — Incident reports, polish, demo:** report generator wired to
all three layers; a scripted live demo showing an attack blocked at the
monitor, one caught only by the classifier, and — if you find one — one
that gets through the obfuscation layer, which is exactly the kind of
honest gap analysis that reads as sophisticated rather than a shortfall.

## Interview Narrative

"Classifying prompt injection after the fact is what most vendors do, and
it's known to be defeatable by adaptive attackers. I built the
architecture the field actually converged on instead: a dual-LLM reference
monitor in the lineage of CaMeL and FIDES that enforces a deterministic
capability policy before every tool call, regardless of what the model was
talked into — plus a static taint-analysis pass before deployment, and a
classifier layer that's now forensics rather than the primary defense. I
tested it against both the standard AgentDojo benchmark and my own
obfuscated-attack harness, and I can show you exactly where it holds and
where it still doesn't."

## Recruiter Signal

| What it proves | Why it matters |
|---|---|
| Systems security thinking, not just ML | Reference monitors and capability policies are classical security engineering applied to a new substrate |
| Awareness of adaptive-attacker methodology | You test against attacks designed to defeat your specific defense, not just the standard benchmark |
| Static + dynamic analysis together | Design-time and runtime security are different skills; showing both is rare |
| Honest gap reporting | Naming exactly where your system fails is stronger signal than claiming it doesn't |

## Sources

- CaMeL, FIDES, Progent, RTBAS, Conseca, FORGE — the out-of-band,
  reference-monitor family this architecture is built in the lineage of
- "Adaptive Evaluation of Out-of-Band Defenses Against Prompt Injection in
  LLM Agents" (arXiv:2606.26479, June 2026) — the adaptive-attacker
  stress-test methodology
- "AgentDyn: Are Your Agent Security Defenses Deployable in Real-World
  Dynamic Environments?" (arXiv:2602.03117)
- TaintP2X (ICSE 2026) — static taint analysis for Prompt-to-Anything
  Injection vulnerabilities
- AgentDojo (Debenedetti et al.) — the standard dynamic evaluation
  benchmark for prompt injection in tool-using agents
- "Open Challenges in Multi-Agent Security" (arXiv:2505.02077) — broader
  survey, includes CaMeL as a case study
- OWASP LLM Top 10 (LLM01: prompt injection) and NIST AI 600-1 Generative
  AI Profile — regulatory/standards framing
