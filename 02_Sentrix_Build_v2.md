# Sentrix — Build Plan v2 (July 2026)

> **v2 changelog:** merges the original "Full Scope" plan with the July
> 2026 landscape check. The most consequential change is external, not
> architectural: the MCP protocol's largest-ever spec revision finalizes
> **July 28, 2026** — inside this plan's build window. Building against
> the outgoing spec is avoidable at zero extra cost by targeting the new
> one from day one. Also added: AgentDyn as a second, near-zero-friction
> eval benchmark; RFC 8707-based provenance tracking (a net time-saver);
> two new adaptive-harness test cases; and a classical-security reframing
> of the reference monitor. Total added effort: ~1 week (8–9 weeks total),
> partially offset by time saved elsewhere.

**Build time:** 8–9 weeks · **Difficulty:** Hard · **GPU required:** No

## One-liner

EDR/XDR for AI agents, upgraded from "classify attacks after the fact" to
"architecturally prevent most of them" — a dual-LLM, capability-based
reference monitor (in the lineage of CaMeL/FIDES) sits in front of every
tool call and enforces a deterministic policy regardless of what the model
was talked into, while a forensics layer still gives you session replay
and incident reporting for whatever gets through. **[NEW]** Built and
tested against the MCP protocol's July 2026 spec revision rather than the
outgoing one, evaluated against both the standard AgentDojo benchmark and
the harder, more current AgentDyn benchmark.

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

**[NEW]** Two developments since the original plan sharpen this further:

- **MCP's own spec is being rewritten around exactly this problem's
  authorization layer.** MCP 2026-07-28 (final release July 28, 2026;
  release candidate shipped May 21, 2026) rewrites authorization around
  OAuth 2.1/OIDC, mandates OAuth 2.0 Protected Resource Metadata
  (RFC 9728), and mandates Resource Indicators (RFC 8707) on the client
  side — the latter specifically closes a confused-deputy class of bug
  (a token issued for server A being replayed against server B). This
  plan's reference monitor and MCP's own new spec are converging on the
  same problem from different directions; building against the new spec
  means inheriting some of this protection rather than reinventing it.
- **AgentDojo may be saturating.** Multiple 2026 papers report AgentDojo
  and InjecAgent producing near-zero attack success rates on current
  frontier models even with *no* defense at all. AgentDyn
  (arXiv:2602.03117) was built specifically to address this, adding
  dynamic/open-ended tasks, helpful (non-malicious) instructions mixed
  into the same context, and harder user tasks — and it's a drop-in
  extension of AgentDojo's own evaluation harness (same scripts, same
  model list, CaMeL and Progent already supported as defenses).

## Read This Before You Build: Honesty Is the Feature

Two things to be upfront about, because the field itself is upfront about
them:

- **Out-of-band defenses aren't a solved story either.** A June 2026 paper
  specifically stress-tests CaMeL, FIDES, Progent, RTBAS, and FORGE against
  *adaptive, defense-aware attackers* rather than the static attacks they
  were originally evaluated against — this is still an open question, not
  a closed one. This paper's own framing is worth adopting directly: it
  organizes the entire CaMeL/FIDES/Progent/RTBAS/FORGE family as instances
  of **classical Biba integrity protection + reference monitoring + least
  privilege** — 1970s security theory applied to a new substrate. Say this
  explicitly in your README rather than only calling it a "capability-based
  policy"; it signals you understand what you built, not just that you
  built something that works. A related paper (AgentDyn) questions whether
  these defenses hold up in real-world *dynamic* environments as opposed to
  the benchmark conditions they were designed for. Build the reference
  monitor, then explicitly test it against obfuscated payloads (e.g.,
  attacker instructions encoded in Unicode Braille, which is documented as
  bypassing simple input/output "firewall" defenses even when they saturate
  standard benchmarks) and report where it holds and where it breaks.
- **Detection still matters — as forensics, not as your primary control.**
  Keep the MVP's classifier layer, but reframe its job: it's there to
  explain *why* the reference monitor blocked something, to catch the
  cases the monitor's policy doesn't cover, and to feed the session replay
  and incident report. It is not the thing standing between an attacker
  and a tool call anymore — the reference monitor is.
- **[NEW] The standard benchmark may already be too easy for frontier
  models.** If AgentDojo's undefended attack success rate is already near
  zero on the models you're testing, "my monitor achieves near-elimination
  of attacks on AgentDojo" is a weaker claim than it used to be — the base
  rate moved, not just your defense. Report AgentDojo and AgentDyn side by
  side and say so plainly.
- **[NEW] You're building against a release candidate.** MCP 2026-07-28
  is an RC as of this writing; the finalized spec ships July 28, 2026.
  Some details could shift before final release. State this explicitly in
  your README rather than presenting RC-tested behavior as if it were
  tested against the final spec.

## Core Features

### 1. Dual-LLM Reference Monitor (the architectural core) **[UPDATED]**
A Privileged LLM plans from the trusted user query only. A Quarantined
LLM processes untrusted content (retrieved documents, emails, web pages)
with zero tool access. A custom interpreter between them tracks data
provenance through the plan and enforces a capability policy — which
tools, on which data, under which conditions — before any tool call
executes, independent of what either LLM "decided."

**[NEW]** Target **MCP spec 2026-07-28** from the start, not the outgoing
2025-11-25 spec — the build window overlaps the July 28 final release, so
there's no cost advantage to starting against the older spec. Two concrete
design consequences:

- **Build the interpreter's provenance-tracking layer on top of RFC 8707
  Resource Indicators** (mandatory for MCP clients under the new spec)
  rather than as a fully separate, bespoke scheme. This is a net
  *reduction* in implementation effort versus a from-scratch capability
  scheme, and it's more realistic — it's what a production system would
  actually do, and it inherits RFC 8707's confused-deputy protection
  instead of reinventing it.
- **Design for the protocol's new stateless model** (session IDs and the
  `initialize`/`initialized` handshake are removed in the new spec) rather
  than assuming session-scoped state is available to key your policy
  decisions on.

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

### 5. Adaptive Attack Test Harness **[UPDATED]**
Don't just test against the standard AgentDojo attack templates. Build (or
adapt) an obfuscation layer — encoding, paraphrase, indirection — and
re-run your reference monitor and classifier against it, following the
adaptive-evaluation methodology from the June 2026 stress-test paper.
Report your monitor's block rate against both the standard and the
obfuscated attack sets side by side.

**[NEW]** Add two attack classes specific to the new MCP spec's actual
surface, scoped conservatively (2–3 test cases each, not a full suite —
these are new enough that no mature benchmark covers them yet):

- **Hit-and-run task abuse:** issue a burst of cheap `tasks/call` handles
  (from the new async Tasks extension) designed to be expensive
  server-side. Check whether your capability policy has — or is missing
  — a resource-quota dimension to catch this. If it's missing, report
  that honestly as a found gap; that's a legitimate, interesting result,
  not a failure.
- **Header-leakage check:** verify no value your interpreter classifies
  as sensitive ever gets serialized into the new `Mcp-Method`/`Mcp-Name`
  HTTP headers, which are visible to every proxy and load balancer in the
  request path — a leakage vector that didn't exist under the old
  session-based transport model.

### 6. Incident Response Report Generator
Unchanged from the MVP: auto-drafted root cause, affected agents/tools/
data, and blast radius — now sourced from all three layers (monitor,
static analysis, classifier) instead of just the classifier.

### 7. [NEW] Dual-Benchmark Evaluation
Run the reference monitor against **both** the standard AgentDojo
benchmark (as originally planned) and **AgentDyn**
(`github.com/leolee99/AgentDyn` — public, drop-in-compatible with
AgentDojo's own evaluation script and model list, ships CaMeL and Progent
support already, which gives your CaMeL-lineage monitor a direct,
low-friction comparison path). Report both numbers side by side with a
short explanation: AgentDojo is the standard, citable, comparable number;
AgentDyn is included because several 2026 papers report AgentDojo's
undefended attack success rate is now near-zero on frontier models, which
makes a "near-elimination of attacks" claim against it alone less
informative than it used to be.

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
        [NEW] hit-and-run task abuse + header-leakage checks,
        run against the whole pipeline periodically)
                               |
                               v
        [NEW] Dual-Benchmark Eval: AgentDojo (standard) +
              AgentDyn (harder, current) reported side by side

  (separate, pre-deployment)
  Static Taint Analysis of tool-integration code -> flags
  P2Xi vulnerabilities before the agent ever runs
```

## Tech Stack

| Component | Choice | Why |
|---|---|---|
| Reference monitor | Custom interpreter (Python), capability-based policy **[UPDATED]** built on RFC 8707 Resource Indicators | Inherits confused-deputy protection from the standard instead of reinventing it — a net time-saver vs. v1's fully custom scheme |
| Dual-LLM orchestration | Claude via Anthropic API for both roles, strict context isolation | Privileged/Quarantined separation must be enforced at the code level, not by prompting alone |
| Static analysis | Custom taint tracker over your agent's tool-integration code, or adapt TaintP2X's published approach | Design-time complement to runtime enforcement |
| Trace/collector | Shared with AgentReflex's SDK | No duplicated infrastructure |
| Eval | **[UPDATED]** AgentDojo (standard) + AgentDyn (harder, current) + a self-built obfuscation layer | Standard, citable numbers; a harder, more current benchmark; and your own adaptive stress test |
| Protocol target | **[NEW]** MCP spec 2026-07-28 (RC as of writing, final July 28, 2026) | Build window overlaps the final release — no cost to targeting it directly instead of the outgoing spec |
| Dashboard | Same stack as AgentReflex | Shared UI investment |

## Implementation Plan

**Week 1 — Reference monitor core, spec-locked [UPDATED]:** read the MCP
2026-07-28 RC's authorization section (OAuth 2.1/OIDC, RFC 9728 Protected
Resource Metadata, RFC 8707 Resource Indicators) before writing any policy
code. Implement the Privileged/Quarantined LLM split with true code-level
isolation (the quarantined model must have zero tool-calling capability,
not just an instruction not to use tools). Design the interpreter's
capability-policy enforcement point on top of RFC 8707 rather than as a
separate scheme, and design for the new stateless protocol model.

**Week 2 — Reference monitor completion:** finish the interpreter's
capability-policy enforcement point; validate provenance tracking against
hand-constructed confused-deputy scenarios.

**Week 3 — Static taint analysis:** build the taint tracker for your
target agent framework's tool-integration code; validate against a small
set of intentionally vulnerable and intentionally safe examples you
construct yourself.

**Week 4 — Classifier + replay/DAG:** port the MVP's classifier to run as
the forensics layer; session replay timeline; multi-agent attack DAG.

**Week 5 — Dual-benchmark evaluation [UPDATED]:** run the reference
monitor against AgentDojo (standard); clone `leolee99/AgentDyn` and run
its drop-in-compatible harness against the same model list; report block
rate by domain for both, side by side, with the "why both" framing.
Budget +2–3 days versus v1 for the AgentDyn integration — largely absorbed
by its compatibility with AgentDojo's existing script.

**Week 6 — Adaptive attack harness [UPDATED]:** build the obfuscation
layer (encoding, paraphrase, indirection); add the 2–3 hit-and-run
task-abuse test cases and the header-leakage check; re-run the full
pipeline; report the delta between standard and obfuscated block rates,
honestly, and note the RC-vs-final-spec caveat explicitly.

**Weeks 7–8 — Incident reports, polish, demo:** report generator wired to
all three layers; a scripted live demo showing an attack blocked at the
monitor, one caught only by the classifier, and — if you find one — one
that gets through the obfuscation layer, which is exactly the kind of
honest gap analysis that reads as sophisticated rather than a shortfall.

**Week 9 (buffer) [NEW]:** absorbs any spillover from the AgentDyn
integration or MCP-spec-specific test cases; if unused, treat as
polish/documentation time. This week only exists because the plan is
now 8–9 weeks instead of 7–8 — use it as slack, not as required scope.

## Interview Narrative

"Classifying prompt injection after the fact is what most vendors do, and
it's known to be defeatable by adaptive attackers. I built the
architecture the field actually converged on instead: a dual-LLM reference
monitor in the lineage of CaMeL and FIDES that enforces a deterministic
capability policy before every tool call, regardless of what the model was
talked into — built against MCP's July 2026 spec revision rather than the
outgoing one, with provenance tracking on top of the new RFC 8707 resource
indicators instead of a bespoke scheme. I tested it against both the
standard AgentDojo benchmark and the harder AgentDyn benchmark, since
AgentDojo's undefended attack success rate is reportedly near zero on
frontier models now — plus my own obfuscated-attack harness including two
attack classes specific to MCP's new async task model. I can show you
exactly where it holds and where it still doesn't."

## Recruiter Signal

| What it proves | Why it matters |
|---|---|
| Systems security thinking, not just ML | Reference monitors and capability policies are classical security engineering applied to a new substrate |
| Awareness of adaptive-attacker methodology | You test against attacks designed to defeat your specific defense, not just the standard benchmark |
| Static + dynamic analysis together | Design-time and runtime security are different skills; showing both is rare |
| Honest gap reporting | Naming exactly where your system fails is stronger signal than claiming it doesn't |
| **[NEW]** Currency with a live protocol change | Built against a spec revision that finalized during your own build window, not a stale snapshot |
| **[NEW]** Benchmark literacy | Recognized that the standard benchmark may be saturating and added a harder one, rather than reporting an inflated number uncritically |

## Explicitly Not Doing (and why)

- **Reimplementing PI-Hunter** (arXiv:2606.12737) as a full comparison
  system. No confirmed public reference implementation found. Its
  "localize where in the pipeline the injection succeeded" design is
  already reflected in this plan's Feature 4 (annotating which layer
  caught/missed each step) — that's the useful idea, taken as design
  inspiration rather than something to reproduce exactly.
- **A comprehensive hit-and-run/header-leakage attack suite.** 2–3
  well-chosen test cases per class demonstrate the point; building out a
  full suite against a still-RC spec is weeks of work for marginal
  additional signal, and some details may still change before the July 28
  final release.

## Sources

- CaMeL, FIDES, Progent, RTBAS, Conseca, FORGE — the out-of-band,
  reference-monitor family this architecture is built in the lineage of
- "Adaptive Evaluation of Out-of-Band Defenses Against Prompt Injection in
  LLM Agents" (arXiv:2606.26479, June 2026) — the adaptive-attacker
  stress-test methodology; also the source of the Biba integrity /
  reference monitoring / least privilege reframing
- **[NEW]** "AgentDyn: A Dynamic Open-Ended Benchmark for Evaluating
  Prompt Injection Attacks of Real-World Agent Security System"
  (arXiv:2602.03117) — `github.com/leolee99/AgentDyn`; drop-in extension
  of AgentDojo's harness with dynamic/open-ended tasks and helpful
  instructions mixed into untrusted content
- TaintP2X (ICSE 2026) — static taint analysis for Prompt-to-Anything
  Injection vulnerabilities
- AgentDojo (Debenedetti et al.) — the standard dynamic evaluation
  benchmark for prompt injection in tool-using agents
- "Open Challenges in Multi-Agent Security" (arXiv:2505.02077) — broader
  survey, includes CaMeL as a case study
- **[NEW]** MCP Specification 2026-07-28 (release candidate shipped
  May 21, 2026; final release July 28, 2026) — OAuth 2.1/OIDC
  authorization, RFC 9728 Protected Resource Metadata, RFC 8707 Resource
  Indicators, stateless protocol model
- **[NEW]** RFC 8707 (Resource Indicators for OAuth 2.0) and RFC 9728
  (OAuth 2.0 Protected Resource Metadata)
- **[NEW]** NSA CSI_MCP_SECURITY (PP-26-1834, May 2026) — data-
  classification zoning, unverified task propagation between MCP servers,
  session-hijacking risk from token passthrough
- **[NEW]** arXiv:2606.12737 — PI-Hunter: automated red-teaming that
  exposes and localizes prompt injections, evaluated against AgentDojo and
  AgentDyn (cited as design inspiration, not implemented)
- OWASP LLM Top 10 (LLM01: prompt injection) and NIST AI 600-1 Generative
  AI Profile — regulatory/standards framing
