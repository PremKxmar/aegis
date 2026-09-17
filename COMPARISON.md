# Is the Agent Governance Toolkit the best tool for this?

The question as posed — "is AGT the best agent governance tool" — is malformed,
and noticing that is more useful than any ranking. Agent governance is not one
product category. It is five, and they are not substitutes for each other.

Everything below about AGT specifically comes from building
[Aegis](README.md) on it, not from reading the marketing.

---

## The five layers

| Layer | The question it answers | Who is good at it |
|---|---|---|
| **Identity** | Which agent is this, and who is accountable for it? | Microsoft Entra Agent ID, Oasis, Astrix, Entro |
| **Runtime action validation** | **Is this specific action allowed, right now?** | **AGT**, Cerone, Zenity |
| **Model-boundary guardrails** | Is this prompt or output harmful? | Lakera, Prompt Security, NeMo Guardrails, Guardrails AI, LlamaFirewall |
| **Observability** | What did the fleet actually do? | Langfuse, Arize Phoenix, LangSmith, Datadog LLM |
| **GRC / compliance** | Can we prove any of this to an auditor? | Credo AI, OneTrust, Lumenova |

AGT owns row two. Asking whether it beats Lakera is like asking whether a door
lock beats a smoke alarm.

A useful way to see the distinction: in Aegis, **ATT-13 evades the guardrail
layer completely** — hostile intent, zero hostile keywords, our tuned detector
scores it 0.00 — and is still neutralised, because the capability, policy and
information-flow layers never consulted the text. Conversely, no amount of
runtime action validation tells you that an agent you forgot about has been
running in a forgotten subscription for six months. That is a discovery problem,
and AGT has no answer to it.

**You need several layers. The interesting question is which one you are missing.**

---

## Where AGT genuinely wins

**It is real enforcement, not advice.** A denied action is structurally
impossible rather than statistically unlikely. In Aegis the delegation layer
refuses to mint a capability the parent lacks — that is a `ValueError` from the
library, not a rule I could forget to write.

**MIT-licensed and fully self-hostable.** No control plane to phone home to, no
per-agent SaaS pricing, runs air-gapped. Zenity and Noma are cloud-oriented and
stop short of no-egress on-prem enforcement. For a bank, a defence contractor or
anyone with data-residency constraints, this is frequently the whole decision.

**Fast enough to be invisible.** Measured in this project: **65.6 µs mean,
92.8 µs p99** for a policy decision; **77 µs total** added per governed tool
call. Against a realistic 200 ms tool that is 0.04%. There is no performance
argument against turning it on.

**Framework-agnostic and multi-language.** Python, TypeScript, .NET, Go, Rust,
with adapters for LangChain, CrewAI, LangGraph, Semantic Kernel, OpenAI Agents
and MCP. Aegis uses none of those adapters — the governor talks to a plain
`ToolCall` — and that portability is the point.

**Genuinely broad primitive set.** Hash-chained tamper-evident audit with Merkle
inclusion proofs, SPIFFE/DID identity, privilege rings, MCP tool fingerprinting,
trust scoring, kill switches, saga orchestration, SRE error budgets. Assembling
this from separate vendors would be a year of integration.

**The MCP rug-pull detection is better than it sounds.** It is
content-independent: it does not care what a redefined tool description *says*,
only that the fingerprint changed. In testing, a description asking the agent to
read `~/.ssh/id_rsa` scored **zero** on the static pattern scan and **CRITICAL**
on the fingerprint comparison. Hashing beats filtering.

---

## Where AGT falls short

**1. You author every policy yourself, and the tooling to help you is broken.**

This is the documented trade-off, and it is the real cost. Worse, the shipped
safety net does not work: `agt lint-policy` reports *"No issues found"* on a
policy file with five defects, including one that crashes the runtime at load
time. Its action whitelist has drifted from the runtime's — they overlap on two
values out of six. The toolkit's own docs recommend that linter as a CI gate.

I wrote [`aegis-policylint`](aegis/policytool.py) because of this. It derives its
vocabulary from the live pydantic model, so it cannot drift.

**2. The policy condition language is weaker than it looks.**

No `not` operator — and `not x` does not error, it silently evaluates `False` in
both directions, so the rule never fires and nothing tells you. No arithmetic,
no set operations, no cross-call state. Every negative condition in Aegis is
pre-computed as a positive boolean in application code, which means real policy
logic leaks out of the YAML and into Python. That erodes the main benefit of
declarative policy.

**3. Silent failure is a recurring design pattern.**

Three of my four findings are silent failures: `scope: global` that scopes
nothing, `not` that never fires, detector config keys that fall back to defaults.
Each one leaves you *more* confident and *less* protected. For a security
product this is the wrong failure mode — these should be loud errors.

**4. Enforcement is in-process, not kernel-level.**

The policy engine shares a process with the agent it governs. The toolkit's own
threat model says so and recommends one container per agent, which is why Aegis
ships [`compose.yaml`](compose.yaml) that way. Worth knowing before you describe
it as a sandbox.

**5. No discovery, no posture management.**

AGT governs agents you have already wired it into. It cannot find shadow agents,
inventory what exists, or tell you which of your agents is over-permissioned.
Noma and Zenity do exactly this. For an enterprise rollout it is a real gap.

**6. Packaging is mid-migration.**

`agt doctor` reports "1/8 packages installed" on a complete `[full]` install
because it checks deprecated distribution names. `agent_mcp_governance` fails to
import outright — it references `agent_os.governance`, which does not exist in
4.1.0. Public preview is public preview.

---

## What I would actually recommend

**Microsoft-aligned enterprise, regulated, on-prem or air-gapped:**
AGT for runtime enforcement + Entra Agent ID for identity + OpenTelemetry into
whatever you already run. AGT's self-hostability and licence are decisive here
and nothing else in the open-source world is close.

**Fast-moving startup, cloud-native, small team:**
Probably not AGT first. The policy-authoring burden is real and the tooling gap
is real. A managed guardrail (Lakera) plus Langfuse gets you 70% of the risk
reduction for a fraction of the effort. Add AGT when an agent starts touching
money or PII — which is exactly the Aegis scenario.

**Large enterprise that does not know what agents it has:**
Start with discovery and posture — Noma or Zenity — because you cannot govern an
inventory you do not have. Layer AGT underneath for the agents that matter.

**Anyone choosing today:** AGT is the strongest *open-source* runtime action
governance layer available, and it legitimised the category. It is not a
complete governance programme, it is one layer of five, and its policy-authoring
story needs work before it is comfortable in CI.

---

## Evidence

Everything asserted about AGT here is reproducible:

```bash
make findings   # the four bugs, re-verified live against the installed package
make test       # 38 tests, 7 of which are regressions against the toolkit itself
make bench      # the latency numbers
make lint-compare   # agt lint-policy vs aegis-policylint on a 5-defect file
```

Tested against `agent-governance-toolkit` **4.1.0**, September 2026. If a later
release fixes any of these, `tests/test_toolkit_findings.py` fails and the
relevant claim above should be withdrawn.
