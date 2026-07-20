# Architecture Decision Record — Agentic SOC Co-Pilot

Status: **Accepted** — Day 7 (Architecture Design)
Derived from: `research/synthesis/architecture_justification.md` (Day 5 synthesis)

This file is the canonical, locked-in version of the 6 component decisions. The synthesis file in `research/` captures the reasoning as it was built up during the reading phase; this file is what the diagram in `figures/system_architecture_v1.png` and the SotA note's Section 4 both cite. If a decision changes after this point, add a new dated entry below rather than editing the original — keep the history visible.

---

## ADR-1: Orchestration Framework

**Decision:** LangGraph
**Alternative considered:** Plain LangChain sequential chain

**Context:** The agent needs conditional routing (e.g., benign alert → terminate; malicious → continue investigation) and persistent state across a multi-step investigation, not a fixed linear sequence of calls.

**Rationale:** LanG (arXiv:2604.05440) demonstrates a working five-node `StateGraph` with `interrupt()`-based human-in-the-loop gates in production-adjacent code. A linear LangChain chain has no native mechanism for conditional branching or pausing mid-execution for analyst approval — both are hard requirements here, not optional features.

**Consequences:** Every node must read/write a shared `SOCAgentState` (see `state_schema.md`). Adds implementation complexity relative to a simple chain, but is the only option that supports the two mandatory HIL gates.

---

## ADR-2: Inference Serving Engine

**Decision:** vLLM
**Alternative considered:** Ollama

**Context:** The agent makes an estimated 5–10 tool calls per investigation. Latency compounds across a single investigation's tool-call chain, so the serving engine's throughput directly determines whether an investigation completes in a useful timeframe.

**Rationale:** LanG's own deployment uses Ollama and is explicitly scoped as single-node/local. vLLM's PagedAttention architecture is designed for exactly this kind of high-throughput, many-small-requests workload, which Ollama does not target.

**Consequences:** Slightly higher setup complexity (vLLM server + OpenAI-compatible endpoint) versus Ollama's simpler CLI, but necessary for the tool-call volume this project's agent generates per investigation.

---

## ADR-3: Asset / Blast-Radius Store

**Decision:** Neo4j
**Alternative considered:** Relational store modeled on LanG's UICR schema

**Context:** The agent needs to answer "what can this attacker reach from the compromised host within N hops" during an active investigation — a variable-depth graph-traversal query.

**Rationale:** This is the single most literature-grounded decision in the project. Two independent sources converge on the same gap: LanG's own stated limitation is the absence of an asset graph (correlation happens over a flat UICR table); OCR-APT's central empirical finding is that graph representation, not flat log tables, is what makes causal root-cause reasoning tractable. Neo4j's Cypher `MATCH ... *1..3` variable-depth path queries answer the blast-radius question directly; a relational join-based equivalent does not scale the same way.

**Consequences:** Introduces a second database (alongside OpenSearch) and a new query language (Cypher) the team must learn before Week 4. This cost is accepted because it is the project's primary literature-identified contribution (Gap 1 in `gaps_and_contribution.md`).

---

## ADR-4: Log / Search Tool

**Decision:** OpenSearch
**Alternative considered:** No dedicated search tool — rely on LLM's own context window

**Context:** RAM's ablation study (arXiv:2502.02337) found that enriching a rule/alert description with external context about its indicators of compromise raised AP from 0.39 to 0.52 and AR from 0.54 to 0.75 — the single largest gain in their entire ablation.

**Rationale:** RAM's own contextual-enrichment step uses live web search, which is inappropriate inside a closed enterprise SOC. OpenSearch, indexed over the organization's own log corpus, is the internal substitute that plays the same role: giving the agent a tool to retrieve supporting evidence rather than reasoning from the raw alert text alone.

**Consequences:** Requires an ingestion pipeline for BOTS v3/Mordor into OpenSearch before the tagger node can be evaluated (Week 1–2 lab setup, `lab/ingest_bots.py`).

---

## ADR-5: Past-Incident Retrieval

**Decision:** Qdrant vector store
**Alternative considered:** No retrieval — rely on the LLM's parametric knowledge only

**Context:** The MDPI/JCP survey (5(4):95) identifies hallucinated or fabricated tool arguments as the field's most commonly reported failure mode across the 105 systems it reviews, and identifies RAG as the leading mitigation strategy.

**Rationale:** OCR-APT's own report-generation pipeline depends on a vector store (indexed serialized subgraphs) to ground each stage of report generation in retrieved, validated context rather than free generation — directly analogous to retrieving similar past incidents here.

**Consequences:** Requires an embedding model and a population step (past resolved incidents, once any exist) before this component adds value; until then it is a stub with no data.

---

## ADR-6: ATT&CK Tagging Method

**Decision:** RAM's 6-step prompt-chaining pipeline
**Alternative considered:** Direct single-prompt LLM classification

**Context:** Every investigation output must include grounded MITRE ATT&CK technique IDs, and the full technique/sub-technique space (~670 classes) does not fit usefully into a single classification prompt.

**Rationale:** RAM shows the full prompt-chained pipeline (IoC extraction → context retrieval → NL translation → data-source ID → technique proposal → CoT refinement) reaches AR 0.75/AP 0.52 with GPT-4-Turbo, versus AR 0.46/AP 0.31 for zero-shot single-prompt classification on the same dataset — nearly double the recall.

**Consequences:** `attack_tagger_node` becomes a multi-step sub-pipeline in its own right, not a single LLM call — adds latency per investigation but is directly justified by RAM's own ablation.

---

## Governance decisions (apply across every component above)

- **HIL placement:** only before high-impact/destructive tool calls (block IP, isolate host), never before read-only investigation steps — following Microsoft's disruption/reasoning-layer split and LanG's two-gate pattern.
- **Deterministic checks stay outside the LLM graph:** allow-lists, IP-reputation thresholds, and similar policy-bound rules are enforced *before* the agent reasons over an alert at all — implemented as a pre-filter, not as another LLM-callable tool, mirroring Microsoft's disruption layer.