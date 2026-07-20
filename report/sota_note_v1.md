# State-of-the-Art Note
### Agentic SOC Co-Pilot — Positioning the Project Against the Current Frontier
*DeepShift AI · Summer 2026 Internship · Weeks 1–2 Deliverable · Draft v1*

---

## 1. Problem Statement

Security operations centers (SOCs) face a structural asymmetry: an attacker only needs one successful action, while defenders are judged on every miss. Industry-reported figures place average breach identification at roughly 200 days and containment at a further 70+ days once identified, and SOC analysts report that the large majority of daily alerts are false positives, producing chronic alert fatigue and high analyst turnover. Traditional SIEM/EDR/XDR tooling reduces noise and improves visibility but still requires a human to read, correlate, and act on each alert before response can begin — a bottleneck that has not scaled with alert volume.

"Agentic" and "automated" are not synonyms, and the distinction matters for this project's scope. Automation follows a fixed, rule-based script (a SOAR playbook, a Snort signature) that halts and escalates the moment it encounters a scenario outside its predefined pattern. An agentic system plans dynamically: it selects among tools, reasons over retrieved evidence, and adapts its next action to what it has just observed, while remaining bounded by governance controls and mandatory human approval before high-impact actions.

This project's scope is Tier-1/Tier-2 alert triage and investigation automation — not detection (which remains the SIEM's job) and not full incident response execution (which remains gated behind analyst approval). The objective, stated in one sentence: build an open-stack, reproducible LangGraph agent that ingests a raw SIEM alert, investigates it using the same tools and reasoning pattern a Tier-1/2 analyst would use, tags it with MITRE ATT&CK techniques, and produces a graph-grounded root-cause analysis — evaluated on open, labeled datasets rather than proprietary production telemetry.

## 2. Product Landscape

Microsoft's April 2026 *"The agentic SOC"* blog post is the clearest public statement of where production agentic SOCs are heading, and it is the framing this note opens with because it demonstrates the target end-state is real, not speculative. Microsoft describes a two-layer model: a deterministic, policy-bound *disruption layer* that contains high-confidence threats automatically in real time, and an *operational layer* of AI agents that reason over evidence and coordinate investigation, with humans supervising rather than performing first-pass triage. Microsoft reports that internal task agents already automate 75% of phishing and malware investigations, and that automatic attack disruption contains threats at a 99.99% confidence rating in an average of three minutes.

Splunk, Cisco, and CrowdStrike make structurally similar claims in the same period — specialized agents embedded into existing SIEM/XDR platforms handling enrichment, prioritization, and initial response under analyst supervision. What none of these production systems disclose is implementation detail: no state schema, no guardrail specification, no reproducible benchmark. This is the gap an open-stack academic project can fill — not by matching Microsoft's scale, but by making the architecture, evaluation, and design rationale fully inspectable and reproducible on open datasets.

## 3. Research Landscape

### 3.1 LanG: An Open, Governed Blueprint

LanG (Abdennebi et al., arXiv:2604.05440, April 2026) is the closest published open system to this project's target architecture. It proposes a five-node LangGraph pipeline — Ingest/Detect → Classify → Human Review 1 → Analyze Logs → Propose Rules → Human Review 2 → Deploy — built on a four-layer Security → Agentic AI → MCP → Governance stack, with every tool call passing through a two-layer guardrail pipeline (regex pre-filter plus a semantic classifier). Its correlation engine reaches F1 = 87% on a Unified Incident Context Record schema, and its multi-format detection-rule generator achieves 96.2% acceptance across four fine-tuned base models. LanG's own state-management pattern — a WorkflowState with a phase enum, accumulated per-node results, and a full decision audit trail — is a direct model for this project's own agent-state schema (see `architecture/state_schema.md`).

**[Figure 1 — 5-node LangGraph pipeline, redrawn from LanG Fig. 2, with HIL gate placement annotated]**

LanG's own limitation is architectural, not incidental: its correlation and reconstruction logic operates over a flat, relational UICR store rather than a queryable entity graph, so a question such as "what can this attacker reach next" cannot be answered directly — it has to be inferred from correlation heuristics rather than graph traversal. That is precisely the gap this project's Neo4j-backed blast-radius layer is designed to close.

### 3.2 Provenance Reasoning for Root-Cause Analysis: OCR-APT

A provenance graph represents system activity as a directed graph — processes, files, and network sockets as nodes; reads, writes, and connections as causally-ordered edges — which lets an investigator trace *why* an event happened, not just that it happened. OCR-APT (Aly, Mansour & Youssef, arXiv:2510.15188; ACM CCS 2025) is the strongest recent demonstration of why this representation matters for root-cause analysis. Its GNN-based detector (OCRGCN) learns normal behavior from structural and behavioral graph features — deliberately excluding brittle attributes such as file paths and IP addresses that attackers can trivially alter — and reaches an average F1 of 0.96 across the DARPA TC3, DARPA OpTC, and NODLINK benchmarks, ahead of the strongest prior subgraph-level baseline (FLASH, F1 = 0.945).

OCR-APT's second contribution is arguably more transferable than its detector: a six-stage, validated LLM report-generation pipeline that decomposes attack-story writing into IOC extraction, per-subgraph narration, merging, and a final LLM-as-judge enrichment pass — a design the authors report "fully mitigates" the hallucinations their earlier, single-prompt approach produced. This project adopts that same decomposition principle for its RCA Generator node, and treats OCR-APT's finding — that graph representation is what makes root-cause reasoning tractable — as the primary literature-grounded justification for choosing Neo4j over a relational store for the asset/blast-radius layer.

**[Figure 2 — example provenance graph: brute-force logon → successful auth → lateral movement → file access, with node/edge types labeled]**

### 3.3 ATT&CK Grounding: RAM

Every investigation this project's agent produces must ground its findings in MITRE ATT&CK technique IDs, and RAM (Wudali et al., arXiv:2502.02337, Feb. 2025) is the direct implementation reference for that step. RAM frames ATT&CK mapping as a retrieval-augmented, prompt-chained task rather than a classification problem: extract indicators of compromise from the input, retrieve external context about them, translate the input into natural language, retrieve relevant ATT&CK data components via agentic RAG, propose candidate techniques, then refine the candidate list with chain-of-thought comparison and confidence scoring. On the Splunk Security Content dataset (360 endpoint-domain rules), RAM's best configuration reaches an average recall of 0.75 and average precision of 0.52 with GPT-4-Turbo, beating a fine-tuned BERT classifier (0.68/0.39) and a zero-shot LLM baseline (0.46/0.31).

The paper's ablation study is the most operationally important finding for this project: moving from a bare rule description to a rule description enriched with external contextual information about its indicators of compromise raised recall from 0.46 to 0.75 and precision from 0.39 to 0.52 — a larger jump than natural-language translation alone provided. This project's `attack_tagger_node` design follows directly from that result: it must have tool access (log search, internal threat-intel lookup) rather than relying on prompt engineering over the raw alert text, and RAM's confidence-threshold (dynamic-k) filtering is adopted as the mechanism for balancing precision and recall in Week 7's evaluation.

### 3.4 Field Survey: AI-Augmented SOC (MDPI/JCP)

Srinivas et al. (Journal of Cybersecurity and Privacy, 5(4):95, 2025) provide the peer-reviewed literature backbone for this note. Their PRISMA-2020, OSF-preregistered review screens 105 papers (from an initial pool of 600+, 2022–2025) across eight SOC functions and introduces a five-level Capability-Maturity Model (Manual → AI-Assisted → Semi-Autonomous → Conditionally Autonomous → Fully Autonomous), positioned as an autonomy-dimension extension of the established SOC-CMM framework. Three findings from the survey are load-bearing for this project's design: (1) across the surveyed systems, hallucinated or fabricated tool arguments are repeatedly identified as the primary reliability failure mode, motivating the guardrail work planned for Week 6; (2) retrieval-augmented generation and explainable-AI techniques are the field's leading mitigation strategy for that failure mode, consistent with both OCR-APT's and RAM's own designs; (3) despite vendor claims of full autonomy, the survey's own synthesis finds that real deployments overwhelmingly cluster at Levels 1–2 (assisted / semi-autonomous) — a finding worth holding in tension against Microsoft's SOC 3 ("fully agentic") framing in Section 2 of this note.

**[Figure 3 — 6-system × 7-attribute comparison table: Microsoft SecCopilot, LanG, OCR-APT, RAM, this project, across tool-calling / HIL placement / ATT&CK grounding / provenance reasoning / dataset / open-source — see `research/synthesis/comparison_table.md`]**

## 4. Architecture Decisions

Every component of the proposed stack traces to a specific finding above; the full rationale for each is in `architecture/decisions.md`. Summary:

| Component | Chosen / Alternative | Reason |
|---|---|---|
| Orchestration | LangGraph (vs. LangChain chain) | LanG's five-node StateGraph with `interrupt()` gates is the working reference for the conditional routing this project needs. |
| Inference serving | vLLM (vs. Ollama) | LanG's Ollama deployment is single-node/local; a triage agent's 5–10 tool calls per investigation need vLLM-class throughput. |
| Asset / blast-radius store | Neo4j (vs. relational UICR-style store) | LanG's stated limitation (no asset graph) plus OCR-APT's finding (graph representation enables causal reasoning) both point here. |
| Log/search tool | OpenSearch | RAM's ablation shows contextual enrichment is the single largest driver of ATT&CK-mapping accuracy. |
| Past-incident retrieval | Qdrant | MDPI survey identifies RAG as the leading mitigation for hallucinated outputs; OCR-APT's pipeline depends on the same pattern. |
| ATT&CK tagging | RAM's 6-step prompt-chaining pipeline (vs. direct classification) | RAM shows this beats zero-shot classification (AR 0.75 vs. 0.46). |

Two governance decisions are held constant across every component, following the Microsoft and LanG pattern directly: HIL checkpoints are placed only before high-impact/destructive tool calls, never before read-only investigation steps; and any deterministic, policy-bound check is kept outside the LLM reasoning graph entirely, mirroring Microsoft's disruption-layer / reasoning-layer separation.

## 5. Identified Gaps & Contribution

Three gaps recur across the five sources above, and none of them is addressed by any single existing system (full detail in `research/synthesis/gaps_and_contribution.md`):

- **Gap 1** — No published open system combines live asset-graph reasoning with agentic investigation. LanG has the agentic pipeline but no asset graph; commercial systems may have both but disclose neither. *This project's contribution:* a Neo4j blast-radius layer wired directly into the LangGraph ReAct loop, evaluated openly.
- **Gap 2** — No open-stack benchmark for tool-argument validation / hallucination rate in a SOC-agent context. The MDPI survey identifies the failure mode but no standardized benchmark exists; OCR-APT's mitigation is validated only within its own narrow task. *This project's contribution:* a guardrail evaluation measured directly against BOTS v3 ground truth.
- **Gap 3** — No evaluation on fully open, labeled datasets with joint ATT&CK precision/recall and MTTR-style timing. RAM, OCR-APT, and Microsoft each evaluate a different slice in isolation, and none is fully reproducible. *This project's contribution:* a single, joint evaluation on BOTS v3 and Mordor.

## 6. Evaluation Plan

Three metrics, each directly traceable to the literature above: (1) **ATT&CK technique F1**, computed the same way as RAM's AR/AP metrics, against BOTS v3's ground-truth technique labels; (2) **simulated Mean Time to Respond**, framed against the qualitative speed claims in Microsoft's agentic SOC post (not as a direct comparison — Microsoft's figures are production-scale and undisclosed in method — but as the same class of metric, computed reproducibly here); (3) **False Execution Rate**, measuring how often the agent would have taken a destructive action without appropriate HIL confirmation, directly operationalizing the guardrail-failure-mode concern raised in the MDPI survey. Datasets: BOTS v3 (primary) and Mordor (secondary, for additional attack-technique coverage). Baseline: a simple rule-based triage script, to make the marginal value of the agentic approach measurable rather than assumed.

## References

See `references.bib` for full citation records.

1. Abdennebi, A., Kara, N., Lahlou, L., & Ould-Slimane, H. (2026). LanG — A Governance-Aware Agentic AI Platform for Unified Security Operations. arXiv:2604.05440v1 [cs.CR].
2. Aly, A., Mansour, E., & Youssef, A. (2025). OCR-APT: Reconstructing APT Stories from Audit Logs using Subgraph Anomaly Detection and LLMs. arXiv:2510.15188v2 [cs.CR]. Extended version of the paper accepted at ACM CCS 2025.
3. IBM. (2025). Cost of a Data Breach Report 2025.
4. Lefferts, R., & Weston, D. (2026, April 9). The agentic SOC—Rethinking SecOps for the next decade. Microsoft Security Blog.
5. Srinivas, S., Kirk, B., Zendejas, J., Espino, M., Boskovich, M., Bari, A., Dajani, K., & Alzahrani, N. (2025). AI-Augmented SOC: A Survey of LLMs and Agents for Security Automation. Journal of Cybersecurity and Privacy, 5(4), 95.
6. Wudali, P. N., Kravchik, M., Malul, E., Gandhi, P. A., Elovici, Y., & Shabtai, A. (2025). Rule-ATT&CK Mapper (RAM): Mapping SIEM Rules to TTPs Using LLMs. arXiv:2502.02337 [cs.CR].