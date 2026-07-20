# Identified Gaps & Contribution

Three gaps recur across the five sources, and none is addressed by any single existing system.

## Gap 1 — No published open system combines live asset-graph reasoning with agentic investigation
LanG has the agentic pipeline but no asset graph (flat UICR store only). Commercial systems (Microsoft, Splunk, CrowdStrike) may have both internally but disclose neither architecture nor evaluation. OCR-APT proves graph representation is what makes causal root-cause reasoning tractable, but its graph is a static provenance graph for post-hoc detection, not a live, queryable asset/blast-radius graph wired into an active investigation loop.

**This project's contribution:** a Neo4j blast-radius layer wired directly into the LangGraph ReAct loop, so the agent can answer "what can this attacker reach in ≤3 hops" *during* investigation, not just reconstruct it after the fact — evaluated openly rather than kept proprietary.

## Gap 2 — No open-stack benchmark for tool-argument validation / hallucination rate in a SOC-agent context
The MDPI survey identifies hallucinated tool arguments as the field's dominant failure mode across 105 surveyed systems, but reports no standardized benchmark for measuring it. OCR-APT's hallucination mitigation is validated only within its own narrow report-generation task (IOC cross-checking against source subgraphs), not against a general SOC-agent tool-calling benchmark.

**This project's contribution:** a guardrail evaluation (Week 6) measuring false tool-argument rate directly against BOTS v3 ground truth — a reproducible, open benchmark rather than a synthetic or proprietary one.

## Gap 3 — No evaluation on fully open, labeled datasets with joint ATT&CK precision/recall and MTTR-style timing
RAM evaluates ATT&CK mapping in isolation on Splunk rules (no timing metric). OCR-APT evaluates detection/reconstruction on DARPA/NODLINK (no ATT&CK-technique-level precision/recall). Microsoft reports production MTTR-class metrics with no released dataset at all, so nothing is independently reproducible.

**This project's contribution:** a single, joint evaluation on BOTS v3 (primary) and Mordor (secondary) covering ATT&CK F1, simulated MTTR, and false-execution rate together, against a rule-based triage baseline — so the marginal value of the agentic approach is measured, not assumed.

## One-paragraph synthesis (for SotA note Section 5)
Across product blogs, open research platforms, provenance-detection systems, ATT&CK-mapping frameworks, and a field-wide survey, the recurring pattern is that *pieces* of an ideal agentic SOC exist and are individually well-evaluated, but no open, reproducible system integrates live asset-graph reasoning, validated ATT&CK grounding, and a jointly-reported evaluation on public labeled data. This project's design is explicitly assembled to close exactly those three gaps, with every component choice traceable to a specific finding in the five sources above (see `architecture_justification.md`).