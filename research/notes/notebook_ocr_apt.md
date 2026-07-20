# Notebook: OCR-APT — Reconstructing APT Stories from Audit Logs

## Title & Source
"OCR-APT: Reconstructing APT Stories from Audit Logs using Subgraph Anomaly Detection and LLMs," arXiv:2510.15188v2 [cs.CR], first submitted 16 October 2025. Authors: Ahmed Aly, Essam Mansour, Amr Youssef (Concordia University, Montreal). Extended version of the paper accepted at ACM CCS 2025 (peer-reviewed), DOI 10.1145/3719027.3765219.

## Problem Addressed
Existing provenance-graph anomaly detectors produce high false-positive rates and coarse-grained alerts, largely because they rely on brittle node attributes (file paths, IP addresses) that attackers can trivially alter without changing underlying behavior. Attack-story reconstruction tools typically require a pre-identified point-of-interest and output dense graphs or raw event sequences that are not narratively interpretable.

## Proposed Solution & Architecture
Two components:
1. **GNN-based subgraph anomaly detector**: audit logs become an RDF-based provenance graph, loaded incrementally into a graph database; a custom model, **OCRGCN** (relational graph convolutional networks per node type + one-class SVM hypersphere), learns normal behavior from action-frequency and idle-period statistics only — deliberately excluding file paths, IPs, and other attribute features. Anomalous nodes are grouped into bounded anomalous subgraphs via one-hop bidirectional traversal and Louvain partitioning.
2. **LLM-based attack investigator**: a six-stage, validated RAG pipeline that serializes each anomalous subgraph into a log document, extracts and cross-checks IOCs against the source subgraph, drafts a per-subgraph report, merges reports into one narrative, then uses an LLM-as-judge step to select the most critical IOCs and re-query the graph for extra context before final enrichment.

## Key Technologies Used
- Relational Graph Convolutional Networks (RGCN) + one-class SVM (OCRGCN)
- RDF-based provenance-graph database with disk-backed incremental ingestion
- Louvain community detection for subgraph partitioning
- text-embedding-3-large for vector-store indexing; LLM-as-a-judge for IOC prioritization
- Evaluated on DARPA TC3, DARPA OpTC, and simulated NODLINK (80M+ system events combined)

## Evaluation: Dataset + Metrics + Results
DARPA TC3 (CADETS/TRACE/THEIA hosts), DARPA OpTC (three Windows hosts), simulated NODLINK (Ubuntu/WS12/W10) — malicious nodes under 0.01% of all nodes, so F1 is the primary metric. OCR-APT achieves an **average F1 of 0.96**, versus 0.248 for NODLINK's own detector and 0.945 for FLASH, the next-best baseline. Generated reports were separately scored against ground-truth simulated-attack reports.

## Strengths (What Works Well)
- Avoiding brittle attribute features makes detection substantially more robust to adversarial evasion
- The validated, multi-stage RAG report pipeline measurably suppressed hallucination relative to the authors' own earlier monolithic single-prompt approach
- Incremental, query-based subgraph extraction scales to enterprise-size provenance data without loading the entire graph into memory

## Limitations & Weaknesses
- One-class training assumes access to attack-free (clean) baseline logs — a trusted-computing-base assumption that will not always hold
- Threat model explicitly excludes data-poisoning, hardware-level, and side-channel attacks
- F1 alone may understate real triage burden; multi-attack handling and cross-host generalization flagged as open problems in the authors' own discussion (Sec. 7.6)

## Key Contributions (Novel Claims)
An anomaly detector (OCRGCN) that captures structural/behavioral graph patterns rather than fragile node attributes, combined with a multi-stage, self-validating LLM investigation pipeline that "fully mitigates hallucinations observed in the earlier approach" — evaluated end-to-end on three realistic benchmarks, outperforming the strongest prior subgraph-level detectors.

## Ideas I Will Reuse in My Project
- Adopt OCR-APT's narrative RCA structure — summary, APT-stage breakdown, IOCs with context, minute-by-minute action log — as the output schema for this project's RCA Generator node
- Apply "decompose LLM report generation into validated sub-stages rather than one monolithic prompt" to any long-form agent output, not just RCA
- Use the paper's core insight — graph representation is what enables causal root-cause reasoning — as the primary justification for choosing Neo4j

## Open Questions After Reading
- How would OCRGCN's behavior-only features transfer to environments without full process-level host audit logs (e.g., cloud/SaaS telemetry vs. BOTS v3's Splunk-format data)?
- Is Louvain-based subgraph partitioning sensitive to its resolution parameter on a much smaller, noisier dataset than DARPA TC3/OpTC?

## Important Figures
Figure 1: overall architecture, provenance graph → OCRGCN → LLM report — clearest diagram to redraw for the SotA note. Figure 3: anomalous-subgraph construction stages. Figure 4: the six-stage LLM attack-investigator RAG pipeline.

## Important Citations Within This Paper
NODLINK (Li et al., 2024) and FLASH (Rehman et al., 2024) — closest prior subgraph-based baselines, worth reading directly if time allows. KAIROS (Cheng et al., 2024) — repeatedly cited comparable GNN-based provenance system.

## Final Takeaway (One Sentence)
Robust root-cause narration comes from (a) detecting anomalies on structural/behavioral graph features instead of brittle attributes, and (b) decomposing LLM report generation into validated sub-stages rather than one large prompt — both directly transferable design rules for this project's RCA pipeline.