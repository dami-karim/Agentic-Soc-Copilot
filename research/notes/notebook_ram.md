# Notebook: RAM — Rule-ATT&CK Mapper

## Title & Source
"Rule-ATT&CK Mapper (RAM): Mapping SIEM Rules to TTPs Using LLMs," arXiv:2502.02337, submitted 4 February 2025. Authors: Prasanna N. Wudali, Ehud Malul, Parth A. Gandhi, Yuval Elovici, Asaf Shabtai (Ben-Gurion University of the Negev) and Moshe Kravchik (Rafael Advanced Defense Systems). Note: the mapping target is structured SIEM detection rules, not raw log observations directly — relevant to how this project's `attack_tagger_node` should be scoped.

## Problem Addressed
Mapping SIEM detection rules to MITRE ATT&CK techniques is manual, slow, and error-prone; supervised ML approaches need retraining whenever new techniques emerge and mostly target unstructured CTI text rather than structured rules. Structured rules carry limited surface information, making automated technique inference harder than for prose threat reports.

## Proposed Solution & Architecture
A six-step, two-phase prompt-chaining pipeline requiring no training data.
- **Phase 1 (rule → text):** (1) zero-shot IoC extraction from the rule; (2) a ReAct web-search agent retrieves contextual information for each IoC; (3) the rule plus context is translated into a natural-language description.
- **Phase 2 (technique recommendation):** (4) agentic-RAG over a ChromaDB vector store of MITRE data-source/mitigation descriptions identifies the relevant data component; (5) a ReAct agent proposes probable ATT&CK techniques (top-k=11, or confidence-threshold 0.8); (6) chain-of-thought rule-technique comparison scores and filters the candidates into final, explained labels.

## Key Technologies Used
- Hosted LLMs: GPT-4-Turbo, GPT-4o, GPT-4o-mini; local LLMs: Mistral-7B, IBM Granite-3.0-8B, Qwen-2.5-7B
- LangChain / LangGraph for hosted-model orchestration
- ChromaDB vector store for MITRE data-source/mitigation retrieval
- ReAct agent framework for web-search context retrieval and technique proposal

## Evaluation: Dataset + Metrics + Results
Splunk Security Content dataset, endpoint domain, 360 rules dated ≥ Nov 2024 (postdates model knowledge cutoffs, avoids leakage). Metrics: Average Recall (AR)/Weighted AR and Average Precision (AP)/Weighted AP. Best configuration (GPT-4-Turbo, dynamic-k): **AR 0.75 (WAR 0.724), AP 0.52 (WAP 0.51), F1 0.62** — beating zero-shot LLM (0.46/0.31), BERT (0.68/0.39), CodeBERT (0.65/0.47), TTPXHunter (0.59/0.42). Ablation: rule-as-is → 0.46/0.39; + NL translation → 0.54/0.42; + contextual enrichment → 0.75/0.52 — **contextual enrichment is the single biggest driver of improvement.**

## Strengths (What Works Well)
- Eliminates training-data dependency entirely — pure prompting, no fine-tuning
- Produces a natural-language chain-of-thought rationale for every mapped technique, unlike black-box classifiers
- Covers the full ~670-technique/sub-technique space rather than a simplified subset

## Limitations & Weaknesses
- Default reliance on hosted models sends rule/log content to an external API — a confidentiality risk for regulated environments
- Prompt chaining adds latency; local models (Mistral: AR 0.12) perform far worse due to smaller context windows
- Precision (0.52) trails recall (0.75) even in the best configuration; ground-truth labels found to be incomplete in places during error analysis

## Key Contributions (Novel Claims)
First framework (to the authors' knowledge) targeting structured SIEM rules rather than unstructured CTI text for full-technique-space ATT&CK mapping without training data; central ablation finding — injecting external contextual information about a rule's IoCs, not NL translation alone, drives the largest accuracy gains.

## Ideas I Will Reuse in My Project
- Adopt the full six-step prompt-chaining pipeline as the direct blueprint for `attack_tagger_node`
- Replicate AR/AP (and weighted variants) as the Week 7 evaluation metric against BOTS v3's ground-truth ATT&CK labels
- Give the tagger node access to internal `log_search` / threat-intel tools rather than relying on prompt engineering over raw alert text alone
- Use confidence-threshold (dynamic-k) filtering instead of fixed top-k

## Open Questions After Reading
- RAM's contextual-retrieval step uses live web search — inappropriate inside a closed enterprise SOC. This project needs an internal threat-intel/vector-DB lookup instead, which materially changes that step's design.
- How sensitive is the k/confidence-threshold tuning to a different, smaller ATT&CK technique subset relevant to this project's own scenarios?

## Important Figures
Figure 1: overview of the six-step AI-agent RAM pipeline. Figure 2: worked example (IoC extraction → context retrieval → recommendation) on a real Splunk rule (`soaphound.exe`). Table 3: comparative AR/AP results across all tested LLMs/baselines.

## Important Citations Within This Paper
Nir et al., "Labeling NIDS Rules with MITRE ATT&CK Techniques Using ChatGPT" (2023/2024) — closest prior structured-data baseline. Mărmureanu & Oprișa, "MITRE Tactics Inference from Splunk Queries" (2023) — BERT tactic-only classifier, useful for explaining why technique-level mapping is harder than tactic-level.

## Final Takeaway (One Sentence)
For structured-input ATT&CK mapping, injecting external contextual information about a rule's indicators of compromise is the single largest driver of accuracy — meaning `attack_tagger_node`'s design should prioritize giving the LLM tool access over prompt engineering alone.