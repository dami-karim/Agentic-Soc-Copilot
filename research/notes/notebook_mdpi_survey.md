# Notebook: AI-Augmented SOC — A Survey of LLMs and Agents for Security Automation

## Title & Source
"AI-Augmented SOC: A Survey of LLMs and Agents for Security Automation," Journal of Cybersecurity and Privacy, Vol. 5, No. 4, Article 95, published 5 November 2025 (peer-reviewed, open access, Systematic Review). Authors: Siddhant Srinivas, Brandon Kirk, Julissa Zendejas, Michael Espino, Matthew Boskovich, Abdul Bari, Khalil Dajani, Nabeel Alzahrani (California State University, San Bernardino).

## Problem Addressed
Traditional rule-based/manual SOC workflows cannot keep pace with threat volume, producing alert fatigue, delayed response, and high false-positive rates. Prior surveys of LLMs in cybersecurity are domain-specific (e.g., only threat intelligence, or only anomaly detection); no existing survey organizes the literature around the SOC's actual operational functions.

## Proposed Solution & Architecture
A PRISMA 2020-compliant, OSF-preregistered systematic review. From an initial pool of 600+ papers (2022–2025), 105 passed screening. Organizes findings into a taxonomy spanning **eight SOC functions**: log summarization, alert triage, threat intelligence, ticket handling, incident response, report generation, asset discovery/management, and vulnerability management. Introduces a **five-level Capability-Maturity Model** (0 Manual → 1 AI-Assisted → 2 Semi-Autonomous → 3 Conditionally Autonomous → 4 Fully Autonomous), positioned as an autonomy-dimension extension of SOC-CMM.

## Key Technologies Used
- No single system; representative tools per function: Microsoft Copilot for Security Guided Response and CyberAlly (alert triage), CyLens and CTINEXUS (threat intelligence), AGIR and GenDFIR (report generation), LLM-BSCVM (vulnerability management)
- Underlying LLMs referenced: GPT-3.5/4, Claude, Llama family
- Orchestration layers referenced: LangChain, AutoGen, MCP, Agent-to-Agent Protocol

## Evaluation: Dataset + Metrics + Results
No single dataset — a literature synthesis, and it explicitly flags resulting metric heterogeneity as a limitation. Representative figures: Microsoft Copilot for Security Guided Response macro-F1 0.87 on incident triage; CyberAlly cut false positives 70%→35%, MTTR 8h→90min; AGIR 0.993 recall / 1.000 precision (no hallucinations) on report generation; GenDFIR 97.51% overall accuracy on incident-timeline reconstruction.

## Strengths (What Works Well)
- First SOC-centered (not purely domain-specific) synthesis connecting eight operational functions under one taxonomy
- Five-level Capability-Maturity Model gives a reusable, citable vocabulary for autonomy level
- PRISMA-preregistered methodology (OSF DOI included) makes the review itself auditable

## Limitations & Weaknesses
- Self-reported "Threats to Validity": post-2022, English-language selection bias; most surveyed systems evaluated in simulated environments, not live SOC deployments
- No standardized benchmark across studies — metrics drawn from each paper's own setup, blocking apples-to-apples comparison
- Almost no empirical study of human-AI collaboration at scale in real-time operations; field characterized as a fast-aging "snapshot"

## Key Contributions (Novel Claims)
A unified eight-function SOC taxonomy plus a five-level, SOC-CMM-aligned Capability-Maturity Model; central empirical claim, synthesized across 105 studies: real-world deployments cluster overwhelmingly at Levels 1–2, with Level 4 remaining largely theoretical.

## Ideas I Will Reuse in My Project
- Adopt the five-level Capability-Maturity Model as the shared vocabulary for stating where this project's agent targets to sit (Level 2–3)
- Reuse the survey's failure-mode taxonomy (hallucinated tool arguments, black-box opacity, adversarial robustness) as the concrete requirements list for Week 6 guardrail design
- Cite the "Threats to Validity" finding — most reported metrics come from simulated environments — as justification for evaluating on open, labeled data (BOTS v3/Mordor)

## Open Questions After Reading
- Where would this project's finished agent land on the five-level maturity model?
- Does Microsoft's SOC 3 claim (Source 1) sit at odds with this survey's finding that real deployments cluster at Levels 1–2? Worth reconciling explicitly in the SotA note.

## Important Figures
Figure 1: PRISMA-style literature-selection flow (600+ → 510 → 105 papers). Figure 2: end-to-end AI-augmented SOC dataflow diagram. Figure 3: the five-level autonomy ladder — most directly reusable for this project's own maturity framing.

## Important Citations Within This Paper
Binbeshr et al., "The Rise of Cognitive SOCs" (IEEE Open J. Comput. Soc., 2025); Mohsin et al., "A Unified Framework for Human-AI Collaboration in SOCs with Trusted Autonomy" (arXiv:2505.23397) — directly relevant to this project's HIL design.

## Final Takeaway (One Sentence)
Across 105 studies, LLM/agent-augmented SOC tools consistently cut false positives and response time versus rule-based baselines, but almost all deployments sit at maturity Levels 1–2 and are evaluated on non-standardized, often simulated benchmarks — this project's contribution is to push toward Level 3 with a reproducible, open evaluation on labeled data.