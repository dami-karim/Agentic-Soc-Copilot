# MITRE ATT&CK — Structure Notes

## What is MITRE ATT&CK?
A publicly maintained, community-curated knowledge base of adversary tactics, techniques, and procedures (TTPs), based on real-world observed attacker behavior. It gives defenders a shared vocabulary: instead of describing an attack in free text, you describe it in ATT&CK technique IDs, which are precise, comparable across organizations, and mappable to detections/mitigations.

## The three-level hierarchy
- **Tactic** — the adversary's *goal* at a given stage (the "why"). There are 14 Enterprise tactics, e.g., Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact. Each has a `TAxxxx` ID.
- **Technique** — the *method* used to achieve that goal (the "how"). Each has a `Txxxx` ID, e.g., T1110 (Brute Force), T1059 (Command and Scripting Interpreter), T1021 (Remote Services / Lateral Movement), T1566 (Phishing), T1547 (Boot or Logon Autostart Execution).
- **Sub-technique** — a more specific variant of a technique. Each has a `Txxxx.yyy` ID, e.g., T1110.001 (Password Guessing), T1110.003 (Password Spraying).

## Worked example: mapping the Day 1 alert
The failed-logon alert (EventCode 4625, repeated attempts) maps as:
- **Tactic:** TA0006 — Credential Access
- **Technique:** T1110 — Brute Force
- **Sub-technique:** T1110.001 — Password Guessing (repeated single-account attempts) *or* T1110.003 — Password Spraying (many accounts, few attempts each) depending on the pattern observed across accounts

**Why this mapping and not another:** the technique is determined by *what the attacker is trying to do to authentication* (guess/spray a password), not by the specific log source. The distinction between .001 and .003 requires looking across multiple accounts/hosts, not just a single alert — which is why correlation (not single-event analysis) is necessary for accurate sub-technique assignment.

## Why automated ATT&CK mapping is not trivial
Even though the taxonomy is well-defined, mapping a specific log event or detection rule to the correct technique is hard for three reasons: (1) a single event can be consistent with several techniques until correlated with other events; (2) sub-technique disambiguation often requires context the raw log doesn't contain (e.g., how many accounts were targeted); (3) the technique space is large (~670 technique/sub-technique classes), so naive classification approaches either oversimplify (map to only a handful of top-level tactics) or require expensive supervised training that goes stale as new techniques are added. This is exactly the problem RAM (`research/notes/notebook_ram.md`) is built to solve via retrieval-augmented prompting instead of classification.

## Data sources and Navigator
- `attack.mitre.org` — browsable matrix, one page per technique with a Detection section (what log/telemetry reveals this technique) and a Data Sources section.
- `mitre-attack.github.io/attack-navigator` — a tool to build and export custom "layers" (e.g., highlight the 5 techniques studied this week) as an image, useful for both study and for the architecture diagram.
- `github.com/mitre-attack/attack-stix-data` — the machine-readable `enterprise-attack.json`, structured as STIX objects; this is what a programmatic mapper (like RAM, or this project's `attack_tagger_node`) queries against instead of scraping the website.