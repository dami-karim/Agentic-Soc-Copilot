# BOTS v3 — Sample Alert Annotation

**Source:** Boss of the SOC v3 dataset (Splunk), `github.com/splunk/botsv3`. A publicly released, labeled dataset simulating a realistic enterprise compromise, built specifically for SOC training and detection-engineering practice — used here as one of the two ground-truth evaluation datasets (alongside Mordor) for this project's Week 7 metrics.

> **Note:** the exact field names/values below are illustrative of the Windows Security Event Log schema BOTS v3 uses (via Splunk's Common Information Model). Replace with the literal JSON from your downloaded sample once you've pulled a real event — do not treat the values below as verified BOTS v3 output.

## Downloading a sample
```bash
git clone https://github.com/splunk/botsv3
# Look for Windows Security event log data, filter for EventCode=4625
```

## Annotated sample event (illustrative schema)
```json
{
  "_time": "2018-08-20T14:32:07",
  "host": "WIN-DC01",
  "EventCode": "4625",
  "src_ip": "10.0.2.15",
  "dest_ip": "10.0.2.5",
  "user": "administrator",
  "Logon_Type": "3",
  "sourcetype": "WinEventLog:Security",
  "signature": "An account failed to log on"
}
```

| Field | Meaning |
|---|---|
| `_time` | Timestamp of the event, in the SIEM's normalized time format |
| `host` | The system that generated the log — here, the domain controller being targeted |
| `EventCode` | Windows Security Event ID; 4625 = failed logon |
| `src_ip` | Origin of the logon attempt |
| `dest_ip` | Target host of the logon attempt |
| `user` | Account name the attempt was made against |
| `Logon_Type` | Windows logon type code — `3` = network logon (common for remote/lateral-movement attempts, as opposed to `2` = interactive/console) |
| `sourcetype` | Tells the SIEM which parser/CIM mapping to apply |
| `signature` | Human-readable description Splunk attaches to this EventCode |

## Tier-1 pivot sequence for this event
1. **Check `src_ip` reputation** — internal RFC1918 address here, so reputation lookup is less useful than checking whether this host is expected to authenticate against `WIN-DC01` at all.
2. **Check logon history** — is repeated 4625 from this `src_ip`/`user` pair new, or a known noisy service account?
3. **Check for a following successful logon (EventCode 4624)** from the same `src_ip` shortly after — the single strongest signal of a successful brute-force.
4. **Check for lateral movement** — new sessions originating from `WIN-DC01` (or from the attacking host) to other internal hosts shortly after a successful logon.

## ATT&CK mapping
- **Tactic:** TA0006 (Credential Access)
- **Technique:** T1110 (Brute Force)
- **Sub-technique:** depends on whether multiple accounts are targeted from the same source (→ T1110.003 Password Spraying) or one account repeatedly (→ T1110.001 Password Guessing) — requires correlating multiple events, not just this one.

## Why this trains the agent's intuition
This exact reasoning chain — reputation → history → correlation → lateral movement, then map to ATT&CK — is the sequence the agent's tool-calling loop (`log_search`, `ioc_lookup`, `attack_tagger_node`) needs to reproduce automatically. Annotating it by hand first is what makes it possible to judge, later, whether the agent's automated output actually matches sound analyst reasoning.