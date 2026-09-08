"""
Generate a synthetic batch of alerts for testing the false-positive filter.

Creates a realistic mix of benign noise (false positives) and genuine
threats (true positives), plus an aligned ground-truth labels file so the
filter's precision/recall/FP-reduction can be scored.

Usage:
    python lab/generate_fp_filter_dataset.py -n 1000 --fp-ratio 0.85

Outputs:
    lab/data/fp_batch.jsonl           one alert per line
    lab/data/fp_batch_labels.jsonl    one label per line, aligned by index
"""
import argparse
import json
import os
import random
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HOSTS = ["WIN-DC01", "WIN-WEB01", "WIN-FIN02", "WIN-DEV03", "WIN-WS50", "WIN-PROXY01"]
USERS = ["jsmith", "mwilson", "administrator", "svc_backup", "intern_alice", "regular_user", "a.vance"]
SRC_IPS = ["192.168.1.55", "192.168.1.50", "10.0.2.15", "10.0.4.8", "203.0.113.10", "10.0.8.1"]
DEST_IPS = ["10.0.0.10", "10.0.2.5", "10.0.2.20", "10.0.0.4", "10.0.2.30", "10.0.0.50"]


def _time_iso():
    now = datetime.now(timezone.utc)
    return (now - timedelta(minutes=random.randint(0, 2880))).isoformat()


def _fp_patterns():
    """Return (alert_dict, is_false_positive=True) generators."""
    benign_codes = [
        ("4634", "An account was successfully logged off", "low"),
        ("4647", "User initiated logoff", "low"),
        ("4800", "The workstation was locked", "low"),
        ("4801", "The workstation was unlocked", "low"),
        ("4624", "An account was successfully logged on", "low"),
        ("4624", "An account was successfully logged on", "medium"),
        ("7036", "The service entered the running state", "low"),
        ("5058", "Key file operation", "low"),
    ]
    fp_signatures = [
        "Vulnerability scan detected from internal scanner",
        "Windows Update installed",
        "Antivirus signature update",
        "Scheduled backup initiated",
        "Network scan from management subnet",
        "Test alert from monitoring",
    ]
    patterns = []
    for code, sig, sev in benign_codes:
        patterns.append((lambda c=code, s=sig, v=sev: _mk_alert(
            c, s, v, count=random.randint(1, 5), user=random.choice(USERS),
            logon=random.choice(["2", "3", "11"])), True))
    for sig in fp_signatures:
        patterns.append((lambda s=sig: _mk_alert(
            "9999", s, "medium", count=random.randint(1, 3),
            user=random.choice(USERS)), True))
    return patterns


def _tp_patterns():
    """Return (alert_dict, is_false_positive=False) generators (threats)."""
    patterns = [
        (lambda: _mk_alert("4625", "An account failed to log on — multiple failures from same source",
                           "high", count=random.randint(12, 200), user="administrator"), False),
        (lambda: _mk_alert("4625", "Password spray detected: account failed to log on",
                           "high", count=random.randint(20, 300), user="jsmith"), False),
        (lambda: _mk_alert("4702", "A scheduled task was updated — persistence mechanism",
                           "high", user="administrator"), False),
        (lambda: _mk_alert("4698", "A scheduled task was created pointing to temp executable",
                           "critical", user="administrator"), False),
        (lambda: _mk_alert("4688", "A new process has been created: powershell.exe -enc SGVsbG8=",
                           "high", user="administrator"), False),
        (lambda: _mk_alert("7045", "A service was installed in the system — persistence via service",
                           "high", user="administrator"), False),
        (lambda: _mk_alert("4624", "Lateral movement via network logon detected",
                           "critical", user="administrator", logon="3"), False),
        (lambda: _mk_alert("1102", "The audit log was cleared — evidence tampering suspected",
                           "critical", user="administrator"), False),
        (lambda: _mk_alert("4672", "Special privileges assigned to new logon — privilege escalation",
                           "high", user="administrator"), False),
        (lambda: _mk_alert("4776", "Credential validation failed — possible brute force",
                           "medium", count=random.randint(10, 80)), False),
        (lambda: _mk_alert("4932", "Synchronization of a replica — lateral movement indicator",
                           "medium", user="administrator"), False),
    ]
    return patterns


def _mk_alert(event_code, signature, severity, count=1, user="jsmith", logon="3"):
    return {
        "host": random.choice(HOSTS),
        "EventCode": event_code,
        "src_ip": random.choice(SRC_IPS),
        "dest_ip": random.choice(DEST_IPS),
        "user": user,
        "Logon_Type": logon,
        "sourcetype": "WinEventLog:Security",
        "signature": signature,
        "severity": severity,
        "count": count,
        "_time": _time_iso(),
    }


def main():
    parser = argparse.ArgumentParser(description="Generate a synthetic alert batch.")
    parser.add_argument("-n", "--num", type=int, default=1000, help="Number of alerts")
    parser.add_argument("--fp-ratio", type=float, default=0.85,
                        help="Share of alerts that are false positives (0.0-1.0)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out", default="lab/data/fp_batch.jsonl")
    parser.add_argument("--labels-out", default="lab/data/fp_batch_labels.jsonl")
    args = parser.parse_args()

    random.seed(args.seed)
    fp_patterns = _fp_patterns()
    tp_patterns = _tp_patterns()

    alerts = []
    labels = []
    for i in range(args.num):
        if random.random() < args.fp_ratio:
            make, label = random.choice(fp_patterns)
        else:
            make, label = random.choice(tp_patterns)
        alerts.append(make())
        labels.append({"is_false_positive": label})

    with open(args.out, "w", encoding="utf-8") as fh:
        fh.writelines(json.dumps(alert) + "\n" for alert in alerts)
    with open(args.labels_out, "w", encoding="utf-8") as fh:
        fh.writelines(json.dumps(entry) + "\n" for entry in labels)

    print(f"Generated {args.num} alerts -> {args.out}")
    print(f"Labels (fp_ratio={args.fp_ratio}) -> {args.labels_out}")
    print(f"Malicious: {sum(1 for l in labels if not l['is_false_positive'])}  "
          f"Benign: {sum(1 for l in labels if l['is_false_positive'])}")


if __name__ == "__main__":
    main()