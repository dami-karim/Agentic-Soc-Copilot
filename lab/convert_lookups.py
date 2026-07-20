import csv
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

LOOKUPS_DIR = Path("lab/data/botsv3_data_set/lookups")
OUTPUT_FILE = Path("lab/data/bots_events.json")

events = []
for csv_file in LOOKUPS_DIR.glob("*.csv"):
    print(f"Reading {csv_file.name}...")
    try:
        with open(csv_file, newline="", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                row["alert_id"] = str(uuid.uuid4())
                row["_source_file"] = csv_file.name
                if "_time" not in row:
                    row["_time"] = datetime.now(timezone.utc).isoformat()
                events.append(row)
    except Exception as e:
        print(f"  Skipped {csv_file.name}: {e}")

print(f"\nTotal events extracted: {len(events)}")

with open(OUTPUT_FILE, "w") as f:
    for event in events:
        f.write(json.dumps(event) + "\n")

print(f"Written to {OUTPUT_FILE}")
