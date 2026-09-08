"""
CLI entry point for the false-positive filter.

Classify a batch of alerts and produce a report.

Examples:
    # Generate a 1000-alert test dataset first:
    python lab/generate_fp_filter_dataset.py -n 1000

    # Classify it (rule-based only):
    python -m src.fp_filter --input lab/data/fp_batch.jsonl --output report/fp_report.json

    # With ground-truth metrics and LLM adjudication for REVIEW alerts:
    python -m src.fp_filter --input lab/data/fp_batch.jsonl \
        --ground-truth lab/data/fp_batch_labels.jsonl \
        --llm --output report/fp_report.json

Run `python -m src.fp_filter --help` for all options.
"""
import argparse
import json
import sys
import time


def _load_labels(path: str, total: int) -> list:
    with open(path, "r", encoding="utf-8") as fh:
        content = fh.read().strip()
    if not content:
        return []
    if content.startswith("["):
        labels = json.loads(content)
    else:
        labels = [json.loads(ln) for ln in content.splitlines() if ln.strip()]
    return labels


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.fp_filter",
        description="Batch false-positive classification for SOC alerts.",
    )
    parser.add_argument("-i", "--input", required=True,
                        help="Alerts file (JSON array, JSONL, or {'alerts': [...]})")
    parser.add_argument("-o", "--output", help="Optional path to write the JSON report")
    parser.add_argument("-g", "--ground-truth",
                        help="Optional aligned labels file for accuracy metrics")
    parser.add_argument("--llm", action="store_true",
                        help="Resolve REVIEW alerts with the local LLM (Ollama)")
    parser.add_argument("--quiet", action="store_true", help="Suppress console summary")
    args = parser.parse_args(argv)

    from src.fp_filter.batch import load_alerts, run_batch

    try:
        alerts = load_alerts(args.input)
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: could not load alerts from {args.input}: {exc}", file=sys.stderr)
        return 1

    if not alerts:
        print("No alerts found in input file.", file=sys.stderr)
        return 1

    ground_truth = None
    if args.ground_truth:
        ground_truth = _load_labels(args.ground_truth, len(alerts))
        if len(ground_truth) != len(alerts):
            print(
                f"ERROR: ground-truth has {len(ground_truth)} entries but "
                f"input has {len(alerts)} alerts",
                file=sys.stderr,
            )
            return 1

    if not args.quiet and args.llm and not args.ground_truth:
        print("INFO: --llm resolves REVIEW alerts via the local model "
              "(make sure Ollama is running).")

    start = time.time()
    report = run_batch(
        alerts,
        ground_truth=ground_truth,
        use_llm=args.llm,
        verbose=not args.quiet,
    )
    report["duration_seconds"] = round(time.time() - start, 3)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)
        if not args.quiet:
            print(f"Report written to {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())