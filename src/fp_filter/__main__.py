"""Allow `python -m src.fp_filter` to invoke the CLI."""
import sys

from src.fp_filter.cli import main

if __name__ == "__main__":
    sys.exit(main())