"""Allow running as `python -m recursive_resolver`."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
