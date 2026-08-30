"""CLI entry point for the CIC-IDS2017 canonical data factory."""

try:
    from .cicids2017_factory import main
except ImportError:
    from cicids2017_factory import main


if __name__ == "__main__":
    raise SystemExit(main())
