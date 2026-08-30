"""Compatibility entry point for canonical CIC-IDS2017 preparation."""

try:
    from .cicids2017_factory import main
except ImportError:
    from cicids2017_factory import main


if __name__ == "__main__":
    raise SystemExit(main())
