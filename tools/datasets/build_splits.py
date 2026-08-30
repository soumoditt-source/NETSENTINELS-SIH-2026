"""Compatibility entry point for leakage-aware CIC split generation."""

try:
    from .cicids2017_factory import main
except ImportError:
    from cicids2017_factory import main


if __name__ == "__main__":
    raise SystemExit(main())
