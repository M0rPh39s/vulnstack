"""Allow ``python -m vulnstack`` to work identically to the ``vulnstack`` script."""

from vulnstack.cli import main

if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
