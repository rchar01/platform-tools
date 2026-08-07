import sys

from . import MINIMUM_PYTHON


def main() -> int:
    if sys.version_info < MINIMUM_PYTHON:
        print("platform-pki requires Python 3.14 or newer", file=sys.stderr)
        return 1

    from .cli import main as cli_main

    return cli_main()


if __name__ == "__main__":
    raise SystemExit(main())
