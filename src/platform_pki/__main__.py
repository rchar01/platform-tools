import os
import sys

from . import MINIMUM_PYTHON


def main() -> int:
    if sys.version_info < MINIMUM_PYTHON:
        print("platform-pki requires Python 3.14 or newer", file=sys.stderr)
        return 1

    if (
        os.environ.get("PLATFORM_PKI_INTERNAL_SSH_ASKPASS") == "1"
        and len(sys.argv) == 2
    ):
        from .ssh_keys import askpass

        return askpass()

    from .cli import main as cli_main

    return cli_main()


if __name__ == "__main__":
    raise SystemExit(main())
