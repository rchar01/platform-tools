#!/usr/bin/env python3
"""Isolated non-public subprocess driver for candidate-finalization recovery."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, os.fspath(REPOSITORY))

from src.platform_pki.csr_recover import recover_finalization, recovery_hooks
from src.platform_pki.errors import ApplicationError


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--pki-dir", required=True)
    parser.add_argument("--transaction")
    arguments = parser.parse_args()
    try:
        fault, pause = recovery_hooks(os.environ)
        return recover_finalization(
            arguments.pki_dir,
            transaction=arguments.transaction,
            environment=os.environ,
            fault_hook=fault,
            pause_hook=pause,
        )
    except ApplicationError as error:
        print(f"[ERROR] {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
