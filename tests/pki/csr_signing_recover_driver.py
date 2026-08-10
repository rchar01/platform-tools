#!/usr/bin/env python3
"""Isolated non-public subprocess driver for CSR signing recovery."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, os.fspath(REPOSITORY))

from src.platform_pki.csr_recover import recover_signing, signing_recovery_hooks
from src.platform_pki.errors import ApplicationError


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--pki-dir", required=True)
    parser.add_argument("--transaction", required=True)
    parser.add_argument("--response-key")
    arguments = parser.parse_args()
    try:
        fault, pause = signing_recovery_hooks(os.environ)
        return recover_signing(
            arguments.pki_dir,
            transaction=arguments.transaction,
            response_key=arguments.response_key,
            environment=os.environ,
            fault_hook=fault,
            pause_hook=pause,
        )
    except (ApplicationError, ValueError) as error:
        print(f"[ERROR] {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
