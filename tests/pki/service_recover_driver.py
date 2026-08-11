#!/usr/bin/env python3
"""Isolated non-public subprocess driver for managed-service recovery."""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, os.fspath(REPOSITORY))

from src.platform_pki.errors import ApplicationError
from src.platform_pki.faults import FaultHook
from src.platform_pki.service_recover import (
    recover_service_transaction,
    service_recovery_hooks,
)


def _trace(path: str, point: str) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW,
        0o600,
    )
    try:
        os.write(descriptor, f"{point}\n".encode("ascii"))
    finally:
        os.close(descriptor)


@dataclass(frozen=True, slots=True)
class _TracingFault(FaultHook):
    trace_path: str = ""

    def __call__(self, point: str) -> None:
        _trace(self.trace_path, point)
        super().__call__(point)


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--pki-dir", required=True)
    parser.add_argument("--transaction", required=True)
    arguments = parser.parse_args()
    try:
        fault, pause = service_recovery_hooks(os.environ)
        trace = os.environ.get("PLATFORM_PKI_SERVICE_RECOVER_TRACE_FILE")
        if trace is not None:
            fault = _TracingFault(
                crash_at=fault.crash_at,
                signal_at=fault.signal_at,
                failure_at=fault.failure_at,
                signum=fault.signum,
                trace_path=trace,
            )

        return recover_service_transaction(
            arguments.pki_dir,
            transaction=arguments.transaction,
            fault_hook=fault,
            pause_hook=pause,
        )
    except (ApplicationError, ValueError) as error:
        print(f"[ERROR] {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
