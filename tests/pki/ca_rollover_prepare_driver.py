#!/usr/bin/env python3
"""Non-public direct subprocess driver for Python CA rollover prepare."""

from __future__ import annotations

import os
import sys
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, os.fspath(REPOSITORY))
os.environ.setdefault("PLATFORM_TOOLS_LIB_DIR", os.fspath(REPOSITORY / "lib"))

from src.platform_pki import ca_rollover_prepare
from src.platform_pki.errors import ApplicationError, render_error
from src.platform_pki.parser import ParserError, parse_route


def _install_mutation_hook() -> None:
    point = os.environ.get("PLATFORM_PKI_PREPARE_DRIVER_MUTATE_AT")
    path = os.environ.get("PLATFORM_PKI_PREPARE_DRIVER_MUTATE_PATH")
    if point is None and path is None:
        return
    if not point or not path:
        raise RuntimeError("prepare driver mutation hook is incomplete")
    mutated = False

    def mutate(preparation: ca_rollover_prepare._Preparation) -> None:
        nonlocal mutated
        if mutated:
            return
        mutated = True
        mutation_path = path.format(
            transaction=preparation.transaction,
            issued_serial=preparation.values.get("issued_serial", "none"),
        )
        descriptor = os.open(
            mutation_path,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        try:
            os.write(descriptor, b"prepare-driver-hostile-mutation\n")
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    mutation_point = point
    original_fault = ca_rollover_prepare._Preparation.fault

    def fault(self: ca_rollover_prepare._Preparation, point: str) -> None:
        original_fault(self, point)
        if point == mutation_point:
            mutate(self)

    ca_rollover_prepare._Preparation.fault = fault


def main() -> int:
    try:
        _install_mutation_hook()
        parsed = parse_route(
            ("ca-rollover", "prepare"), sys.argv[1:], interactive=False
        )
        return ca_rollover_prepare.prepare_ca_rollover(parsed)
    except ParserError as error:
        sys.stderr.write(error.render())
        return 1
    except ApplicationError as error:
        sys.stderr.write(render_error(error))
        return error.status


if __name__ == "__main__":
    raise SystemExit(main())
