"""Generated service-certificate expiry reporting."""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping

from .errors import ApplicationError
from .operational import (
    acquire_operational_locks,
    load_active_issuer,
    load_inventory,
    prepare_control_state,
    require_generation_layout,
    require_inventory_readable,
    require_pki_directory,
    require_program,
    resolve_paths,
    run_external,
)
from .parser import ParseResult


def _write_child_stderr(value: bytes) -> None:
    sys.stderr.buffer.write(value)
    sys.stderr.buffer.flush()


def _command_text(
    argv: tuple[str, ...], environment: Mapping[str, str]
) -> tuple[int, str]:
    result = run_external(argv, environment)
    _write_child_stderr(result.stderr)
    if result.status:
        return result.status, ""
    try:
        return 0, result.stdout.decode("utf-8").rstrip("\n")
    except UnicodeDecodeError:
        raise ApplicationError("External command returned invalid text") from None


def _not_after(
    certificate: str, environment: Mapping[str, str]
) -> tuple[int, str]:
    openssl = run_external(
        ("openssl", "x509", "-in", certificate, "-noout", "-enddate"),
        environment,
    )
    _write_child_stderr(openssl.stderr)
    sed = run_external(
        ("sed", "s/^notAfter=//"), environment, input=openssl.stdout
    )
    _write_child_stderr(sed.stderr)
    status = sed.status or openssl.status
    if status:
        return status, ""
    try:
        return 0, sed.stdout.decode("utf-8").rstrip("\n")
    except UnicodeDecodeError:
        raise ApplicationError("External command returned invalid text") from None


def _expiry_values(
    certificate: str, environment: Mapping[str, str]
) -> tuple[int, int, str]:
    status, not_after = _not_after(certificate, environment)
    if status:
        return status, 0, ""
    status, end_text = _command_text(
        ("date", "-u", "-d", not_after, "+%s"), environment
    )
    if status:
        return status, 0, ""
    status, now_text = _command_text(("date", "-u", "+%s"), environment)
    if status:
        return status, 0, ""
    try:
        delta = int(end_text, 10) - int(now_text, 10)
    except ValueError:
        raise ApplicationError("Certificate expiry command returned invalid time") from None
    days_left = delta // 86400 if delta >= 0 else -((-delta) // 86400)

    status, not_after = _not_after(certificate, environment)
    if status:
        return status, 0, ""
    status, expires = _command_text(
        ("date", "-u", "-d", not_after, "+%Y-%m-%dT%H:%M:%SZ"),
        environment,
    )
    return status, days_left, expires


def list_expiry(parsed: ParseResult) -> int:
    """Print expiry status for every service in inventory order."""

    environment = dict(os.environ)
    paths = resolve_paths(parsed.values, environment)
    warn_days = int(str(parsed["--warn-days"]), 10)
    critical_days = int(str(parsed["--critical-days"]), 10)
    require_program("openssl", environment)
    require_pki_directory(paths.pki_dir)
    prepare_control_state(paths.pki_dir)
    inventory_path = require_inventory_readable(paths.pki_dir)
    require_program("flock", environment)

    with acquire_operational_locks(paths.pki_dir, "inventory"):
        require_generation_layout(paths.pki_dir)
        load_active_issuer(paths.pki_dir, environment)
        inventory = load_inventory(inventory_path)
        print(f"{'SERVICE':24} {'EXPIRES':22} {'DAYS_LEFT':10} STATUS", flush=True)
        exit_status = 0
        for service in inventory.services:
            certificate = (
                f"{paths.pki_dir}/services/{service.name}/certs/tls.crt"
            )
            if not os.path.isfile(certificate):
                print(f"{service.name:24} {'-':22} {'-':10} MISSING", flush=True)
                exit_status = 3
                continue

            status, days_left, expires = _expiry_values(certificate, environment)
            if status:
                return status
            label = "OK"
            if days_left <= critical_days:
                label = "CRITICAL"
                if exit_status < 2:
                    exit_status = 2
            elif days_left <= warn_days:
                label = "WARN"
                if exit_status < 1:
                    exit_status = 1
            print(
                f"{service.name:24} {expires:22} {days_left:<10} {label}",
                flush=True,
            )
        return exit_status
