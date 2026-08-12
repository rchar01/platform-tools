#!/usr/bin/env python3
"""Non-public direct subprocess driver for Python CA rollover migration."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any


REPOSITORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, os.fspath(REPOSITORY))
os.environ.setdefault("PLATFORM_TOOLS_LIB_DIR", os.fspath(REPOSITORY / "lib"))

from src.platform_pki import ca_rollover_migrate
from src.platform_pki.errors import ApplicationError, render_error
from src.platform_pki.parser import ParserError, parse_route


def _replace(path: str, data: bytes) -> None:
    target = Path(path)
    target.unlink(missing_ok=True)
    target.write_bytes(data)
    target.chmod(0o600)


def _touch(path: str) -> None:
    metadata = os.stat(path, follow_symlinks=False)
    os.utime(
        path,
        ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000_000),
        follow_symlinks=False,
    )


def _install_race_hook() -> None:
    selected = os.environ.get("PLATFORM_PKI_MIGRATE_DRIVER_RACE")
    if selected is None:
        return
    original_build = ca_rollover_migrate._build_transaction
    original_write = ca_rollover_migrate._Transaction.write_journal
    original_move = ca_rollover_migrate._move_tree
    original_publish = ca_rollover_migrate._publish_file
    raced = False

    def build(*args: Any, **kwargs: Any) -> Any:
        if selected == "journal-after-gate":
            _replace(f"{args[0]}/state/rollover/journal", b"hostile-journal\n")
        return original_build(*args, **kwargs)

    def write(self: Any, phase: str, *, committed: bool = False) -> None:
        nonlocal raced
        original_write(self, phase, committed=committed)
        if phase == "pre-mutation" and selected in {
            "root-reservation-original",
            "intermediate-reservation-original",
        }:
            prefix = selected.removesuffix("-reservation-original")
            _replace(self.values[f"{prefix}_reservation"], b"hostile-reservation\n")
        elif phase == "pre-mutation" and selected in {
            "root-reservation-stage",
            "intermediate-reservation-stage",
        }:
            prefix = selected.removesuffix("-reservation-stage")
            _replace(
                f"{self.transaction_dir}/{prefix}-reserved.publish",
                b"hostile-stage\n",
            )
        elif phase == "quarantined" and selected in {
            "root-reservation-reserved",
            "intermediate-reservation-reserved",
        }:
            prefix = selected.removesuffix("-reservation-reserved")
            _replace(self.values[f"{prefix}_reservation"], b"hostile-reserved\n")

    def move(source: str, destination: str, *args: Any, **kwargs: Any) -> Any:
        basename = os.path.basename(source)
        if selected == f"nested-{basename}":
            certificate = (
                f"{source}/certs/root-ca.crt"
                if basename == "root-ca"
                else f"{source}/certs/intermediate-ca.crt"
            )
            metadata = os.stat(certificate, follow_symlinks=False)
            os.utime(
                certificate,
                ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000_000),
                follow_symlinks=False,
            )
        return original_move(source, destination, *args, **kwargs)

    def publish(source: str, destination: str, *args: Any, **kwargs: Any) -> Any:
        nonlocal raced
        if selected == "nested-before-active" and destination.endswith(
            "/state/active-issuer"
        ):
            certificate = destination.removesuffix(
                "/state/active-issuer"
            ) + "/authorities/roots/g1/certs/root-ca.crt"
            metadata = os.stat(certificate, follow_symlinks=False)
            os.utime(
                certificate,
                ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000_000),
                follow_symlinks=False,
            )
        group_match = (
            selected == "config-authority"
            and destination.endswith("/authorities/roots/g1/openssl.cnf")
        ) or (
            selected == "issuer-public" and destination.endswith("/services/app/issuer")
        ) or (
            selected == "quarantine-private"
            and "/quarantine/" in destination
        ) or (
            selected in {"active-inventory", "active-receipt"}
            and destination.endswith("/state/active-issuer")
        )
        if group_match and not raced:
            raced = True
            pki_dir = destination.split("/authorities/", 1)[0]
            if selected == "issuer-public":
                pki_dir = destination.split("/services/", 1)[0]
            elif selected == "quarantine-private":
                pki_dir = destination.split("/state/rollover/", 1)[0]
            elif selected in {"active-inventory", "active-receipt"}:
                pki_dir = destination.removesuffix("/state/active-issuer")
            race_path = {
                "config-authority": f"{pki_dir}/authorities/roots/g1/certs/root-ca.crt",
                "issuer-public": f"{pki_dir}/services/app/certs/tls.crt",
                "quarantine-private": f"{pki_dir}/authorities/roots/g1/private/root-ca.key",
                "active-inventory": f"{pki_dir}/inventory/services.yml",
                "active-receipt": sys.argv[sys.argv.index("--backup-receipt") + 1],
            }[selected]
            _touch(race_path)
        return original_publish(source, destination, *args, **kwargs)

    ca_rollover_migrate._build_transaction = build
    ca_rollover_migrate._Transaction.write_journal = write
    ca_rollover_migrate._move_tree = move
    ca_rollover_migrate._publish_file = publish


def main() -> int:
    try:
        _install_race_hook()
        parsed = parse_route(
            ("ca-rollover", "migrate"), sys.argv[1:], interactive=False
        )
        return ca_rollover_migrate.migrate_ca_rollover(parsed)
    except ParserError as error:
        sys.stderr.write(error.render())
        return 1
    except ApplicationError as error:
        sys.stderr.write(render_error(error))
        return error.status


if __name__ == "__main__":
    raise SystemExit(main())
