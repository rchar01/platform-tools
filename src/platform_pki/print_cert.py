"""Readable service-certificate inspection."""

from __future__ import annotations

import os
import sys

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
    require_service,
    resolve_paths,
    run_external,
    validate_service_name,
)
from .parser import ParseResult


def _write_result(stdout: bytes, stderr: bytes) -> None:
    sys.stdout.buffer.write(stdout)
    sys.stderr.buffer.write(stderr)
    sys.stdout.buffer.flush()
    sys.stderr.buffer.flush()


def print_certificate(parsed: ParseResult) -> int:
    """Render one inventory service certificate through OpenSSL-owned output."""

    environment = dict(os.environ)
    service = parsed["service"]
    assert isinstance(service, str)
    validate_service_name(service)
    paths = resolve_paths(parsed.values, environment)
    require_program("openssl", environment)
    require_pki_directory(paths.pki_dir)
    prepare_control_state(paths.pki_dir)
    inventory_path = require_inventory_readable(paths.pki_dir)
    require_program("flock", environment)

    with acquire_operational_locks(paths.pki_dir, "inventory"):
        require_generation_layout(paths.pki_dir)
        load_active_issuer(paths.pki_dir, environment)
        inventory = load_inventory(inventory_path)
        require_service(inventory, service, inventory_path)
        certificate = f"{paths.pki_dir}/services/{service}/certs/tls.crt"
        if not os.path.isfile(certificate):
            raise ApplicationError(f"Required file is missing: {certificate}")

        sys.stdout.buffer.write(f"Service: {service}\n".encode("ascii"))
        sys.stdout.buffer.flush()
        result = run_external(
            (
                "openssl",
                "x509",
                "-in",
                certificate,
                "-noout",
                "-subject",
                "-issuer",
                "-serial",
                "-startdate",
                "-enddate",
                "-fingerprint",
                "-sha256",
            ),
            environment,
        )
        _write_result(result.stdout, result.stderr)
        if result.status:
            return result.status

        for extension in ("subjectAltName", "keyUsage", "extendedKeyUsage"):
            result = run_external(
                (
                    "openssl",
                    "x509",
                    "-in",
                    certificate,
                    "-noout",
                    "-ext",
                    extension,
                ),
                environment,
            )
            _write_result(result.stdout, result.stderr)
    return 0
