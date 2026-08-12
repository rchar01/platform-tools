"""Managed service-certificate verification."""

from __future__ import annotations

import os
import sys
import tempfile
from collections.abc import Mapping

from .errors import ApplicationError
from .operational import (
    acquire_operational_locks,
    get_service,
    load_active_issuer,
    load_inventory,
    load_service_issuer,
    prepare_control_state,
    require_generation_layout,
    require_inventory_readable,
    require_pki_directory,
    require_program,
    resolve_paths,
    run_external,
    validate_service_name,
)
from .parser import ParseResult


def _write_stderr(value: bytes) -> None:
    sys.stderr.buffer.write(value)
    sys.stderr.buffer.flush()


def _run_visible_stderr(
    argv: tuple[str, ...], environment: Mapping[str, str]
):
    result = run_external(argv, environment)
    _write_stderr(result.stderr)
    return result


def _require_file(path: str) -> None:
    if not os.path.isfile(path):
        raise ApplicationError(f"Required file is missing: {path}")


def _write_private(path: str, content: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as opened:
        opened.write(content)


def _key_matches_certificate(
    key: str, certificate: str, environment: Mapping[str, str]
) -> bool:
    with tempfile.TemporaryDirectory(prefix="platform-pki-service-verify.") as directory:
        cert_public = f"{directory}/cert.pub"
        key_public = f"{directory}/key.pub"
        result = _run_visible_stderr(
            ("openssl", "x509", "-in", certificate, "-pubkey", "-noout"),
            environment,
        )
        if result.status:
            return False
        _write_private(cert_public, result.stdout)
        result = _run_visible_stderr(
            ("openssl", "pkey", "-in", key, "-pubout"), environment
        )
        if result.status:
            return False
        _write_private(key_public, result.stdout)
        result = run_external(("cmp", "-s", cert_public, key_public), environment)
        return result.status == 0


def _certificate_text_contains(
    certificate: str,
    extension: str,
    expected: str,
    environment: Mapping[str, str],
) -> bool:
    result = run_external(
        ("openssl", "x509", "-in", certificate, "-noout", "-ext", extension),
        environment,
    )
    _write_stderr(result.stderr)
    grep = run_external(
        ("grep", "-F", expected), environment, input=result.stdout
    )
    return result.status == 0 and grep.status == 0


def verify_service(parsed: ParseResult) -> int:
    """Verify one managed service certificate in the frozen check order."""

    environment = dict(os.environ)
    service_name = parsed["service"]
    assert isinstance(service_name, str)
    validate_service_name(service_name)
    min_days = int(str(parsed["--min-days"]), 10)
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
        service = get_service(inventory, service_name, inventory_path)
        if service.key_custody != "managed":
            raise ApplicationError(
                "Host-local signer-side candidate verification is unavailable: "
                f"{service_name}"
            )

        key = f"{paths.pki_dir}/services/{service_name}/private/tls.key"
        certificate = f"{paths.pki_dir}/services/{service_name}/certs/tls.crt"
        root, intermediate = load_service_issuer(paths.pki_dir, service_name)
        root_certificate = (
            f"{paths.pki_dir}/authorities/roots/{root}/certs/root-ca.crt"
        )
        intermediate_certificate = (
            f"{paths.pki_dir}/authorities/intermediates/{intermediate}"
            "/certs/intermediate-ca.crt"
        )
        for path in (key, certificate, root_certificate, intermediate_certificate):
            _require_file(path)

        result = _run_visible_stderr(
            (
                "openssl",
                "verify",
                "-CAfile",
                root_certificate,
                "-untrusted",
                intermediate_certificate,
                certificate,
            ),
            environment,
        )
        if result.status:
            return result.status
        if not _key_matches_certificate(key, certificate, environment):
            raise ApplicationError(
                f"Private key does not match certificate for service: {service_name}"
            )
        if not _certificate_text_contains(
            certificate, "basicConstraints", "CA:FALSE", environment
        ):
            raise ApplicationError(f"Certificate is missing CA:false: {certificate}")
        if not _certificate_text_contains(
            certificate,
            "extendedKeyUsage",
            "TLS Web Server Authentication",
            environment,
        ):
            raise ApplicationError(
                f"Certificate is missing serverAuth EKU: {certificate}"
            )
        for dns in service.dns:
            if not _certificate_text_contains(
                certificate, "subjectAltName", f"DNS:{dns}", environment
            ):
                raise ApplicationError(
                    f"Certificate is missing DNS SAN '{dns}': {certificate}"
                )
        for ip in service.ips:
            if not _certificate_text_contains(
                certificate, "subjectAltName", f"IP Address:{ip}", environment
            ):
                raise ApplicationError(
                    f"Certificate is missing IP SAN '{ip}': {certificate}"
                )
        result = _run_visible_stderr(
            (
                "openssl",
                "x509",
                "-in",
                certificate,
                "-checkend",
                str(min_days * 86400),
                "-noout",
            ),
            environment,
        )
        if result.status:
            raise ApplicationError(
                f"Certificate has less than {min_days} days remaining: {certificate}"
            )

        print(f"[OK] Verified service certificate: {service_name}")
        return 0
