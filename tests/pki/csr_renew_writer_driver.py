#!/usr/bin/env python3
"""Isolated non-public subprocess driver for Python host-local CSR renewal."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, os.fspath(REPOSITORY))

from src.platform_pki.errors import ApplicationError, render_error
from src.platform_pki.faults import FaultHook, PauseHook
from src.platform_pki.service_issue import renew_host_local_csr


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("service")
    parser.add_argument("--pki-dir", required=True)
    parser.add_argument("--request-file", required=True)
    parser.add_argument("--request-signature", required=True)
    parser.add_argument("--approval-file", required=True)
    parser.add_argument("--approval-signature", required=True)
    parser.add_argument("--csr-file", required=True)
    parser.add_argument("--response-key", required=True)
    parser.add_argument("--current-cert-file", required=True)
    parser.add_argument("--intermediate-pass-file")
    parser.add_argument("--issuer-safety-days", default="1")
    arguments = parser.parse_args()
    environment = os.environ
    try:
        return renew_host_local_csr(
            arguments.service,
            pki_dir=arguments.pki_dir,
            request_file=arguments.request_file,
            request_signature=arguments.request_signature,
            approval_file=arguments.approval_file,
            approval_signature=arguments.approval_signature,
            csr_file=arguments.csr_file,
            response_key=arguments.response_key,
            current_cert_file=arguments.current_cert_file,
            intermediate_pass_file=arguments.intermediate_pass_file,
            issuer_safety_days=arguments.issuer_safety_days,
            environment=environment,
            fault_hook=FaultHook(
                crash_at=environment.get("PLATFORM_PKI_CSR_PYTHON_WRITER_CRASH_AT"),
                signal_at=environment.get("PLATFORM_PKI_CSR_PYTHON_WRITER_SIGNAL_AT"),
                failure_at=environment.get("PLATFORM_PKI_CSR_PYTHON_WRITER_FAILURE_AT"),
                signum=int(environment.get("PLATFORM_PKI_CSR_PYTHON_WRITER_SIGNAL", "15")),
            ),
            pause_hook=PauseHook(
                pause_at=environment.get("PLATFORM_PKI_CSR_PYTHON_WRITER_PAUSE_AT"),
                marker=environment.get("PLATFORM_PKI_CSR_PYTHON_WRITER_PAUSE_MARKER"),
                release=environment.get("PLATFORM_PKI_CSR_PYTHON_WRITER_PAUSE_RELEASE"),
            ),
        )
    except ApplicationError as error:
        sys.stderr.write(render_error(error))
        return error.status


if __name__ == "__main__":
    raise SystemExit(main())
