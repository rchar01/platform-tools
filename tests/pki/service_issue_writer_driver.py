from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, os.fspath(REPOSITORY))

from src.platform_pki.errors import ApplicationError, render_error
from src.platform_pki.faults import FaultHook, PauseHook
from src.platform_pki.service_issue import issue_managed_service


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("service")
    parser.add_argument("--pki-dir", required=True)
    parser.add_argument("--days")
    parser.add_argument("--issuer-safety-days", default="1")
    parser.add_argument("--intermediate-pass-file")
    parser.add_argument("--rotate-key", action="store_true")
    arguments = parser.parse_args()
    environment = os.environ
    try:
        return issue_managed_service(
            arguments.service,
            pki_dir=arguments.pki_dir,
            days=arguments.days,
            issuer_safety_days=arguments.issuer_safety_days,
            intermediate_pass_file=arguments.intermediate_pass_file,
            rotate_key=arguments.rotate_key,
            environment=environment,
            fault_hook=FaultHook(
                crash_at=environment.get("PLATFORM_PKI_SERVICE_ISSUE_CRASH_AT"),
                signal_at=environment.get("PLATFORM_PKI_SERVICE_ISSUE_SIGNAL_AT"),
                failure_at=environment.get("PLATFORM_PKI_SERVICE_ISSUE_FAILURE_AT"),
                signum=int(environment.get("PLATFORM_PKI_SERVICE_ISSUE_SIGNAL", "15")),
            ),
            pause_hook=PauseHook(
                pause_at=environment.get("PLATFORM_PKI_SERVICE_ISSUE_PAUSE_AT"),
                marker=environment.get("PLATFORM_PKI_SERVICE_ISSUE_PAUSE_MARKER"),
                release=environment.get("PLATFORM_PKI_SERVICE_ISSUE_PAUSE_RELEASE"),
            ),
        )
    except ApplicationError as error:
        sys.stderr.write(render_error(error))
        return error.status


if __name__ == "__main__":
    raise SystemExit(main())
