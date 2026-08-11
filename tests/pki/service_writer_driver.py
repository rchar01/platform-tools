from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, os.fspath(REPOSITORY))

from src.platform_pki.errors import ApplicationError
from src.platform_pki.faults import FaultHook, PauseHook
from src.platform_pki.service_writer import ManagedServiceWriter


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pki-dir", required=True)
    arguments = parser.parse_args()
    environment = os.environ
    try:
        writer = ManagedServiceWriter.load(
            f"{arguments.pki_dir}/state/service/recovery-journal",
            pki_dir=arguments.pki_dir,
            fault=FaultHook(
                crash_at=environment.get("PLATFORM_PKI_SERVICE_WRITER_CRASH_AT"),
                signal_at=environment.get("PLATFORM_PKI_SERVICE_WRITER_SIGNAL_AT")
            ),
            pause=PauseHook(
                pause_at=environment.get("PLATFORM_PKI_SERVICE_WRITER_PAUSE_AT"),
                marker=environment.get("PLATFORM_PKI_SERVICE_WRITER_PAUSE_MARKER"),
                release=environment.get("PLATFORM_PKI_SERVICE_WRITER_PAUSE_RELEASE"),
            ),
        )
        writer.publish_next()
    except ApplicationError as error:
        print(f"[ERROR] {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
