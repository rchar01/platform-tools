#!/usr/bin/env python3
"""Non-public direct subprocess driver for Python CA rollover status."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, os.fspath(REPOSITORY))
os.environ.setdefault(
    "PLATFORM_TOOLS_LIB_DIR",
    os.fspath(REPOSITORY / "tests/pki/oracles/final-bash-source/lib"),
)

from src.platform_pki import ca_rollover_status as status_module
from src.platform_pki.errors import ApplicationError, render_error
from src.platform_pki.parser import ParserError, parse_route


def _install_race() -> None:
    target_value = os.environ.pop("PLATFORM_PKI_STATUS_RACE_TARGET", None)
    replacement_value = os.environ.pop("PLATFORM_PKI_STATUS_RACE_REPLACEMENT", None)
    mode = os.environ.pop("PLATFORM_PKI_STATUS_RACE_MODE", "certificate")
    if target_value is None and replacement_value is None and mode == "certificate":
        return
    if mode == "certificate":
        if not target_value or not replacement_value:
            raise RuntimeError("status race injection requires target and replacement")
        target = Path(target_value)
        replacement = Path(replacement_value)
        original = status_module.run_process
        replaced = False

        def run_process(*args, **kwargs):
            nonlocal replaced
            result = original(*args, **kwargs)
            argv = tuple(os.fspath(value) for value in args[0])
            if not replaced and argv[:2] == ("openssl", "x509") and "-in" in argv:
                reference = argv[argv.index("-in") + 1]
                try:
                    descriptor = int(reference.removeprefix("/proc/self/fd/"))
                    matches = os.path.samestat(os.fstat(descriptor), os.stat(target))
                except (OSError, ValueError):
                    matches = False
                if matches:
                    shutil.copystat(target, replacement)
                    os.replace(replacement, target)
                    replaced = True
            return result

        status_module.run_process = run_process
        return
    if not target_value or mode not in ("replace", "remove", "create"):
        raise RuntimeError("unsupported status output race injection")
    target = Path(target_value)

    def before_output() -> None:
        if mode == "remove":
            target.unlink()
        elif mode == "create":
            target.write_text("race\n", encoding="ascii")
            target.chmod(0o600)
        else:
            if not replacement_value:
                raise RuntimeError("record replacement requires a replacement")
            replacement = Path(replacement_value)
            shutil.copystat(target, replacement)
            os.replace(replacement, target)

    status_module._before_output = before_output


def main() -> int:
    try:
        _install_race()
        parsed = parse_route(
            ("ca-rollover", "status"), sys.argv[1:], interactive=False
        )
        return status_module.ca_rollover_status(parsed)
    except ParserError as error:
        sys.stderr.write(error.render())
        return 1
    except ApplicationError as error:
        sys.stderr.write(render_error(error))
        return error.status


if __name__ == "__main__":
    raise SystemExit(main())
