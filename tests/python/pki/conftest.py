import os
from collections.abc import Mapping
from pathlib import Path

import pytest


@pytest.fixture
def rollover_tool() -> Path:
    return Path(__file__).resolve().parents[3] / "bin/platform-pki-ca-rollover"


@pytest.fixture
def isolated_environment(tmp_path: Path) -> Mapping[str, str]:
    home = tmp_path / "home"
    config = tmp_path / "config"
    temporary = tmp_path / "tmp"
    for directory in (home, config, temporary):
        directory.mkdir(mode=0o700)
        directory.chmod(0o700)

    return {
        "HOME": os.fspath(home),
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "PATH": os.environ.get("PATH", os.defpath),
        "TMPDIR": os.fspath(temporary),
        "XDG_CONFIG_HOME": os.fspath(config),
    }
