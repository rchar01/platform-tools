from __future__ import annotations

import hashlib
import os
import sys
import time
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "bin/platform-runtime-evidence"
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
LEGACY_ALIASES = (
    "platform-pki-init",
    "platform-pki-inventory-install",
    "platform-pki-print-cert",
    "platform-pki-list-expiry",
    "platform-pki-service-verify",
    "platform-pki-export-ansible",
    "platform-pki-backup",
    "platform-pki-custody-report",
    "platform-pki-ca-passphrase-verify",
    "platform-pki-root-create",
    "platform-pki-intermediate-create",
    "platform-pki-csr-recover",
    "platform-pki-service-issue",
    "platform-pki-service-renew",
    "platform-pki-csr-trust-install",
    "platform-pki-certificate-export",
    "platform-pki-csr-candidate",
    "platform-pki-ca-rollover",
)


def arguments(install_dir: Path, probe_dir: Path) -> list[str | Path]:
    return [
        TOOL,
        "--identity",
        "test-host",
        "--role",
        "operator-controller",
        "--owner",
        "unassigned",
        "--executes-pki",
        "yes",
        "--install-dir",
        install_dir,
        "--probe-dir",
        probe_dir,
    ]


def parse_record(output: str) -> dict[str, str]:
    lines = output.splitlines()
    assert lines
    assert all("=" in line for line in lines)
    pairs = [line.split("=", 1) for line in lines]
    assert len(pairs) == len({key for key, _value in pairs})
    return dict(pairs)


def record_keys(output: str) -> list[str]:
    return [line.split("=", 1)[0] for line in output.splitlines()]


def pausing_python_env(
    tmp_path: Path, checkpoint: str, marker: Path, release: Path
) -> dict[str, str]:
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    python = fake_bin / "python3"
    real_python = Path(sys.executable).resolve()
    python.write_text(
        f"""#!{real_python}
import os
import sys

real_python = {os.fspath(real_python)!r}
checkpoint = {checkpoint!r}
if len(sys.argv) >= 3 and sys.argv[1] == "-c":
    source = sys.argv[2]
    def insert_pause(line, *, after=False):
        start = source.index(line)
        line_start = source.rfind("\\n", 0, start) + 1
        indent = source[line_start:start]
        pause = (
            indent + "import time as _evidence_time\\n"
            + indent + "with open({os.fspath(marker)!r}, 'xb'):\\n"
            + indent + "    pass\\n"
            + indent + "while not os.path.exists({os.fspath(release)!r}):\\n"
            + indent + "    _evidence_time.sleep(0.01)\\n"
        )
        if after:
            line_end = source.index("\\n", start) + 1
            return source[:line_end] + pause + source[line_end:]
        return source[:line_start] + pause + source[line_start:]
    if "print(before.st_uid" in source and checkpoint == "before-hash":
        source = insert_pause("descriptor = os.open(path")
    elif "print(before.st_uid" in source and checkpoint == "during-hash":
        source = insert_pause("digest.update(chunk)", after=True)
    elif "print(before.st_uid" in source and checkpoint == "after-hash":
        source = insert_pause("after = os.fstat(descriptor)")
    elif "result = subprocess.run" in source and checkpoint == "before-invoke":
        source = insert_pause("result = subprocess.run(")
    os.execv(real_python, [real_python, "-c", source, *sys.argv[3:]])
os.execv(real_python, [real_python, *sys.argv[1:]])
""",
        encoding="utf-8",
    )
    python.chmod(0o755)
    return {**os.environ, "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}"}


def wait_for_pause(process, marker: Path) -> None:
    deadline = time.monotonic() + 5
    while not marker.exists():
        observation = process.observe()
        assert observation.status is None, observation
        if time.monotonic() >= deadline:
            pytest.fail(f"timed out waiting for pause marker: {marker}", pytrace=False)
        time.sleep(0.01)


@pytest.mark.parametrize(
    ("arguments", "status", "stdout_text", "stderr_text"),
    [
        (["--help"], 0, "Usage:", ""),
        (["--version"], 0, f"platform-runtime-evidence {VERSION}\n", ""),
        (["--unknown"], 1, "", "invalid option: --unknown"),
        ([], 1, "", "missing required flag: --identity IDENTITY"),
        (
            [
                "--identity",
                "",
                "--role",
                "role",
                "--owner",
                "owner",
                "--executes-pki",
                "unknown",
                "--install-dir",
                "/tmp/install",
            ],
            1,
            "",
            "must not be empty",
        ),
        (
            [
                "--identity",
                "bad\nidentity",
                "--role",
                "role",
                "--owner",
                "owner",
                "--executes-pki",
                "unknown",
                "--install-dir",
                "/tmp/install",
            ],
            1,
            "",
            "must not contain tabs or line breaks",
        ),
    ],
    ids=("help", "version", "unknown", "required", "empty", "control"),
)
def test_parser_contract(
    arguments: list[str],
    status: int,
    stdout_text: str,
    stderr_text: str,
    process_runner,
) -> None:
    result = process_runner([TOOL, *arguments])

    assert result.status == status
    if arguments == ["--help"]:
        assert stdout_text in result.stdout
        assert "--executes-pki STATUS (required)" in result.stdout
        assert "identity uncertainty can retain that directory" in result.stdout
        assert "platform-runtime-evidence --identity HOST --role ROLE --owner OWNER" in result.stdout
    else:
        assert result.stdout == stdout_text
    if stderr_text:
        assert stderr_text in result.stderr
    else:
        assert result.stderr == ""


def test_collects_bounded_record_without_invoking_artifact(
    tmp_path: Path, process_runner
) -> None:
    install_dir = tmp_path / "install"
    probe_dir = tmp_path / "probe"
    install_dir.mkdir()
    probe_dir.mkdir()
    invoked = tmp_path / "invoked"
    artifact = install_dir / "platform-pki"
    artifact.write_text(
        f"#!/bin/sh\ntouch {invoked!s}\nprintf 'unexpected\\n'\n",
        encoding="utf-8",
    )
    artifact.chmod(0o755)
    (install_dir / "platform-pki-init").write_text("legacy\n", encoding="utf-8")
    (install_dir / "platform-pki-inventory-install").mkdir()
    (install_dir / "platform-pki-print-cert").symlink_to(artifact)
    (install_dir / "platform-pki-list-expiry").symlink_to(tmp_path / "missing")

    result = process_runner(arguments(install_dir, probe_dir))

    assert result.status == 0, result.stderr
    assert result.stderr == ""
    assert not invoked.exists()
    assert not tuple(probe_dir.iterdir())
    record = parse_record(result.stdout)
    assert record["schema"] == "1"
    assert record["identity"] == "test-host"
    assert record["python3_meets_3_14"] == "yes"
    assert record["platform_pki_state"] == "regular-file"
    assert record["platform_pki_identity_stable"] == "yes"
    assert len(record["platform_pki_sha256"]) == 64
    assert record["platform_pki_version"] == "not-invoked"
    assert record["legacy_alias.platform-pki-init.state"] == "regular-file"
    assert record["legacy_alias.platform-pki-inventory-install.state"] == "directory"
    assert record["legacy_alias.platform-pki-print-cert.state"] == "symlink"
    assert record["legacy_alias.platform-pki-list-expiry.state"] == "dangling-symlink"
    for alias in LEGACY_ALIASES[4:]:
        assert record[f"legacy_alias.{alias}.state"] == "absent"
    assert record["runtime_status"] == "blocked"


def test_record_sections_have_fixed_order(tmp_path: Path, process_runner) -> None:
    install_dir = tmp_path / "install"
    probe_dir = tmp_path / "probe"
    install_dir.mkdir()
    probe_dir.mkdir()

    result = process_runner(arguments(install_dir, probe_dir))

    assert result.status == 0, result.stderr
    keys = record_keys(result.stdout)
    assert keys[:8] == [
        "schema",
        "encoding",
        "identity",
        "role",
        "owner",
        "executes_pki",
        "install_dir",
        "install_dir_state",
    ]
    alias_keys = [f"legacy_alias.{alias}.state" for alias in LEGACY_ALIASES]
    assert keys[keys.index(alias_keys[0]) : keys.index(alias_keys[-1]) + 1] == alias_keys
    assert keys[-1] == "runtime_status"


def test_artifact_read_atime_change_does_not_report_identity_drift(
    tmp_path: Path, process_runner
) -> None:
    install_dir = tmp_path / "install"
    probe_dir = tmp_path / "probe"
    install_dir.mkdir()
    probe_dir.mkdir()
    artifact = install_dir / "platform-pki"
    artifact.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    artifact.chmod(0o755)
    current = artifact.stat()
    os.utime(artifact, ns=(1, current.st_mtime_ns))

    result = process_runner(arguments(install_dir, probe_dir))

    assert result.status == 0, result.stderr
    assert parse_record(result.stdout)["platform_pki_identity_stable"] == "yes"


def test_runtime_status_uses_emitted_legacy_alias_snapshot(
    tmp_path: Path, process_starter
) -> None:
    install_dir = tmp_path / "install"
    probe_dir = tmp_path / "probe"
    fake_bin = tmp_path / "fake-bin"
    install_dir.mkdir()
    probe_dir.mkdir()
    fake_bin.mkdir()
    artifact = install_dir / "platform-pki"
    artifact.write_text("#!/bin/sh\nprintf 'platform-pki 2.3.0\\n'\n", encoding="utf-8")
    artifact.chmod(0o755)
    marker = tmp_path / "alias-snapshot-complete"
    release = tmp_path / "release"
    openssl = fake_bin / "openssl"
    openssl.write_text(
        "#!/bin/sh\n"
        f": > {os.fspath(marker)!r}\n"
        f"while [ ! -e {os.fspath(release)!r} ]; do sleep 0.01; done\n"
        "printf 'OpenSSL test\\n'\n",
        encoding="utf-8",
    )
    openssl.chmod(0o755)
    env = {**os.environ, "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}"}

    process = process_starter(arguments(install_dir, probe_dir), env=env)
    wait_for_pause(process, marker)
    (install_dir / LEGACY_ALIASES[0]).write_bytes(b"late alias\n")
    release.touch()
    result = process.wait()

    assert result.status == 0, result.stderr
    assert result.stderr == ""
    record = parse_record(result.stdout)
    assert record[f"legacy_alias.{LEGACY_ALIASES[0]}.state"] == "absent"
    assert record["runtime_status"] == "role-review-required"


def test_artifact_metadata_uses_emitted_path_state(
    tmp_path: Path, process_starter
) -> None:
    install_dir = tmp_path / "install"
    probe_dir = tmp_path / "probe"
    fake_bin = tmp_path / "fake-bin"
    install_dir.mkdir()
    probe_dir.mkdir()
    fake_bin.mkdir()
    artifact = install_dir / "platform-pki"
    marker = tmp_path / "artifact-state-sampled"
    release = tmp_path / "release"
    uname = fake_bin / "uname"
    uname.write_text(
        "#!/bin/sh\n"
        f"if [ ! -e {os.fspath(marker)!r} ]; then\n"
        f"  : > {os.fspath(marker)!r}\n"
        f"  while [ ! -e {os.fspath(release)!r} ]; do sleep 0.01; done\n"
        "fi\n"
        "case $1 in\n"
        "  -s) printf 'Linux\\n' ;;\n"
        "  -r) printf 'test-release\\n' ;;\n"
        "  -m) printf 'test-architecture\\n' ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    uname.chmod(0o755)
    env = {**os.environ, "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}"}

    process = process_starter(arguments(install_dir, probe_dir), env=env)
    wait_for_pause(process, marker)
    artifact.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    artifact.chmod(0o755)
    release.touch()
    result = process.wait()

    assert result.status == 0, result.stderr
    assert result.stderr == ""
    record = parse_record(result.stdout)
    assert record["platform_pki_state"] == "absent"
    assert record["platform_pki_sha256"] == "unavailable"
    assert record["platform_pki_identity_stable"] == "unavailable"
    assert record["runtime_status"] == "blocked"


def test_artifact_executable_status_uses_hashed_descriptor(
    tmp_path: Path, process_starter
) -> None:
    install_dir = tmp_path / "install"
    probe_dir = tmp_path / "probe"
    install_dir.mkdir()
    probe_dir.mkdir()
    artifact = install_dir / "platform-pki"
    artifact.write_text("#!/bin/sh\nprintf 'original\\n'\n", encoding="utf-8")
    artifact.chmod(0o755)
    replacement = install_dir / "replacement"
    replacement.write_text("#!/bin/sh\nprintf 'replacement\\n'\n", encoding="utf-8")
    replacement.chmod(0o644)
    marker = tmp_path / "artifact-state-sampled"
    release = tmp_path / "release"
    env = pausing_python_env(tmp_path, "before-hash", marker, release)

    process = process_starter(arguments(install_dir, probe_dir), env=env)
    wait_for_pause(process, marker)
    os.replace(replacement, artifact)
    release.touch()
    result = process.wait()

    assert result.status == 0, result.stderr
    assert result.stderr == ""
    record = parse_record(result.stdout)
    assert record["platform_pki_state"] == "regular-file"
    assert record["platform_pki_mode"] == "644"
    assert record["platform_pki_sha256"] == hashlib.sha256(
        b"#!/bin/sh\nprintf 'replacement\\n'\n"
    ).hexdigest()
    assert record["platform_pki_identity_stable"] == "yes"
    assert record["runtime_status"] == "blocked"


@pytest.mark.parametrize("checkpoint", ("during-hash", "after-hash"))
def test_artifact_path_replacement_during_hashing_is_reported_unstable(
    checkpoint: str, tmp_path: Path, process_starter
) -> None:
    install_dir = tmp_path / "install"
    probe_dir = tmp_path / "probe"
    install_dir.mkdir()
    probe_dir.mkdir()
    probe_dir.chmod(0o700)
    artifact = install_dir / "platform-pki"
    original = b"#!/bin/sh\nprintf 'trusted\\n'\n"
    artifact.write_bytes(original)
    artifact.chmod(0o755)
    replacement = install_dir / "replacement"
    replacement.write_bytes(b"#!/bin/sh\nprintf 'hostile\\n'\n")
    replacement.chmod(0o755)
    marker = tmp_path / "paused"
    release = tmp_path / "release"
    env = pausing_python_env(tmp_path, checkpoint, marker, release)

    process = process_starter(arguments(install_dir, probe_dir), env=env)
    wait_for_pause(process, marker)
    os.replace(replacement, artifact)
    release.touch()
    result = process.wait()

    assert result.status == 0, result.stderr
    assert result.stderr == ""
    record = parse_record(result.stdout)
    assert record["platform_pki_sha256"] == hashlib.sha256(original).hexdigest()
    assert record["platform_pki_identity_stable"] == "no"
    assert record["runtime_status"] == "blocked"


def test_probe_setup_failure_removes_owned_directory(
    tmp_path: Path, process_runner
) -> None:
    install_dir = tmp_path / "install"
    probe_dir = tmp_path / "probe"
    fake_bin = tmp_path / "fake-bin"
    install_dir.mkdir()
    probe_dir.mkdir()
    fake_bin.mkdir()
    chmod = fake_bin / "chmod"
    chmod.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    chmod.chmod(0o755)

    result = process_runner(
        arguments(install_dir, probe_dir),
        env={**os.environ, "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}"},
    )

    assert result.status == 1
    assert "Could not protect the capability-probe directory" in result.stderr
    assert not tuple(probe_dir.iterdir())


def test_rejects_unprotected_probe_parent(tmp_path: Path, process_runner) -> None:
    install_dir = tmp_path / "install"
    probe_dir = tmp_path / "probe"
    install_dir.mkdir()
    probe_dir.mkdir(mode=0o777)
    probe_dir.chmod(0o777)

    result = process_runner(arguments(install_dir, probe_dir))

    assert result.status == 1
    assert "must be an identity-stable protected directory" in result.stderr
    assert not tuple(probe_dir.iterdir())


def test_accepts_sticky_probe_parent(tmp_path: Path, process_runner) -> None:
    install_dir = tmp_path / "install"
    probe_dir = tmp_path / "probe"
    install_dir.mkdir()
    probe_dir.mkdir(mode=0o1777)
    probe_dir.chmod(0o1777)

    result = process_runner(arguments(install_dir, probe_dir))

    assert result.status == 0, result.stderr
    assert not tuple(probe_dir.iterdir())


def test_explicit_version_invocation_is_recorded(tmp_path: Path, process_runner) -> None:
    install_dir = tmp_path / "install"
    probe_dir = tmp_path / "probe"
    install_dir.mkdir()
    probe_dir.mkdir()
    artifact = install_dir / "platform-pki"
    artifact.write_text(
        "#!/bin/sh\ncase $0 in /proc/self/fd/*) printf 'artifact %% version\\nignored\\n' ;; *) printf 'pathname execution\\n' ;; esac\n",
        encoding="utf-8",
    )
    artifact.chmod(0o755)

    result = process_runner([*arguments(install_dir, probe_dir), "--invoke-version"])

    assert result.status == 0, result.stderr
    assert result.stderr == ""
    record = parse_record(result.stdout)
    assert record["platform_pki_version_status"] == "0"
    assert record["platform_pki_version"] == "artifact %25 version"
    assert record["runtime_status"] == "role-review-required"


def test_explicit_version_invokes_sealed_snapshot_after_path_replacement(
    tmp_path: Path, process_starter
) -> None:
    install_dir = tmp_path / "install"
    probe_dir = tmp_path / "probe"
    install_dir.mkdir()
    probe_dir.mkdir()
    probe_dir.chmod(0o700)
    artifact = install_dir / "platform-pki"
    original = b"#!/bin/sh\nprintf 'sealed original\\n'\n"
    artifact.write_bytes(original)
    artifact.chmod(0o755)
    replacement = install_dir / "replacement"
    replacement.write_text("#!/bin/sh\nprintf 'path replacement\\n'\n", encoding="utf-8")
    replacement.chmod(0o755)
    marker = tmp_path / "paused"
    release = tmp_path / "release"
    env = pausing_python_env(tmp_path, "before-invoke", marker, release)

    process = process_starter(
        [*arguments(install_dir, probe_dir), "--invoke-version"], env=env
    )
    wait_for_pause(process, marker)
    os.replace(replacement, artifact)
    release.touch()
    result = process.wait()

    assert result.status == 0, result.stderr
    assert result.stderr == ""
    record = parse_record(result.stdout)
    assert record["platform_pki_sha256"] == hashlib.sha256(original).hexdigest()
    assert record["platform_pki_version_status"] == "0"
    assert record["platform_pki_version"] == "sealed original"


def test_version_control_bytes_are_encoded(tmp_path: Path, process_runner) -> None:
    install_dir = tmp_path / "install"
    probe_dir = tmp_path / "probe"
    install_dir.mkdir()
    probe_dir.mkdir()
    artifact = install_dir / "platform-pki"
    artifact.write_text("#!/bin/sh\nprintf 'artifact \\033 version\\n'\n", encoding="utf-8")
    artifact.chmod(0o755)

    result = process_runner([*arguments(install_dir, probe_dir), "--invoke-version"])

    assert result.status == 0, result.stderr
    assert parse_record(result.stdout)["platform_pki_version"] == "artifact %1B version"


def test_non_executor_does_not_require_an_artifact(tmp_path: Path, process_runner) -> None:
    install_dir = tmp_path / "missing-install"
    probe_dir = tmp_path / "probe"
    probe_dir.mkdir()
    argv = arguments(install_dir, probe_dir)
    argv[argv.index("yes")] = "no"

    result = process_runner(argv)

    assert result.status == 0, result.stderr
    record = parse_record(result.stdout)
    assert record["install_dir_state"] == "absent"
    assert record["platform_pki_state"] == "absent"
    assert record["runtime_status"] == "not-applicable"


@pytest.mark.parametrize("boundary", ("install", "probe"))
def test_rejects_symlinked_boundaries(
    boundary: str, tmp_path: Path, process_runner
) -> None:
    real = tmp_path / "real"
    real.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)
    install_dir = linked if boundary == "install" else tmp_path / "install"
    probe_dir = linked if boundary == "probe" else tmp_path / "probe"
    if boundary != "install":
        install_dir.mkdir()
    if boundary != "probe":
        probe_dir.mkdir()

    result = process_runner(arguments(install_dir, probe_dir))

    assert result.status == 1
    assert result.stdout == ""
    assert "must not be a symlink" in result.stderr or "non-symlink" in result.stderr


def test_rejects_relative_paths_without_mutation(tmp_path: Path, process_runner) -> None:
    probe_dir = tmp_path / "probe"
    probe_dir.mkdir()

    result = process_runner(arguments(Path("relative"), probe_dir), cwd=tmp_path)

    assert result.status == 1
    assert result.stdout == ""
    assert "must be absolute" in result.stderr
    assert not (tmp_path / "relative").exists()


@pytest.mark.parametrize(
    ("identity", "encoded"),
    (("host%one", "host%25one"), ("host\x1bone", "host%1Bone")),
    ids=("percent", "escape"),
)
def test_scalar_controls_are_encoded(
    identity: str, encoded: str, tmp_path: Path, process_runner
) -> None:
    install_dir = tmp_path / "install"
    probe_dir = tmp_path / "probe"
    install_dir.mkdir()
    probe_dir.mkdir()
    argv = arguments(install_dir, probe_dir)
    argv[argv.index("test-host")] = identity

    result = process_runner(argv, env={**os.environ, "NO_COLOR": "1"})

    assert result.status == 0, result.stderr
    assert parse_record(result.stdout)["identity"] == encoded
