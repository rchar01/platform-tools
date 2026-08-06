from __future__ import annotations

import fcntl
import os
import re
import shutil
import tempfile
from collections.abc import Callable, Iterator, Mapping, Sequence
from hashlib import sha256
from pathlib import Path

import pytest

from ..harness import ProcessResult
from .conftest import RolloverWorkspace


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "bin/platform-pki-ca-passphrase-verify"
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
GENERIC_FAILURE = "[ERROR] CA passphrase verification failed\n"


@pytest.fixture
def executable_directory() -> Iterator[Path]:
    temporary_root = ROOT / ".tmp"
    temporary_root.mkdir(mode=0o700, exist_ok=True)
    path = Path(tempfile.mkdtemp(prefix="pytest-ca-passphrase-verify.", dir=temporary_root))
    path.chmod(0o700)
    yield path
    shutil.rmtree(path)


def _run(
    process_runner: Callable[..., ProcessResult],
    workspace: RolloverWorkspace,
    arguments: Sequence[str | Path],
    environment: Mapping[str, str],
) -> ProcessResult:
    return process_runner(
        [TOOL, "--namespace", workspace.namespace, *arguments],
        env=environment,
        timeout=30,
    )


def _write_private(path: Path, content: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(content)


def _state_snapshot(pki: Path) -> dict[str, tuple[int, int, int, str]]:
    snapshot = {}
    for path in sorted(pki.rglob("*")):
        if not path.is_file() or path.is_symlink() or path.is_relative_to(pki / "locks"):
            continue
        metadata = path.stat()
        snapshot[path.relative_to(pki).as_posix()] = (
            metadata.st_mode,
            metadata.st_size,
            metadata.st_mtime_ns,
            sha256(path.read_bytes()).hexdigest(),
        )
    return snapshot


def test_help_and_version(process_runner: Callable[..., ProcessResult]) -> None:
    help_result = process_runner([TOOL, "--help"])
    assert help_result.status == 0
    assert "inherited file descriptors" in help_result.stdout
    assert help_result.stderr == ""

    version_result = process_runner([TOOL, "--version"])
    assert version_result == ProcessResult(
        version_result.args,
        0,
        f"platform-pki-ca-passphrase-verify {VERSION}\n",
        "",
    )


def test_requires_at_least_one_passphrase_file(
    process_runner: Callable[..., ProcessResult],
) -> None:
    result = process_runner([TOOL])
    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == (
        "[ERROR] At least one of --root-pass-file or "
        "--intermediate-pass-file is required\n"
    )


@pytest.mark.parametrize(
    ("arguments", "stdout"),
    [
        pytest.param(
            ["--root-pass-file", "{passphrase}"],
            "root=valid\n",
            id="root",
        ),
        pytest.param(
            ["--intermediate-pass-file", "{passphrase}"],
            "intermediate=valid\n",
            id="intermediate",
        ),
        pytest.param(
            [
                "--root-pass-file",
                "{passphrase}",
                "--intermediate-pass-file",
                "{passphrase}",
            ],
            "root=valid\nintermediate=valid\n",
            id="both",
        ),
    ],
)
def test_valid_passphrases_are_read_only_and_deterministic(
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    arguments: list[str],
    stdout: str,
    request: pytest.FixtureRequest,
) -> None:
    workspace = rollover_case_factory(f"valid-{request.node.callspec.id}")
    expanded = [
        os.fspath(workspace.passphrase_file) if value == "{passphrase}" else value
        for value in arguments
    ]
    before = _state_snapshot(workspace.pki)

    result = _run(process_runner, workspace, expanded, isolated_environment)

    assert result == ProcessResult(result.args, 0, stdout, "")
    assert _state_snapshot(workspace.pki) == before
    assert not list(workspace.pki.rglob("*passphrase-verif*"))


@pytest.mark.parametrize("authority", ("root", "intermediate"))
def test_wrong_passphrase_has_only_generic_failure(
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    authority: str,
) -> None:
    workspace = rollover_case_factory(f"wrong-{authority}")
    wrong = workspace.root / "wrong-passphrase"
    secret = "wrong-passphrase-must-not-leak"
    _write_private(wrong, f"{secret}\n")

    result = _run(
        process_runner,
        workspace,
        [f"--{authority}-pass-file", wrong],
        isolated_environment,
    )

    assert result == ProcessResult(result.args, 1, "", GENERIC_FAILURE)
    assert secret not in result.stdout + result.stderr
    assert "decrypt" not in result.stderr.lower()


@pytest.mark.parametrize("wrong_authority", ("root", "intermediate"))
def test_requested_checks_fail_without_partial_success_output(
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    wrong_authority: str,
) -> None:
    workspace = rollover_case_factory(f"no-partial-success-{wrong_authority}")
    wrong = workspace.root / f"wrong-{wrong_authority}-passphrase"
    _write_private(wrong, f"wrong-{wrong_authority}-passphrase\n")
    root_pass = wrong if wrong_authority == "root" else workspace.passphrase_file
    intermediate_pass = wrong if wrong_authority == "intermediate" else workspace.passphrase_file

    result = _run(
        process_runner,
        workspace,
        [
            "--root-pass-file",
            root_pass,
            "--intermediate-pass-file",
            intermediate_pass,
        ],
        isolated_environment,
    )

    assert result == ProcessResult(result.args, 1, "", GENERIC_FAILURE)


def test_key_certificate_mismatch_has_only_generic_failure(
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = rollover_case_factory("certificate-mismatch")
    root_certificate = workspace.pki / "authorities/roots/g1/certs/root-ca.crt"
    intermediate_certificate = (
        workspace.pki
        / "authorities/intermediates/g1-i1/certs/intermediate-ca.crt"
    )
    shutil.copyfile(intermediate_certificate, root_certificate)
    root_certificate.chmod(0o644)

    result = _run(
        process_runner,
        workspace,
        ["--root-pass-file", workspace.passphrase_file],
        isolated_environment,
    )

    assert result == ProcessResult(result.args, 1, "", GENERIC_FAILURE)


def test_unencrypted_key_cannot_validate_a_passphrase(
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = rollover_case_factory("unencrypted-key")
    root_key = workspace.pki / "authorities/roots/g1/private/root-ca.key"
    plaintext = workspace.root / "plaintext-root.key"
    conversion = process_runner(
        [
            "openssl",
            "pkey",
            "-in",
            root_key,
            "-passin",
            f"file:{workspace.passphrase_file}",
            "-out",
            plaintext,
        ],
        env=isolated_environment,
    )
    assert conversion.status == 0, conversion.stderr
    assert conversion.stdout == ""
    plaintext.replace(root_key)
    root_key.chmod(0o600)

    result = _run(
        process_runner,
        workspace,
        ["--root-pass-file", workspace.passphrase_file],
        isolated_environment,
    )

    assert result == ProcessResult(result.args, 1, "", GENERIC_FAILURE)


@pytest.mark.parametrize("case", ("open-mode", "symlink", "hardlink"))
def test_rejects_unsafe_passphrase_files(
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    case: str,
) -> None:
    workspace = rollover_case_factory(f"unsafe-{case}")
    safe = workspace.root / "safe-passphrase"
    selected = workspace.root / "selected-passphrase"
    _write_private(safe, "safe-passphrase-for-testing\n")
    if case == "open-mode":
        selected = safe
        selected.chmod(0o644)
    elif case == "symlink":
        selected.symlink_to(safe)
    else:
        os.link(safe, selected)

    result = _run(
        process_runner,
        workspace,
        ["--root-pass-file", selected],
        isolated_environment,
    )

    assert result.status == 1
    assert result.stdout == ""
    assert "Passphrase file" in result.stderr


def test_rejects_unresolved_journal_before_opening_passphrase(
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = rollover_case_factory("unresolved-journal")
    marker = workspace.pki / "state/rollover/recovery-required"
    _write_private(marker, "transaction=test\n")
    missing = workspace.root / "missing-passphrase"

    result = _run(
        process_runner,
        workspace,
        ["--root-pass-file", missing],
        isolated_environment,
    )

    assert result.status == 1
    assert result.stdout == ""
    assert "PKI recovery is required" in result.stderr
    assert "Passphrase file" not in result.stderr


@pytest.mark.parametrize("journal_kind", ("rollover", "csr"))
def test_recovery_journals_block_before_passphrase_or_key_inspection(
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    executable_directory: Path,
    journal_kind: str,
) -> None:
    workspace = rollover_case_factory(f"blocked-{journal_kind}-journal")
    if journal_kind == "rollover":
        journal = workspace.pki / "state/rollover/journal"
        content = "operation=rollover-prepare\ncommitted=false\n"
        message = "PKI recovery is required"
    else:
        journal = workspace.pki / "state/csr/recovery-journal"
        journal.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        content = "operation=csr-sign\n"
        message = "Authenticated CSR signing recovery is required"
    if journal.exists():
        journal.write_text(content, encoding="utf-8")
        journal.chmod(0o600)
    else:
        _write_private(journal, content)
    pass_marker = workspace.root / "passphrase-inspected"
    key_marker = workspace.root / "key-inspected"
    root_key = workspace.pki / "authorities/roots/g1/private/root-ca.key"
    fake_bin = executable_directory / f"journal-gate-{journal_kind}"
    fake_bin.mkdir(mode=0o700)
    wrapper = fake_bin / "stat"
    wrapper.write_text(
        """#!/usr/bin/env bash
set -euo pipefail
for argument in "$@"; do
  [[ $argument != "$WATCH_PASS" ]] || : >"$PASS_MARKER"
  [[ $argument != "$WATCH_KEY" ]] || : >"$KEY_MARKER"
done
exec "$REAL_STAT" "$@"
""",
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    environment = dict(isolated_environment)
    environment.update(
        PATH=f"{fake_bin}:{environment['PATH']}",
        REAL_STAT=shutil.which("stat", path=isolated_environment["PATH"]) or "",
        WATCH_PASS=os.fspath(workspace.passphrase_file),
        WATCH_KEY=os.fspath(root_key),
        PASS_MARKER=os.fspath(pass_marker),
        KEY_MARKER=os.fspath(key_marker),
    )

    result = _run(
        process_runner,
        workspace,
        ["--root-pass-file", workspace.passphrase_file],
        environment,
    )

    assert result.status == 1
    assert result.stdout == ""
    assert message in result.stderr
    assert not pass_marker.exists()
    assert not key_marker.exists()


def test_rejects_legacy_layout(
    legacy_rollover_case_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = legacy_rollover_case_factory("legacy")
    result = _run(
        process_runner,
        workspace,
        ["--root-pass-file", workspace.passphrase_file],
        isolated_environment,
    )
    assert result.status == 1
    assert result.stdout == ""
    assert "Legacy PKI state requires migration" in result.stderr


def test_rejects_incomplete_generation_layout(
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = rollover_case_factory("partial")
    (workspace.pki / "state/active-issuer").unlink()
    result = _run(
        process_runner,
        workspace,
        ["--root-pass-file", workspace.passphrase_file],
        isolated_environment,
    )
    assert result.status == 1
    assert result.stdout == ""
    assert "PKI state is incomplete or ambiguous" in result.stderr


@pytest.mark.parametrize("lock_name", ("lifecycle", "root", "intermediate"))
def test_honors_standard_ca_lock_boundary(
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    lock_name: str,
) -> None:
    workspace = rollover_case_factory(f"lock-{lock_name}")
    lock = workspace.pki / "locks" / lock_name
    with lock.open("r+", encoding="utf-8") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = _run(
            process_runner,
            workspace,
            ["--root-pass-file", workspace.passphrase_file],
            isolated_environment,
        )

    assert result.status == 1
    assert result.stdout == ""
    assert f"Another {'PKI ' if lock_name == 'lifecycle' else ''}{lock_name}" in result.stderr


def _write_openssl_wrapper(path: Path) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(
        """#!/usr/bin/env bash
set -u
printf '%s\\n' "$@" >>"$OPENSSL_ARGV_LOG"
while IFS= read -r -d '' entry; do
  printf '%s\\n' "$entry"
done </proc/self/environ >>"$OPENSSL_ENV_LOG"
if [[ -n ${RACE_PASS_FILE:-} && $1 == pkey && ! -e $RACE_MARKER ]]; then
  printf '%s\\n' 'replacement-passphrase-for-race' >"$RACE_PASS_FILE.replacement"
  chmod 600 "$RACE_PASS_FILE.replacement"
  mv "$RACE_PASS_FILE.replacement" "$RACE_PASS_FILE"
  : >"$RACE_MARKER"
fi
exec "$REAL_OPENSSL" "$@"
""",
        encoding="utf-8",
    )
    path.chmod(0o755)


def _write_fd_monitor(path: Path) -> None:
    path.write_text(
        """#!/usr/bin/env bash
set -u
name=${0##*/}
pass_count=0
key_count=0
cert_count=0
for descriptor in /proc/self/fd/[0-9]*; do
  [[ -e $descriptor ]] || continue
  IFS=: read -r -a targets <<<"$MONITOR_PASS_FILES"
  for target in "${targets[@]}"; do [[ $descriptor -ef $target ]] && ((pass_count += 1)); done
  IFS=: read -r -a targets <<<"$MONITOR_KEY_FILES"
  for target in "${targets[@]}"; do [[ $descriptor -ef $target ]] && ((key_count += 1)); done
  IFS=: read -r -a targets <<<"$MONITOR_CERT_FILES"
  for target in "${targets[@]}"; do [[ $descriptor -ef $target ]] && ((cert_count += 1)); done
done
expected_pass=0
expected_key=0
expected_cert=0
case $name in
  openssl)
    case ${1:-} in
      pkey) expected_pass=1; expected_key=1 ;;
      x509) expected_cert=1 ;;
      *) printf 'unexpected-openssl-command:%s\\n' "${1:-missing}" >>"$MONITOR_LOG"; exit 97 ;;
    esac
    real=$REAL_OPENSSL
    ;;
  stat)
    for argument in "$@"; do
      [[ $argument == /proc/self/fd/[0-9]* ]] || continue
      IFS=: read -r -a targets <<<"$MONITOR_PASS_FILES"
      for target in "${targets[@]}"; do [[ $argument -ef $target ]] && expected_pass=1; done
      IFS=: read -r -a targets <<<"$MONITOR_KEY_FILES"
      for target in "${targets[@]}"; do [[ $argument -ef $target ]] && expected_key=1; done
      IFS=: read -r -a targets <<<"$MONITOR_CERT_FILES"
      for target in "${targets[@]}"; do [[ $argument -ef $target ]] && expected_cert=1; done
    done
    real=$REAL_STAT
    ;;
  cmp) real=$REAL_CMP ;;
  id) real=$REAL_ID ;;
  rm) real=$REAL_RM ;;
  *) printf 'unexpected-monitor-name:%s\\n' "$name" >>"$MONITOR_LOG"; exit 97 ;;
esac
printf '%s:%s pass=%d key=%d cert=%d expected=%d,%d,%d\\n' \
  "$name" "${1:-}" "$pass_count" "$key_count" "$cert_count" \
  "$expected_pass" "$expected_key" "$expected_cert" >>"$MONITOR_LOG"
if (( pass_count != expected_pass || key_count != expected_key || cert_count != expected_cert )); then
  printf 'unexpected-sensitive-descriptor-inheritance\\n' >>"$MONITOR_LOG"
  exit 97
fi
exec "$real" "$@"
""",
        encoding="utf-8",
    )
    path.chmod(0o755)


def test_openssl_argv_environment_and_output_do_not_disclose_passphrase(
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    executable_directory: Path,
) -> None:
    workspace = rollover_case_factory("non-disclosure")
    secret = workspace.passphrase_file.read_text(encoding="utf-8").strip()
    passphrase = workspace.passphrase_file
    fake_openssl = executable_directory / "openssl"
    argv_log = workspace.root / "openssl.argv"
    env_log = workspace.root / "openssl.env"
    _write_openssl_wrapper(fake_openssl)
    environment = dict(isolated_environment)
    environment.update(
        PATH=f"{fake_openssl.parent}:{environment['PATH']}",
        REAL_OPENSSL=shutil.which("openssl", path=isolated_environment["PATH"]) or "",
        OPENSSL_ARGV_LOG=os.fspath(argv_log),
        OPENSSL_ENV_LOG=os.fspath(env_log),
    )

    result = _run(
        process_runner,
        workspace,
        ["--root-pass-file", passphrase, "--intermediate-pass-file", passphrase],
        environment,
    )

    assert result == ProcessResult(result.args, 0, "root=valid\nintermediate=valid\n", "")
    logged_argv = argv_log.read_text(encoding="utf-8")
    logged_environment = env_log.read_text(encoding="utf-8")
    assert re.search(r"^fd:[0-9]+$", logged_argv, re.MULTILINE)
    assert re.search(r"^/proc/self/fd/[0-9]+$", logged_argv, re.MULTILINE)
    assert secret not in logged_argv
    assert secret not in logged_environment
    assert secret not in result.stdout + result.stderr
    assert os.fspath(passphrase) not in logged_argv


def test_passphrase_replacement_race_uses_descriptor_and_fails_closed(
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    executable_directory: Path,
) -> None:
    workspace = rollover_case_factory("passphrase-race")
    fake_openssl = executable_directory / "openssl"
    argv_log = workspace.root / "race.argv"
    env_log = workspace.root / "race.env"
    marker = workspace.root / "race.marker"
    _write_openssl_wrapper(fake_openssl)
    environment = dict(isolated_environment)
    environment.update(
        PATH=f"{fake_openssl.parent}:{environment['PATH']}",
        REAL_OPENSSL=shutil.which("openssl", path=isolated_environment["PATH"]) or "",
        OPENSSL_ARGV_LOG=os.fspath(argv_log),
        OPENSSL_ENV_LOG=os.fspath(env_log),
        RACE_PASS_FILE=os.fspath(workspace.passphrase_file),
        RACE_MARKER=os.fspath(marker),
    )

    result = _run(
        process_runner,
        workspace,
        ["--root-pass-file", workspace.passphrase_file],
        environment,
    )

    assert marker.is_file()
    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == "[ERROR] CA verification input changed during verification\n"
    assert re.search(
        r"^fd:[0-9]+$", argv_log.read_text(encoding="utf-8"), re.MULTILINE
    )


def test_children_inherit_only_their_required_sensitive_descriptors(
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    executable_directory: Path,
) -> None:
    workspace = rollover_case_factory("descriptor-inheritance")
    fake_bin = executable_directory / "monitored-bin"
    fake_bin.mkdir(mode=0o700)
    for name in ("openssl", "cmp", "stat", "id", "rm"):
        _write_fd_monitor(fake_bin / name)
    log = workspace.root / "descriptor-inheritance.log"
    root_key = workspace.pki / "authorities/roots/g1/private/root-ca.key"
    root_certificate = workspace.pki / "authorities/roots/g1/certs/root-ca.crt"
    intermediate_key = workspace.pki / "authorities/intermediates/g1-i1/private/intermediate-ca.key"
    intermediate_certificate = workspace.pki / "authorities/intermediates/g1-i1/certs/intermediate-ca.crt"
    environment = dict(isolated_environment)
    environment.update(
        PATH=f"{fake_bin}:{environment['PATH']}",
        MONITOR_PASS_FILES=os.fspath(workspace.passphrase_file),
        MONITOR_KEY_FILES=f"{root_key}:{intermediate_key}",
        MONITOR_CERT_FILES=f"{root_certificate}:{intermediate_certificate}",
        MONITOR_LOG=os.fspath(log),
        REAL_OPENSSL=shutil.which("openssl", path=isolated_environment["PATH"])
        or "",
        REAL_CMP=shutil.which("cmp", path=isolated_environment["PATH"]) or "",
        REAL_STAT=shutil.which("stat", path=isolated_environment["PATH"]) or "",
        REAL_ID=shutil.which("id", path=isolated_environment["PATH"]) or "",
        REAL_RM=shutil.which("rm", path=isolated_environment["PATH"]) or "",
    )

    result = _run(
        process_runner,
        workspace,
        ["--root-pass-file", workspace.passphrase_file, "--intermediate-pass-file", workspace.passphrase_file],
        environment,
    )

    assert result == ProcessResult(result.args, 0, "root=valid\nintermediate=valid\n", "")
    observations = log.read_text(encoding="utf-8")
    assert "unexpected-sensitive-descriptor-inheritance" not in observations
    assert "openssl:pkey pass=1 key=1 cert=0 expected=1,1,0" in observations
    assert "openssl:x509 pass=0 key=0 cert=1 expected=0,0,1" in observations
    assert "cmp:-s pass=0 key=0 cert=0 expected=0,0,0" in observations


def test_verification_cleanup_preserves_foreign_replacement(
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    executable_directory: Path,
) -> None:
    workspace = rollover_case_factory("verification-cleanup-race")
    temporary = workspace.root / "verification-tmp"
    temporary.mkdir(mode=0o700)
    foreign = workspace.root / "foreign-verification-directory"
    foreign.mkdir(mode=0o700)
    sentinel = foreign / "sentinel"
    _write_private(sentinel, "foreign verification directory\n")
    sentinel_metadata = sentinel.lstat()
    before = (
        foreign.stat().st_ino,
        sentinel_metadata.st_mode,
        sentinel_metadata.st_uid,
        sentinel_metadata.st_gid,
        sentinel_metadata.st_ino,
        sentinel_metadata.st_size,
        sentinel_metadata.st_mtime_ns,
        sha256(sentinel.read_bytes()).hexdigest(),
    )
    displaced = workspace.root / "displaced-verification-directory"
    counter = workspace.root / "verification-stat.count"
    marker = workspace.root / "verification-race.marker"
    fake_bin = executable_directory / "verification-cleanup-race"
    fake_bin.mkdir(mode=0o700)
    wrapper = fake_bin / "stat"
    wrapper.write_text(
        """#!/usr/bin/env bash
set -euo pipefail
target=${!#}
if [[ ${target%/*} == "$RACE_TMPDIR" && ${target##*/} == platform-pki-ca-passphrase-verify.* ]]; then
  count=0
  [[ ! -f $RACE_COUNTER ]] || read -r count <"$RACE_COUNTER"
  count=$((count + 1))
  printf '%s\n' "$count" >"$RACE_COUNTER"
  if (( count == 2 )); then
    "$REAL_MV" -T -- "$target" "$RACE_DISPLACED"
    "$REAL_MV" -T -- "$RACE_FOREIGN" "$target"
    : >"$RACE_MARKER"
  fi
fi
exec "$REAL_STAT" "$@"
""",
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    environment = dict(isolated_environment)
    environment.update(
        PATH=f"{fake_bin}:{environment['PATH']}",
        TMPDIR=os.fspath(temporary),
        REAL_STAT=shutil.which("stat", path=isolated_environment["PATH"]) or "",
        REAL_MV=shutil.which("mv", path=isolated_environment["PATH"]) or "",
        RACE_TMPDIR=os.fspath(temporary),
        RACE_COUNTER=os.fspath(counter),
        RACE_FOREIGN=os.fspath(foreign),
        RACE_DISPLACED=os.fspath(displaced),
        RACE_MARKER=os.fspath(marker),
    )

    result = _run(
        process_runner,
        workspace,
        ["--root-pass-file", workspace.passphrase_file],
        environment,
    )

    retained = tuple(temporary.glob("platform-pki-ca-passphrase-verify.*"))
    assert len(retained) == 1
    sentinel_metadata = retained[0].joinpath("sentinel").lstat()
    after = (
        retained[0].stat().st_ino,
        sentinel_metadata.st_mode,
        sentinel_metadata.st_uid,
        sentinel_metadata.st_gid,
        sentinel_metadata.st_ino,
        sentinel_metadata.st_size,
        sentinel_metadata.st_mtime_ns,
        sha256((retained[0] / "sentinel").read_bytes()).hexdigest(),
    )
    assert result == ProcessResult(result.args, 1, "root=valid\n", "")
    assert marker.is_file()
    assert displaced.is_dir()
    assert after == before
