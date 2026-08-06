from __future__ import annotations

import os
import shutil
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

from ..harness import ProcessResult
from .support import BIN, assert_result, digest, environment, executable, executable_directory, mode, write_executable, write_private


pytestmark = pytest.mark.pki
INIT = BIN / "platform-pki-init"
TOOL = BIN / "platform-pki-csr-trust-install"
POLICY = """schema=1
request_namespace=platform-pki-csr-request-v1
approval_namespace=platform-pki-csr-approval-v1
response_namespace=platform-pki-csr-response-v1
request_max_age_seconds=604800
sole_operator_min_delay_seconds=86400
approval_max_age_seconds=86400
clock_skew_seconds=300
approver_principal=offline-approver
response_principal=offline-response
"""


def run(process_runner: Callable[..., ProcessResult], env: Mapping[str, str], namespace: Path, private: Path, *arguments: object) -> ProcessResult:
    return process_runner(
        [TOOL, "--namespace", namespace, "--private-repo", private, *arguments],
        env=env,
        timeout=30,
    )


def public_key(process_runner, env, root: Path, name: str) -> str:
    key = root / name
    result = process_runner(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key],
        env=env,
        timeout=30,
    )
    assert_result(result, 0)
    fields = key.with_suffix(".pub").read_text().split()
    return f"{fields[0]} {fields[1]}"


def setup_workspace(tmp_path: Path, process_runner, env) -> tuple[Path, Path, Path]:
    namespace = tmp_path / "namespace"
    assert_result(process_runner([INIT, "--namespace", namespace], env=env, timeout=30), 0)
    private = tmp_path / "platform-private"
    trust = private / "pki/csr-trust"
    trust.mkdir(mode=0o700, parents=True)
    private.chmod(0o700)
    (private / "pki").chmod(0o700)
    keys = tmp_path / "keys"
    keys.mkdir(mode=0o700)
    requester = public_key(process_runner, env, keys, "requester")
    approver = public_key(process_runner, env, keys, "approver")
    response = public_key(process_runner, env, keys, "response")
    write_private(trust / "policy", POLICY)
    write_private(trust / "requesters.allowed_signers", f"host-01 {requester}\n")
    write_private(trust / "approvers.allowed_signers", f"offline-approver {approver}\n")
    write_private(trust / "responses.allowed_signers", f"offline-response {response}\n")
    return namespace, private, keys


def test_install_noop_and_atomic_update(tmp_path, process_runner, isolated_environment) -> None:
    namespace, private, keys = setup_workspace(tmp_path, process_runner, isolated_environment)
    destination = namespace / "pki/inventory/csr-trust"

    result = run(process_runner, isolated_environment, namespace, private)
    assert_result(result, 0, stderr="")
    assert "CSR trust installed:" in result.stdout
    assert sorted(path.name for path in destination.iterdir()) == [
        "approvers.allowed_signers", "policy", "requesters.allowed_signers", "responses.allowed_signers"
    ]
    assert mode(destination) == 0o700
    assert all(mode(path) == 0o600 for path in destination.iterdir())
    inode = destination.stat().st_ino

    result = run(process_runner, isolated_environment, namespace, private)
    assert_result(result, 0, stderr="")
    assert "CSR trust already current:" in result.stdout
    assert destination.stat().st_ino == inode

    replacement = public_key(process_runner, isolated_environment, keys, "requester-new")
    write_private(private / "pki/csr-trust/requesters.allowed_signers", f"host-01 {replacement}\n")
    result = run(process_runner, isolated_environment, namespace, private)
    assert_result(result, 0, stderr="")
    assert "CSR trust updated:" in result.stdout
    assert destination.stat().st_ino != inode
    assert replacement in (destination / "requesters.allowed_signers").read_text()


@pytest.mark.parametrize(
    ("case", "message"),
    (
        pytest.param("options", "no-options Ed25519", id="options"),
        pytest.param("wrong-algorithm", "no-options Ed25519", id="algorithm"),
        pytest.param("wrong-policy", "request maximum age must be 604800", id="policy"),
        pytest.param("extra-file", "must contain exactly policy", id="extra-file"),
        pytest.param("missing-principal", "does not contain required principal", id="principal"),
        pytest.param("duplicate-principal", "contains duplicate principal", id="duplicate-principal"),
        pytest.param("extra-token", "no-options Ed25519", id="extra-token"),
        pytest.param("invalid-key", "invalid Ed25519 public key", id="invalid-key"),
        pytest.param("empty-signers", "bounded ASCII text", id="empty-signers"),
        pytest.param("additional-approver", "exactly the pinned principal", id="additional-approver"),
        pytest.param("additional-response", "exactly the pinned principal", id="additional-response"),
        pytest.param("missing-file", "must contain exactly policy", id="missing-file"),
        pytest.param("non-ascii", "bounded ASCII text", id="non-ascii"),
        pytest.param("no-trailing-newline", "bounded ASCII text", id="no-trailing-newline"),
        pytest.param("blank-line", "bounded ASCII text", id="blank-line"),
        pytest.param("reordered-policy", "schema must be 1", id="reordered-policy"),
    ),
)
def test_invalid_trust_is_rejected_without_replacing_installed_state(tmp_path, process_runner, isolated_environment, case: str, message: str) -> None:
    namespace, private, _ = setup_workspace(tmp_path, process_runner, isolated_environment)
    assert_result(run(process_runner, isolated_environment, namespace, private), 0)
    destination = namespace / "pki/inventory/csr-trust"
    before = {path.name: digest(path) for path in destination.iterdir()}
    trust = private / "pki/csr-trust"
    if case == "options":
        path = trust / "requesters.allowed_signers"
        path.write_text(f'cert-authority {path.read_text()}')
    elif case == "wrong-algorithm":
        (trust / "requesters.allowed_signers").write_text("host-01 ssh-rsa AAAA\n")
    elif case == "wrong-policy":
        path = trust / "policy"
        path.write_text(path.read_text().replace("request_max_age_seconds=604800", "request_max_age_seconds=1"))
    elif case == "extra-file":
        write_private(trust / "extra", "unexpected\n")
    elif case == "missing-principal":
        path = trust / "approvers.allowed_signers"
        path.write_text(path.read_text().replace("offline-approver", "other-approver"))
    elif case == "duplicate-principal":
        path = trust / "requesters.allowed_signers"
        path.write_text(path.read_text() * 2)
    elif case == "extra-token":
        path = trust / "requesters.allowed_signers"
        path.write_text(path.read_text().rstrip() + " comment\n")
    elif case == "invalid-key":
        (trust / "requesters.allowed_signers").write_text("host-01 ssh-ed25519 AAAA\n")
    elif case == "empty-signers":
        (trust / "requesters.allowed_signers").write_text("")
    elif case == "additional-approver":
        path = trust / "approvers.allowed_signers"
        path.write_text(path.read_text() + (trust / "requesters.allowed_signers").read_text())
    elif case == "additional-response":
        path = trust / "responses.allowed_signers"
        path.write_text(path.read_text() + (trust / "requesters.allowed_signers").read_text())
    elif case == "missing-file":
        (trust / "responses.allowed_signers").unlink()
    elif case == "non-ascii":
        path = trust / "requesters.allowed_signers"
        path.write_bytes(path.read_bytes() + b"\xc3\xa9\n")
    elif case == "no-trailing-newline":
        path = trust / "requesters.allowed_signers"
        path.write_text(path.read_text().rstrip("\n"))
    elif case == "blank-line":
        path = trust / "requesters.allowed_signers"
        path.write_text(path.read_text() + "\n")
    else:
        path = trust / "policy"
        lines = path.read_text().splitlines()
        lines[0], lines[1] = lines[1], lines[0]
        path.write_text("\n".join(lines) + "\n")
    for path in trust.iterdir():
        path.chmod(0o600)

    result = run(process_runner, isolated_environment, namespace, private)

    assert result.status == 1
    assert message in result.stderr
    assert {path.name: digest(path) for path in destination.iterdir()} == before


@pytest.mark.parametrize(
    "name",
    ("policy", "requesters.allowed_signers", "approvers.allowed_signers", "responses.allowed_signers"),
)
def test_each_source_replacement_during_staging_is_rejected(
    tmp_path, process_runner, isolated_environment, executable_directory, name: str
) -> None:
    namespace, private, keys = setup_workspace(tmp_path, process_runner, isolated_environment)
    assert_result(run(process_runner, isolated_environment, namespace, private), 0)
    destination = namespace / "pki/inventory/csr-trust"
    before = {path.name: digest(path) for path in destination.iterdir()}
    source = private / "pki/csr-trust" / name
    replacement = tmp_path / f"{name}.replacement"
    if name == "policy":
        write_private(replacement, POLICY)
    else:
        principal = {"requesters.allowed_signers": "host-01", "approvers.allowed_signers": "offline-approver", "responses.allowed_signers": "offline-response"}[name]
        key_name = name.split(".", 1)[0] + "-replacement"
        write_private(replacement, f"{principal} {public_key(process_runner, isolated_environment, keys, key_name)}\n")
    fake_bin = executable_directory / f"replace-{name}"
    write_executable(
        fake_bin / "cp",
        """#!/usr/bin/env bash
set -euo pipefail
"$REAL_CP" "$@"
if [[ ${3:-} == "$RACE_SOURCE" && ! -e $RACE_MARKER ]]; then
  mv -T -- "$RACE_REPLACEMENT" "$RACE_SOURCE"
  : >"$RACE_MARKER"
fi
""",
    )
    marker = tmp_path / f"{name}.marker"

    result = run(
        process_runner,
        environment(
            isolated_environment,
            PATH=f"{fake_bin}:{isolated_environment['PATH']}",
            REAL_CP=executable("cp"),
            RACE_SOURCE=os.fspath(source),
            RACE_REPLACEMENT=os.fspath(replacement),
            RACE_MARKER=os.fspath(marker),
        ),
        namespace,
        private,
    )

    assert result.status == 1
    assert marker.is_file()
    assert "CSR trust source directory changed during installation" in result.stderr
    assert {path.name: digest(path) for path in destination.iterdir()} == before
    assert not tuple((namespace / "pki/inventory").glob(".platform-pki-csr-trust.*"))


def test_public_key_validation_cleanup_preserves_foreign_replacement(
    tmp_path, process_runner, isolated_environment, executable_directory
) -> None:
    namespace, private, _ = setup_workspace(tmp_path, process_runner, isolated_environment)
    temporary = tmp_path / "public-key-validation-tmp"
    temporary.mkdir(mode=0o700)
    foreign = tmp_path / "foreign-public-key-validation"
    write_private(foreign, "foreign public key validation file\n")
    metadata = foreign.lstat()
    before = (metadata.st_mode, metadata.st_uid, metadata.st_gid, metadata.st_ino, metadata.st_nlink, metadata.st_size, metadata.st_mtime_ns, digest(foreign))
    displaced = tmp_path / "displaced-public-key-validation"
    marker = tmp_path / "public-key-validation-race.marker"
    fake_bin = executable_directory / "public-key-validation-race"
    write_executable(
        fake_bin / "ssh-keygen",
        """#!/usr/bin/env bash
set -u
"$REAL_SSH_KEYGEN" "$@"
status=$?
target=''
for ((index = 1; index <= $#; index++)); do
  if [[ ${!index} == -f ]]; then next=$((index + 1)); target=${!next}; break; fi
done
if [[ ${target%/*} == "$RACE_TMPDIR" && ${target##*/} == platform-pki-csr-public-key.* && ! -e $RACE_MARKER ]]; then
  "$REAL_MV" -T -- "$target" "$RACE_DISPLACED"
  "$REAL_MV" -T -- "$RACE_FOREIGN" "$target"
  : >"$RACE_MARKER"
fi
exit "$status"
""",
    )

    result = run(
        process_runner,
        environment(
            isolated_environment,
            PATH=f"{fake_bin}:{isolated_environment['PATH']}",
            TMPDIR=os.fspath(temporary),
            REAL_SSH_KEYGEN=executable("ssh-keygen"),
            REAL_MV=executable("mv"),
            RACE_TMPDIR=os.fspath(temporary),
            RACE_FOREIGN=os.fspath(foreign),
            RACE_DISPLACED=os.fspath(displaced),
            RACE_MARKER=os.fspath(marker),
        ),
        namespace,
        private,
    )

    retained = tuple(temporary.glob("platform-pki-csr-public-key.*"))
    assert len(retained) == 1
    metadata = retained[0].lstat()
    after = (metadata.st_mode, metadata.st_uid, metadata.st_gid, metadata.st_ino, metadata.st_nlink, metadata.st_size, metadata.st_mtime_ns, digest(retained[0]))
    assert result.status == 1
    assert "CSR trust public-key validation file changed before cleanup" in result.stderr
    assert marker.is_file()
    assert displaced.is_file()
    assert after == before
    assert not (namespace / "pki/inventory/csr-trust").exists()


def test_installed_destination_replacement_before_exchange_is_rejected(
    tmp_path, process_runner, isolated_environment, executable_directory
) -> None:
    namespace, private, keys = setup_workspace(tmp_path, process_runner, isolated_environment)
    assert_result(run(process_runner, isolated_environment, namespace, private), 0)
    inventory = namespace / "pki/inventory"
    destination = inventory / "csr-trust"
    replacement = tmp_path / "destination-replacement"
    displaced = tmp_path / "destination-displaced"
    shutil.copytree(destination, replacement, copy_function=shutil.copy2)
    new_key = public_key(process_runner, isolated_environment, keys, "requester-destination-race")
    write_private(private / "pki/csr-trust/requesters.allowed_signers", f"host-01 {new_key}\n")
    fake_bin = executable_directory / "destination-race"
    marker = tmp_path / "destination-race.marker"
    write_executable(
        fake_bin / "cmp",
        """#!/usr/bin/env bash
set -euo pipefail
if [[ ! -e $RACE_MARKER ]]; then
  mv -T -- "$RACE_DESTINATION" "$RACE_DISPLACED"
  mv -T -- "$RACE_REPLACEMENT" "$RACE_DESTINATION"
  : >"$RACE_MARKER"
fi
exec "$REAL_CMP" "$@"
""",
    )

    result = run(
        process_runner,
        environment(
            isolated_environment,
            PATH=f"{fake_bin}:{isolated_environment['PATH']}",
            REAL_CMP=executable("cmp"),
            RACE_DESTINATION=os.fspath(destination),
            RACE_DISPLACED=os.fspath(displaced),
            RACE_REPLACEMENT=os.fspath(replacement),
            RACE_MARKER=os.fspath(marker),
        ),
        namespace,
        private,
    )

    assert result.status == 1
    assert marker.is_file()
    assert "Installed CSR trust changed before publication" in result.stderr
    assert new_key not in (destination / "requesters.allowed_signers").read_text()
    assert not tuple(inventory.glob(".platform-pki-csr-trust.*"))


def test_destination_replacement_at_exchange_is_preserved(
    tmp_path, process_runner, isolated_environment, executable_directory
) -> None:
    namespace, private, keys = setup_workspace(tmp_path, process_runner, isolated_environment)
    assert_result(run(process_runner, isolated_environment, namespace, private), 0)
    inventory = namespace / "pki/inventory"
    destination = inventory / "csr-trust"
    displaced = tmp_path / "destination-displaced-at-exchange"
    foreign = tmp_path / "foreign-destination"
    shutil.copytree(destination, foreign, copy_function=shutil.copy2)
    write_private(foreign / "foreign-owned", "must survive failed exchange\n")
    foreign_inode = foreign.stat().st_ino
    new_key = public_key(process_runner, isolated_environment, keys, "requester-exchange-race")
    write_private(private / "pki/csr-trust/requesters.allowed_signers", f"host-01 {new_key}\n")
    fake_bin = executable_directory / "exchange-destination-race"
    marker = tmp_path / "exchange-destination-race.marker"
    write_executable(
        fake_bin / "mv",
        """#!/usr/bin/env bash
set -euo pipefail
if [[ $* == *--exchange* && ! -e $RACE_MARKER ]]; then
  "$REAL_MV" -T -- "$RACE_DESTINATION" "$RACE_DISPLACED"
  "$REAL_MV" -T -- "$RACE_FOREIGN" "$RACE_DESTINATION"
  : >"$RACE_MARKER"
fi
exec "$REAL_MV" "$@"
""",
    )

    result = run(
        process_runner,
        environment(
            isolated_environment,
            PATH=f"{fake_bin}:{isolated_environment['PATH']}",
            REAL_MV=executable("mv"),
            RACE_DESTINATION=os.fspath(destination),
            RACE_DISPLACED=os.fspath(displaced),
            RACE_FOREIGN=os.fspath(foreign),
            RACE_MARKER=os.fspath(marker),
        ),
        namespace,
        private,
    )

    retained = tuple(inventory.glob(".platform-pki-csr-trust.*"))
    assert result.status == 1
    assert result.stdout == ""
    assert "CSR trust exchange identity check failed" in result.stderr
    assert marker.is_file()
    assert displaced.is_dir()
    assert len(retained) == 1
    assert retained[0].stat().st_ino == foreign_inode
    assert (retained[0] / "foreign-owned").read_text() == "must survive failed exchange\n"
    assert new_key in (destination / "requesters.allowed_signers").read_text()


@pytest.mark.parametrize("case", ("exchange-after-mutation", "post-publication-fsync", "cleanup"))
def test_update_interruptions_leave_one_complete_trust_tree(
    tmp_path, process_runner, isolated_environment, executable_directory, case: str
) -> None:
    namespace, private, keys = setup_workspace(tmp_path, process_runner, isolated_environment)
    assert_result(run(process_runner, isolated_environment, namespace, private), 0)
    inventory = namespace / "pki/inventory"
    destination = inventory / "csr-trust"
    prior_requester = (destination / "requesters.allowed_signers").read_text()
    new_key = public_key(process_runner, isolated_environment, keys, f"requester-{case}")
    write_private(private / "pki/csr-trust/requesters.allowed_signers", f"host-01 {new_key}\n")
    fake_bin = executable_directory / f"interruption-{case}"
    marker = tmp_path / f"{case}.marker"
    environment_values: dict[str, str] = {
        "PATH": f"{fake_bin}:{isolated_environment['PATH']}",
        "RACE_MARKER": os.fspath(marker),
    }
    if case == "exchange-after-mutation":
        write_executable(
            fake_bin / "mv",
            """#!/usr/bin/env bash
set -euo pipefail
if [[ $* == *--exchange* && ! -e $RACE_MARKER ]]; then
  "$REAL_MV" "$@"
  : >"$RACE_MARKER"
  exit 42
fi
exec "$REAL_MV" "$@"
""",
        )
        environment_values["REAL_MV"] = executable("mv")
    elif case == "post-publication-fsync":
        counter = tmp_path / "sync.counter"
        write_executable(
            fake_bin / "sync",
            """#!/usr/bin/env bash
set -euo pipefail
if [[ ${!#} == "$RACE_INVENTORY" ]]; then
  count=0
  [[ ! -f $RACE_COUNTER ]] || read -r count <"$RACE_COUNTER"
  count=$((count + 1))
  printf '%s\n' "$count" >"$RACE_COUNTER"
  if (( count == 2 )); then : >"$RACE_MARKER"; exit 42; fi
fi
exec "$REAL_SYNC" "$@"
""",
        )
        environment_values.update(
            REAL_SYNC=executable("sync"),
            RACE_INVENTORY=os.fspath(inventory),
            RACE_COUNTER=os.fspath(counter),
        )
    else:
        write_executable(
            fake_bin / "rm",
            """#!/usr/bin/env bash
set -euo pipefail
if [[ $* == *'.platform-pki-csr-trust.'* && ! -e $RACE_MARKER ]]; then
  : >"$RACE_MARKER"
  exit 42
fi
exec "$REAL_RM" "$@"
""",
        )
        environment_values["REAL_RM"] = executable("rm")

    result = run(
        process_runner,
        environment(isolated_environment, **environment_values),
        namespace,
        private,
    )

    assert result.status == 1
    assert marker.is_file()
    assert sorted(path.name for path in destination.iterdir()) == [
        "approvers.allowed_signers", "policy", "requesters.allowed_signers", "responses.allowed_signers"
    ]
    assert new_key in (destination / "requesters.allowed_signers").read_text()
    retained = tuple(inventory.glob(".platform-pki-csr-trust.*"))
    assert len(retained) == 1
    assert sorted(path.name for path in retained[0].iterdir()) == [
        "approvers.allowed_signers", "policy", "requesters.allowed_signers", "responses.allowed_signers"
    ]
    assert (retained[0] / "requesters.allowed_signers").read_text() == prior_requester


@pytest.mark.parametrize("case", ("symlink", "hardlink", "writable"))
def test_unsafe_source_is_rejected(tmp_path, process_runner, isolated_environment, case: str) -> None:
    namespace, private, _ = setup_workspace(tmp_path, process_runner, isolated_environment)
    source = private / "pki/csr-trust/requesters.allowed_signers"
    if case == "symlink":
        target = source.with_name("requesters.real")
        source.rename(target)
        source.symlink_to(target)
    elif case == "hardlink":
        os.link(source, source.with_name("requesters.link"))
    else:
        source.chmod(0o622)

    result = run(process_runner, isolated_environment, namespace, private)

    assert result.status == 1
    assert not (namespace / "pki/inventory/csr-trust").exists()


def test_failed_exchange_preserves_installed_trust(tmp_path, process_runner, isolated_environment, executable_directory) -> None:
    namespace, private, keys = setup_workspace(tmp_path, process_runner, isolated_environment)
    assert_result(run(process_runner, isolated_environment, namespace, private), 0)
    destination = namespace / "pki/inventory/csr-trust"
    before = digest(destination / "requesters.allowed_signers")
    replacement = public_key(process_runner, isolated_environment, keys, "requester-failure")
    write_private(private / "pki/csr-trust/requesters.allowed_signers", f"host-01 {replacement}\n")
    fake_bin = executable_directory / "exchange-failure"
    write_executable(fake_bin / "mv", """#!/usr/bin/env bash
if [[ $* == *--exchange* ]]; then exit 42; fi
exec "$REAL_MV" "$@"
""")

    result = run(
        process_runner,
        environment(isolated_environment, PATH=f"{fake_bin}:{isolated_environment['PATH']}", REAL_MV=executable("mv")),
        namespace,
        private,
    )

    assert result.status == 1
    assert digest(destination / "requesters.allowed_signers") == before
    assert not tuple((namespace / "pki/inventory").glob(".platform-pki-csr-trust.*"))


def test_source_change_during_staging_is_rejected(tmp_path, process_runner, isolated_environment, executable_directory) -> None:
    namespace, private, _ = setup_workspace(tmp_path, process_runner, isolated_environment)
    assert_result(run(process_runner, isolated_environment, namespace, private), 0)
    destination = namespace / "pki/inventory/csr-trust"
    before = {path.name: digest(path) for path in destination.iterdir()}
    source = private / "pki/csr-trust/requesters.allowed_signers"
    fake_bin = executable_directory / "source-race"
    write_executable(fake_bin / "cp", """#!/usr/bin/env bash
"$REAL_CP" "$@"
status=$?
if (( status == 0 )) && [[ ${3:-} == "$RACE_SOURCE" ]]; then chmod 622 -- "$RACE_SOURCE"; fi
exit "$status"
""")

    result = run(
        process_runner,
        environment(
            isolated_environment,
            PATH=f"{fake_bin}:{isolated_environment['PATH']}",
            RACE_SOURCE=str(source),
            REAL_CP=executable("cp"),
        ),
        namespace,
        private,
    )

    assert result.status == 1
    assert "CSR trust source changed during installation: requesters.allowed_signers" in result.stderr
    assert {path.name: digest(path) for path in destination.iterdir()} == before
    assert not tuple((namespace / "pki/inventory").glob(".platform-pki-csr-trust.*"))


def test_unsafe_installed_trust_is_not_replaced(tmp_path, process_runner, isolated_environment) -> None:
    namespace, private, keys = setup_workspace(tmp_path, process_runner, isolated_environment)
    assert_result(run(process_runner, isolated_environment, namespace, private), 0)
    destination = namespace / "pki/inventory/csr-trust"
    installed = destination / "requesters.allowed_signers"
    installed.chmod(0o644)
    before = digest(installed)
    replacement = public_key(process_runner, isolated_environment, keys, "requester-unsafe-destination")
    write_private(private / "pki/csr-trust/requesters.allowed_signers", f"host-01 {replacement}\n")

    result = run(process_runner, isolated_environment, namespace, private)

    assert result.status == 1
    assert f"Installed CSR trust file is unsafe: {installed}" in result.stderr
    assert digest(installed) == before
    assert mode(installed) == 0o644
