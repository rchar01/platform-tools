from __future__ import annotations

import fcntl
import hashlib
import os
import shutil
import stat
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

from ..harness import ProcessResult
from .support import BIN, REPOSITORY, assert_result, digest, environment, executable, executable_directory, mode, write_executable, write_private
from .test_csr_candidate import POLICY2, REQUEST_ID, configure_deployer_trust, decide, prepare, publish_request
from .test_csr_signing import (
    EXPORT as ANSIBLE_EXPORT,
    INVENTORY,
    ISSUE,
    CsrWorkspace,
    RENEW,
    csr_workspace,
    write_exchange,
)


pytestmark = pytest.mark.pki
INIT = BIN / "platform-pki-init"
TOOL = BIN / "platform-pki-csr-trust-install"
ORACLE_ROOT = REPOSITORY / "tests/pki/oracles/platform-pki-csr-trust-install"
ORACLE_COMMIT = "678daa6de2ea24ada1fd36199013347f79f303bf"
ORACLE_HASHES = {
    "platform-pki-csr-trust-install": "280333e79c824ea6d1d4f159c36d6cf8573d6a13fd985144f7ba0b0b4fbefa40",
    "lib/platform-pki-common.sh": "dee644be8ab6236cb368a553493f55b53a90c3aead291550f7e635c080a5494f",
    "lib/platform-pki-csr-sign.sh": "8659a730f91c592c12fa3d40acbb080cf10d3eff6bd2de38fa486e8055f3e001",
    "lib/platform-pki-csr-candidate.sh": "ca1fb976f09730fbbc840ce97cb0c6db3ae76e5d679fdc777a1a96d80df5b43f",
}
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


def test_frozen_trust_install_oracle_matches_provenance_and_modes() -> None:
    plan = (REPOSITORY / "docs/plans/platform-pki-python-migration.md").read_text(
        encoding="utf-8"
    )
    assert ORACLE_COMMIT in plan
    assert {
        path.relative_to(ORACLE_ROOT).as_posix()
        for path in ORACLE_ROOT.rglob("*")
    } == {"lib", *ORACLE_HASHES}
    for relative, expected in ORACLE_HASHES.items():
        path = ORACLE_ROOT / relative
        assert path.is_file() and not path.is_symlink()
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected
        expected_mode = 0o644 if relative.startswith("lib/") else 0o755
        assert stat.S_IMODE(path.stat().st_mode) == expected_mode
        if expected_mode == 0o755:
            assert os.access(path, os.X_OK)


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


def test_noop_rechecks_each_installed_trust_file(
    tmp_path, process_runner, isolated_environment, executable_directory
) -> None:
    namespace, private, _ = setup_workspace(
        tmp_path, process_runner, isolated_environment
    )
    assert_result(run(process_runner, isolated_environment, namespace, private), 0)
    installed = namespace / "pki/inventory/csr-trust/responses.allowed_signers"
    fake_bin = executable_directory / "noop-installed-race"
    marker = tmp_path / "noop-installed-race.marker"
    write_executable(
        fake_bin / "cmp",
        """#!/usr/bin/env bash
set -u
"$REAL_CMP" "$@"
status=$?
if (( status == 0 )) && [[ ${!#} == "$RACE_INSTALLED" && ! -e $RACE_MARKER ]]; then
  printf '\n' >>"$RACE_INSTALLED"
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
            REAL_CMP=executable("cmp"),
            RACE_INSTALLED=os.fspath(installed),
            RACE_MARKER=os.fspath(marker),
        ),
        namespace,
        private,
    )

    assert result.status == 1
    assert marker.is_file()
    assert "CSR trust already current:" not in result.stdout


def test_update_rechecks_installed_trust_after_final_state_digest(
    csr_workspace: CsrWorkspace, executable_directory, tmp_path
) -> None:
    workspace = csr_workspace
    artifact, manifest_digest = prepare(workspace)
    assert_result(
        decide(
            workspace,
            REQUEST_ID,
            artifact,
            manifest_digest,
            action="finalize",
            result="activated",
        ),
        0,
    )
    destination = workspace.pki / "inventory/csr-trust"
    destination_inode = destination.stat().st_ino
    deployer_before = digest(destination / "deployers.allowed_signers")
    installed = destination / "responses.allowed_signers"
    replace_deployer_trust(workspace)
    fake_bin = executable_directory / "update-installed-race"
    marker = tmp_path / "update-installed-race.marker"
    write_executable(
        fake_bin / "sha256sum",
        """#!/usr/bin/env bash
set -euo pipefail
if (( $# == 0 )) && [[ ! -e $RACE_MARKER ]]; then
  printf '\n' >>"$RACE_INSTALLED"
  : >"$RACE_MARKER"
fi
exec "$REAL_SHA256SUM" "$@"
""",
    )

    result = run(
        workspace.runner,
        environment(
            workspace.env,
            PATH=f"{fake_bin}:{workspace.env['PATH']}",
            REAL_SHA256SUM=executable("sha256sum"),
            RACE_INSTALLED=os.fspath(installed),
            RACE_MARKER=os.fspath(marker),
        ),
        workspace.namespace,
        workspace.private,
    )

    assert result.status == 1
    assert marker.is_file()
    assert destination.stat().st_ino == destination_inode
    assert digest(destination / "deployers.allowed_signers") == deployer_before


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


@pytest.mark.parametrize(
    ("name", "label"),
    (
        pytest.param("lifecycle", "PKI lifecycle operation", id="lifecycle"),
        pytest.param("root", "root CA operation", id="root"),
        pytest.param("intermediate", "intermediate CA operation", id="intermediate"),
        pytest.param("inventory", "inventory operation", id="inventory"),
    ),
)
def test_each_operation_lock_blocks_installation(
    tmp_path, process_runner, isolated_environment, name: str, label: str
) -> None:
    namespace, private, _ = setup_workspace(
        tmp_path, process_runner, isolated_environment
    )
    lock_path = namespace / f"pki/locks/{name}"
    with lock_path.open("a+") as lock:
        lock_path.chmod(0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = run(
            process_runner, isolated_environment, namespace, private
        )

    assert result.status == 1
    assert f"Another {label} is in progress: {lock_path}" in result.stderr
    assert not (namespace / "pki/inventory/csr-trust").exists()


@pytest.mark.parametrize("case", ("success", "failure"))
def test_operation_locks_are_released_in_reverse_order(
    tmp_path,
    process_runner,
    isolated_environment,
    executable_directory,
    case: str,
) -> None:
    namespace, private, _ = setup_workspace(
        tmp_path, process_runner, isolated_environment
    )
    if case == "failure":
        assert_result(
            run(process_runner, isolated_environment, namespace, private), 0
        )
        (namespace / "pki/inventory/csr-trust/policy").chmod(0o644)
    fake_bin = executable_directory / f"flock-release-{case}"
    log = tmp_path / f"flock-release-{case}.log"
    write_executable(
        fake_bin / "flock",
        """#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$FLOCK_LOG"
exec "$REAL_FLOCK" "$@"
""",
    )
    result = run(
        process_runner,
        environment(
            isolated_environment,
            PATH=f"{fake_bin}:{isolated_environment['PATH']}",
            FLOCK_LOG=os.fspath(log),
            REAL_FLOCK=executable("flock"),
        ),
        namespace,
        private,
    )

    assert result.status == (0 if case == "success" else 1)
    calls = log.read_text().splitlines()
    acquired = [call.removeprefix("-n ") for call in calls if call.startswith("-n ")]
    released = [call.removeprefix("-u ") for call in calls if call.startswith("-u ")]
    assert len(acquired) == 4
    assert released == list(reversed(acquired))


def test_root_contention_explicitly_releases_lifecycle_lock(
    tmp_path, process_runner, isolated_environment, executable_directory
) -> None:
    namespace, private, _ = setup_workspace(
        tmp_path, process_runner, isolated_environment
    )
    root_lock = namespace / "pki/locks/root"
    fake_bin = executable_directory / "flock-root-contention"
    log = tmp_path / "flock-root-contention.log"
    write_executable(
        fake_bin / "flock",
        """#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$FLOCK_LOG"
exec "$REAL_FLOCK" "$@"
""",
    )
    with root_lock.open("a+") as lock:
        root_lock.chmod(0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = run(
            process_runner,
            environment(
                isolated_environment,
                PATH=f"{fake_bin}:{isolated_environment['PATH']}",
                FLOCK_LOG=os.fspath(log),
                REAL_FLOCK=executable("flock"),
            ),
            namespace,
            private,
        )

    assert result.status == 1
    calls = log.read_text().splitlines()
    acquired = [call.removeprefix("-n ") for call in calls if call.startswith("-n ")]
    released = [call.removeprefix("-u ") for call in calls if call.startswith("-u ")]
    assert len(acquired) == 2
    assert released == [acquired[0]]


def replace_deployer_trust(workspace: CsrWorkspace) -> None:
    fields = workspace.response_key.with_suffix(".pub").read_text().split()
    write_private(
        workspace.private / "pki/csr-trust/deployers.allowed_signers",
        f"host-01 {fields[0]} {fields[1]}\n",
    )


def test_initial_schema_two_install_succeeds_without_candidate_state(
    tmp_path, process_runner, isolated_environment
) -> None:
    namespace, private, keys = setup_workspace(
        tmp_path, process_runner, isolated_environment
    )
    trust = private / "pki/csr-trust"
    fields = (keys / "requester.pub").read_text().split()
    write_private(trust / "policy", POLICY2)
    write_private(
        trust / "deployers.allowed_signers",
        f"host-01 {fields[0]} {fields[1]}\n",
    )

    result = run(process_runner, isolated_environment, namespace, private)

    assert_result(result, 0)
    assert "CSR trust installed:" in result.stdout


def test_initial_schema_two_install_and_pending_exact_noop(
    csr_workspace: CsrWorkspace,
) -> None:
    workspace = csr_workspace
    configure_deployer_trust(workspace)
    result = run(
        workspace.runner, workspace.env, workspace.namespace, workspace.private
    )
    assert_result(result, 0)
    assert "CSR trust updated:" in result.stdout
    assert_result(workspace.issue(), 0)

    result = run(
        workspace.runner, workspace.env, workspace.namespace, workspace.private
    )

    assert_result(result, 0)
    assert "CSR trust already current:" in result.stdout


@pytest.mark.parametrize(
    "transition", ("schema-one-to-two", "schema-two-update", "schema-two-to-one")
)
def test_pending_candidate_blocks_actual_schema_two_trust_change(
    csr_workspace: CsrWorkspace, transition: str
) -> None:
    workspace = csr_workspace
    if transition != "schema-one-to-two":
        configure_deployer_trust(workspace)
        assert_result(
            run(
                workspace.runner,
                workspace.env,
                workspace.namespace,
                workspace.private,
            ),
            0,
        )
    assert_result(workspace.issue(), 0)
    if transition == "schema-one-to-two":
        configure_deployer_trust(workspace)
    elif transition == "schema-two-update":
        replace_deployer_trust(workspace)
    else:
        trust = workspace.private / "pki/csr-trust"
        (trust / "deployers.allowed_signers").unlink()
        write_private(trust / "policy", POLICY)

    result = run(
        workspace.runner, workspace.env, workspace.namespace, workspace.private
    )

    assert result.status == 1
    assert f"pending candidate: external/{REQUEST_ID}" in result.stderr


@pytest.mark.parametrize(
    ("action", "result_name"),
    (
        pytest.param("finalize", "activated", id="finalized"),
        pytest.param("abandon", "not-activated", id="abandoned"),
    ),
)
def test_authenticated_terminal_history_allows_schema_two_rotation(
    csr_workspace: CsrWorkspace,
    action: str,
    result_name: str,
) -> None:
    workspace = csr_workspace
    artifact, manifest_digest = prepare(workspace)
    assert_result(
        decide(
            workspace,
            REQUEST_ID,
            artifact,
            manifest_digest,
            action=action,
            result=result_name,
        ),
        0,
    )
    replace_deployer_trust(workspace)

    result = run(
        workspace.runner, workspace.env, workspace.namespace, workspace.private
    )

    assert_result(result, 0)
    assert "CSR trust updated:" in result.stdout


def test_terminal_history_fails_closed_without_current_inventory_binding(
    csr_workspace: CsrWorkspace,
) -> None:
    workspace = csr_workspace
    artifact, manifest_digest = prepare(workspace)
    assert_result(
        decide(
            workspace,
            REQUEST_ID,
            artifact,
            manifest_digest,
            action="finalize",
            result="activated",
        ),
        0,
    )
    write_private(
        workspace.pki / "inventory/services.yml",
        "services:\n"
        "  other:\n"
        "    common_name: other.example.internal\n"
        "    dns:\n"
        "      - other.example.internal\n",
    )
    replace_deployer_trust(workspace)

    result = run(
        workspace.runner, workspace.env, workspace.namespace, workspace.private
    )

    assert result.status == 1
    assert "is not defined" in result.stderr


def test_superseded_terminal_history_allows_schema_two_rotation(
    csr_workspace: CsrWorkspace,
) -> None:
    workspace = csr_workspace
    first_artifact, first_manifest = prepare(workspace)
    assert_result(
        decide(
            workspace,
            REQUEST_ID,
            first_artifact,
            first_manifest,
            action="finalize",
            result="activated",
        ),
        0,
    )
    renewal_id = "2123456789abcdef0123456789abcdef"
    current = first_artifact / "tls.crt"
    write_exchange(workspace, "renew", renewal_id, "cd" * 32, digest(current))
    assert_result(workspace.sign(RENEW, current_cert=current), 0)
    renewal_artifact, renewal_manifest = publish_request(workspace, renewal_id)
    assert_result(
        decide(
            workspace,
            renewal_id,
            renewal_artifact,
            renewal_manifest,
            action="finalize",
            result="activated",
        ),
        0,
    )
    replace_deployer_trust(workspace)

    result = run(
        workspace.runner, workspace.env, workspace.namespace, workspace.private
    )

    assert_result(result, 0)
    assert "CSR trust updated:" in result.stdout


def prepare_terminal_migration(workspace: CsrWorkspace) -> None:
    managed_inventory = INVENTORY.replace(
        "    key_custody: host-local\n"
        "    target: host-01\n"
        "    validation_boundary_sha256: " + "0" * 64 + "\n"
        "    rollback_hold_seconds: 3600\n",
        "",
    )
    write_private(workspace.pki / "inventory/services.yml", managed_inventory)
    assert_result(
        workspace.runner(
            [
                ISSUE,
                "external",
                "--namespace",
                workspace.namespace,
                "--intermediate-pass-file",
                workspace.intermediate_pass,
            ],
            env=workspace.env,
            timeout=120,
        ),
        0,
    )
    certificate = workspace.pki / "services/external/certs/tls.crt"
    assert_result(
        workspace.runner(
            [
                ANSIBLE_EXPORT,
                "external",
                "--namespace",
                workspace.namespace,
                "--force",
            ],
            env=workspace.env,
            timeout=120,
        ),
        0,
    )
    write_private(workspace.pki / "inventory/services.yml", INVENTORY)
    migration_id = "1123456789abcdef0123456789abcdef"
    write_exchange(
        workspace, "migrate", migration_id, "bc" * 32, digest(certificate)
    )
    configure_deployer_trust(workspace)
    assert_result(
        run(
            workspace.runner,
            workspace.env,
            workspace.namespace,
            workspace.private,
        ),
        0,
    )
    assert_result(workspace.issue(), 0)
    artifact, manifest_digest = publish_request(workspace, migration_id)
    assert_result(
        decide(
            workspace,
            migration_id,
            artifact,
            manifest_digest,
            action="finalize",
            result="activated",
        ),
        0,
    )


def test_terminal_migration_history_allows_rotation_with_preserved_state(
    csr_workspace: CsrWorkspace,
) -> None:
    workspace = csr_workspace
    prepare_terminal_migration(workspace)
    replace_deployer_trust(workspace)

    result = run(
        workspace.runner, workspace.env, workspace.namespace, workspace.private
    )

    assert_result(result, 0)
    assert "CSR trust updated:" in result.stdout


def test_migration_history_is_rechecked_at_publication_boundary(
    csr_workspace: CsrWorkspace,
    executable_directory,
    tmp_path,
) -> None:
    workspace = csr_workspace
    prepare_terminal_migration(workspace)
    destination = workspace.pki / "inventory/csr-trust"
    before = digest(destination / "deployers.allowed_signers")
    replace_deployer_trust(workspace)
    fake_bin = executable_directory / "migration-history-race"
    gate_marker = tmp_path / "migration-history-race.gate"
    marker = tmp_path / "migration-history-race.marker"
    write_executable(
        fake_bin / "ssh-keygen",
        """#!/usr/bin/env bash
set -euo pipefail
if [[ $* == *platform-pki-csr-deployment-v1* && ! -e $RACE_GATE_MARKER ]]; then
  : >"$RACE_GATE_MARKER"
elif [[ -e $RACE_GATE_MARKER && ! -e $RACE_MARKER ]]; then
  printf '\n' >>"$RACE_MANAGED_CERTIFICATE"
  : >"$RACE_MARKER"
fi
exec "$REAL_SSH_KEYGEN" "$@"
""",
    )

    result = run(
        workspace.runner,
        environment(
            workspace.env,
            PATH=f"{fake_bin}:{workspace.env['PATH']}",
            REAL_SSH_KEYGEN=executable("ssh-keygen"),
            RACE_GATE_MARKER=os.fspath(gate_marker),
            RACE_MARKER=os.fspath(marker),
            RACE_MANAGED_CERTIFICATE=os.fspath(
                workspace.pki / "services/external/certs/tls.crt"
            ),
        ),
        workspace.namespace,
        workspace.private,
    )

    assert result.status == 1
    assert marker.is_file()
    assert digest(destination / "deployers.allowed_signers") == before


@pytest.mark.parametrize("tamper", ("outcome", "active-pointer"))
def test_tampered_terminal_state_blocks_schema_two_rotation(
    csr_workspace: CsrWorkspace, tamper: str
) -> None:
    workspace = csr_workspace
    artifact, manifest_digest = prepare(workspace)
    assert_result(
        decide(
            workspace,
            REQUEST_ID,
            artifact,
            manifest_digest,
            action="finalize",
            result="activated",
        ),
        0,
    )
    if tamper == "outcome":
        decision = workspace.pki / f"state/csr/outcomes/external/{REQUEST_ID}/decision"
        decision.write_text(
            decision.read_text().replace("state=finalized\n", "state=abandoned\n")
        )
    else:
        active = workspace.pki / "state/csr/active/external"
        active.write_text(
            active.read_text().replace(
                f"request_id={REQUEST_ID}\n", "request_id=" + "f" * 32 + "\n"
            )
        )
    replace_deployer_trust(workspace)

    result = run(
        workspace.runner, workspace.env, workspace.namespace, workspace.private
    )

    assert result.status == 1
    assert "CSR trust updated:" not in result.stdout


@pytest.mark.parametrize(
    "race",
    (
        "staged-trust",
        "retained-request",
        "post-gate-state",
        "post-gate-inventory",
    ),
)
def test_candidate_gate_rechecks_staged_trust_and_retained_history(
    csr_workspace: CsrWorkspace,
    executable_directory,
    tmp_path,
    race: str,
) -> None:
    workspace = csr_workspace
    artifact, manifest_digest = prepare(workspace)
    assert_result(
        decide(
            workspace,
            REQUEST_ID,
            artifact,
            manifest_digest,
            action="finalize",
            result="activated",
        ),
        0,
    )
    destination = workspace.pki / "inventory/csr-trust"
    before = digest(destination / "deployers.allowed_signers")
    replace_deployer_trust(workspace)
    fake_bin = executable_directory / f"candidate-gate-race-{race}"
    marker = tmp_path / f"candidate-gate-race-{race}.marker"
    gate_marker = tmp_path / f"candidate-gate-race-{race}.gate"
    write_executable(
        fake_bin / "ssh-keygen",
        """#!/usr/bin/env bash
set -euo pipefail
if [[ $RACE_KIND == post-gate-* && $* == *platform-pki-csr-deployment-v1* && ! -e $RACE_GATE_MARKER ]]; then
  : >"$RACE_GATE_MARKER"
elif [[ $RACE_KIND == post-gate-* && -e $RACE_GATE_MARKER && ! -e $RACE_MARKER ]]; then
  if [[ $RACE_KIND == post-gate-state ]]; then
    mkdir -m 700 -- "$RACE_PKI/state/csr/outcomes/external/ffffffffffffffffffffffffffffffff"
  else
    printf '\n' >>"$RACE_INVENTORY_FILE"
  fi
  : >"$RACE_MARKER"
elif [[ $* == *platform-pki-csr-deployment-v1* && ! -e $RACE_MARKER ]]; then
  if [[ $RACE_KIND == staged-trust ]]; then
    for path in "$RACE_INVENTORY"/.platform-pki-csr-trust.*/deployers.allowed_signers; do
      [[ -f $path ]] || continue
      printf '\n' >>"$path"
      break
    done
  else
    printf '\n' >>"$RACE_RETAINED_REQUEST"
  fi
  : >"$RACE_MARKER"
fi
exec "$REAL_SSH_KEYGEN" "$@"
""",
    )

    result = run(
        workspace.runner,
        environment(
            workspace.env,
            PATH=f"{fake_bin}:{workspace.env['PATH']}",
            REAL_SSH_KEYGEN=executable("ssh-keygen"),
            RACE_KIND=race,
            RACE_MARKER=os.fspath(marker),
            RACE_GATE_MARKER=os.fspath(gate_marker),
            RACE_INVENTORY=os.fspath(workspace.pki / "inventory"),
            RACE_INVENTORY_FILE=os.fspath(
                workspace.pki / "inventory/services.yml"
            ),
            RACE_PKI=os.fspath(workspace.pki),
            RACE_RETAINED_REQUEST=os.fspath(
                workspace.pki / f"state/csr/transactions/csr-{REQUEST_ID}/request"
            ),
        ),
        workspace.namespace,
        workspace.private,
    )

    assert result.status == 1
    assert marker.is_file()
    assert digest(destination / "deployers.allowed_signers") == before


@pytest.mark.parametrize(
    "case",
    (
        "malformed-outcome",
        "orphan-outcome",
        "duplicate-request",
        "empty-candidate-service",
        "empty-outcome-service",
        "malformed-active",
        "recovery",
    ),
)
def test_ambiguous_or_recovery_required_candidate_state_blocks_rotation(
    csr_workspace: CsrWorkspace, case: str
) -> None:
    workspace = csr_workspace
    if case in {"malformed-outcome", "duplicate-request"}:
        assert_result(workspace.issue(), 0)
    if case == "malformed-outcome":
        outcome = workspace.pki / f"state/csr/outcomes/external/{REQUEST_ID}"
        outcome.mkdir(mode=0o700, parents=True)
        outcome.parent.chmod(0o700)
        outcome.parent.parent.chmod(0o700)
    elif case == "orphan-outcome":
        outcome = workspace.pki / "state/csr/outcomes/external/1123456789abcdef0123456789abcdef"
        outcome.mkdir(mode=0o700, parents=True)
        outcome.parent.chmod(0o700)
        outcome.parent.parent.chmod(0o700)
    elif case == "duplicate-request":
        candidates = workspace.pki / "state/csr/candidates"
        duplicate = candidates / f"other/{REQUEST_ID}"
        duplicate.parent.mkdir(mode=0o700)
        shutil.copytree(candidates / f"external/{REQUEST_ID}", duplicate)
    elif case == "empty-candidate-service":
        service = workspace.pki / "state/csr/candidates/external"
        service.mkdir(mode=0o700, parents=True)
        service.parent.chmod(0o700)
    elif case == "empty-outcome-service":
        service = workspace.pki / "state/csr/outcomes/external"
        service.mkdir(mode=0o700, parents=True)
        service.parent.chmod(0o700)
    elif case == "malformed-active":
        active = workspace.pki / "state/csr/active"
        active.mkdir(mode=0o700, parents=True)
        active.parent.chmod(0o700)
        write_private(active / "external", "malformed active pointer\n")
    else:
        write_private(
            workspace.pki / "state/csr/finalization-recovery-journal",
            "recovery required\n",
        )
    configure_deployer_trust(workspace)

    result = run(
        workspace.runner, workspace.env, workspace.namespace, workspace.private
    )

    assert result.status == 1
    assert "CSR trust updated:" not in result.stdout
