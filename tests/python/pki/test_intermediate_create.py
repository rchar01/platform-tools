from __future__ import annotations

import fcntl
import os
import stat
from collections.abc import Callable
from pathlib import Path

import pytest

from ..harness import ProcessResult
from .create_test_support import (
    command_path,
    create_intermediate,
    create_root,
    digest,
    environment,
    executable,
    file_object_identity,
    filesystem_snapshot,
    initialize,
    mode,
    names,
    openssl,
    record,
    require_success,
    run,
    tools,
    workspace,
)


pytestmark = pytest.mark.pki

ROOT_DB = {
    "index": "index.txt",
    "index_attr": "index.txt.attr",
    "serial": "serial",
    "crlnumber": "crlnumber",
    "index_old": "index.txt.old",
    "index_attr_old": "index.txt.attr.old",
    "serial_old": "serial.old",
    "crlnumber_old": "crlnumber.old",
}
ROOT_PUBLICATIONS = (*ROOT_DB, "newcert")
OPTIONAL_ROOT_DB = ("index_old", "index_attr_old", "serial_old", "crlnumber_old")
BOUNDARIES = (
    "after-journal", "after-reservation", "after-intermediate", "after-root-db",
    "after-reservation-consumed", "after-active", "after-bootstrap",
)


def _command(value, toolset, *arguments: str | Path) -> list[str | Path]:
    return [toolset.intermediate, "--namespace", value.namespace, *arguments]


def _bootstrap(process_runner, value, env, toolset) -> None:
    initialize(process_runner, value, env, toolset)
    require_success(create_root(process_runner, value, env, toolset), "root fixture")


def _create_command(value, toolset, *, unencrypted: bool = True) -> list[str | Path]:
    result: list[str | Path] = [
        toolset.intermediate, "--namespace", value.namespace,
        "--name", "Pytest Intermediate", "--org", "Platform Test", "--country", "PL",
        "--root-pass-file", value.root_pass,
    ]
    if unencrypted:
        result.append("--allow-unencrypted-intermediate-key")
    else:
        result.extend(("--intermediate-pass-file", value.intermediate_pass))
    return result


def _root_state(value) -> tuple[str, str, tuple[str, ...]]:
    root = value.pki / "authorities/roots/g1"
    return digest(root / "index.txt"), digest(root / "serial"), names(root / "newcerts")


def _complete_root_db(value) -> None:
    root = value.pki / "authorities/roots/g1"
    for key in OPTIONAL_ROOT_DB:
        path = root / ROOT_DB[key]
        path.write_text(f"pre-transaction-{key}\n")
        path.chmod(0o600)
    source = root / "certs/root-ca.crt"
    destination = root / "newcerts/0ABC.pem"
    destination.write_bytes(source.read_bytes())
    destination.chmod(source.stat().st_mode & 0o777)


def _db_snapshot(value) -> dict[str, tuple[object, ...] | None]:
    root = value.pki / "authorities/roots/g1"
    result: dict[str, tuple[object, ...] | None] = {}
    for key, name in ROOT_DB.items():
        path = root / name
        if not path.exists() and not path.is_symlink():
            result[key] = None
        else:
            metadata = path.lstat()
            if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
                pytest.fail("root DB snapshot found a non-regular object", pytrace=False)
            result[key] = (metadata.st_uid, metadata.st_mode, metadata.st_nlink, digest(path))
    newcerts = root / "newcerts"
    directory_metadata = newcerts.lstat()
    if newcerts.is_symlink() or not stat.S_ISDIR(directory_metadata.st_mode):
        pytest.fail("root newcerts snapshot found a non-directory object", pytrace=False)
    result["newcerts-dir"] = (
        directory_metadata.st_uid,
        mode(newcerts),
        directory_metadata.st_nlink,
        stat.S_IFMT(directory_metadata.st_mode),
    )
    for path in sorted(newcerts.iterdir()):
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            pytest.fail("root newcerts snapshot found a non-regular object", pytrace=False)
        result[f"newcert:{path.name}"] = (metadata.st_uid, metadata.st_mode, metadata.st_nlink, digest(path))
    return result


def _recovery_command(value, toolset, transaction: str, action: str) -> list[str | Path]:
    return [toolset.recover, "recover", "--namespace", value.namespace, "--transaction", transaction, "--action", action, "--yes"]


@pytest.mark.parametrize(
    ("arguments", "status", "stdout_fragment", "stderr_fragment"),
    (
        pytest.param(("--help",), 0, "Usage:", "", id="help"),
        pytest.param(("--version",), 0, "platform-pki-intermediate-create", "", id="version"),
        pytest.param(("--unknown",), 1, "", "invalid option: --unknown", id="unknown-option"),
        pytest.param(("--org", "Test", "--country", "PL"), 1, "", "missing required flag: --name CN", id="missing-name"),
        pytest.param(("--name", "Test", "--org", "Test", "--country", "PL", "--days", "zero"), 1, "", "Days value must be numeric: zero", id="invalid-days"),
        pytest.param(("--name", "Test", "--org", "Test", "--country", "PL", "--days="), 1, "", "invalid option: --days=", id="empty-days"),
    ),
)
def test_parser_contract(tmp_path: Path, process_runner: Callable[..., ProcessResult], arguments: tuple[str, ...], status: int, stdout_fragment: str, stderr_fragment: str) -> None:
    toolset = tools()
    result = run(process_runner, [toolset.intermediate, *arguments], environment(tmp_path / "environment"))
    assert result.status == status
    assert stdout_fragment in result.stdout
    assert stderr_fragment in result.stderr
    if arguments == ("--help",):
        assert "platform-pki-intermediate-create --version | -v" in result.stdout
        assert "--allow-unencrypted-intermediate-key" in result.stdout
        assert result.stderr == ""
    if arguments == ("--version",):
        assert result.stdout == f"platform-pki-intermediate-create {toolset.version}\n"
        assert result.stderr == ""


def test_conflicting_intermediate_key_options(tmp_path: Path, process_runner: Callable[..., ProcessResult]) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment")
    result = run(process_runner, _command(value, toolset, "--name", "Test", "--org", "Test", "--country", "PL", "--intermediate-pass-file", value.intermediate_pass, "--allow-unencrypted-intermediate-key"), env)
    assert result.status == 1
    assert "conflicting options" in result.stderr


@pytest.mark.parametrize(
    ("case", "diagnostic"),
    (
        pytest.param("dn-newline", "must not contain newlines", id="dn-newline"),
        pytest.param("pki-variable", "PKI directory must not contain OpenSSL variable expansion syntax", id="pki-openssl-variable"),
    ),
)
def test_invalid_input_creates_no_namespace(tmp_path: Path, process_runner: Callable[..., ProcessResult], case: str, diagnostic: str) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment")
    arguments: list[str | Path] = ["--name", "Invalid\nCN" if case == "dn-newline" else "Test", "--org", "Test", "--country", "PL", "--root-pass-file", value.root_pass, "--intermediate-pass-file", value.intermediate_pass]
    invalid_pki = tmp_path / "pki-$variable"
    if case == "pki-variable":
        arguments[0:0] = ["--pki-dir", invalid_pki]
    result = run(process_runner, _command(value, toolset, *arguments), env)
    assert result.status == 1
    assert diagnostic in result.stderr
    assert not value.namespace.exists()
    assert not invalid_pki.exists()


def test_missing_bootstrap_root_is_rejected(tmp_path: Path, process_runner: Callable[..., ProcessResult]) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment")
    initialize(process_runner, value, env, toolset)
    result = create_intermediate(process_runner, value, env, toolset)
    assert result.status == 1
    assert "Bootstrap root manifest is missing" in result.stderr


def test_issuer_validity_margin_rejects_intermediate_without_publication(tmp_path: Path, process_runner: Callable[..., ProcessResult]) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment")
    initialize(process_runner, value, env, toolset)
    require_success(create_root(process_runner, value, env, toolset, days=2), "short root fixture")
    result = create_intermediate(process_runner, value, env, toolset, days=2)
    assert result.status == 1
    assert "exceeds issuer validity safety margin" in result.stderr
    assert not (value.pki / "authorities/intermediates/g1-i1").exists()
    assert (value.pki / "state/bootstrap-root").is_file()


def test_encrypted_intermediate_real_openssl_and_database(tmp_path: Path, process_runner: Callable[..., ProcessResult]) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment")
    _bootstrap(process_runner, value, env, toolset)
    result = create_intermediate(process_runner, value, env, toolset, days=5)
    require_success(result, "intermediate creation")
    authority = value.pki / "authorities/intermediates/g1-i1"
    key = authority / "private/intermediate-ca.key"
    certificate = authority / "certs/intermediate-ca.crt"
    assert (mode(key), mode(certificate)) == (0o600, 0o644)
    assert openssl(process_runner, ["pkey", "-in", key, "-passin", f"file:{value.intermediate_pass}", "-noout"], env).status == 0
    assert openssl(process_runner, ["pkey", "-in", key, "-passin", "pass:incorrect", "-noout"], env).status != 0
    certificate_public = openssl(process_runner, ["x509", "-in", certificate, "-pubkey", "-noout"], env)
    key_public = openssl(process_runner, ["pkey", "-in", key, "-passin", f"file:{value.intermediate_pass}", "-pubout"], env)
    assert certificate_public.status == key_public.status == 0
    assert certificate_public.stdout == key_public.stdout
    verify = openssl(process_runner, ["verify", "-CAfile", value.pki / "authorities/roots/g1/certs/root-ca.crt", certificate], env)
    assert verify.status == 0
    assert (value.pki / "state/active-issuer").read_text() == "root=g1\nintermediate=g1-i1\n"
    assert not (value.pki / "state/bootstrap-root").exists()
    assert (authority / "index.txt").read_text() == ""
    assert (authority / "index.txt.attr").read_text() == "unique_subject = no\n"
    assert (authority / "serial").read_text().strip() == "1000"
    assert (authority / "crlnumber").read_text().strip() == "1000"
    assert all(mode(authority / name) == 0o600 for name in ("index.txt", "index.txt.attr", "serial", "crlnumber"))
    assert openssl(process_runner, ["ca", "-config", authority / "openssl.cnf", "-updatedb", "-passin", f"file:{value.intermediate_pass}"], env).status == 0


def test_force_refuses_active_issuer(tmp_path: Path, process_runner: Callable[..., ProcessResult]) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment")
    _bootstrap(process_runner, value, env, toolset)
    require_success(create_intermediate(process_runner, value, env, toolset), "intermediate fixture")
    result = run(process_runner, _command(value, toolset, "--name", "Replacement", "--org", "Test", "--country", "PL", "--root-pass-file", value.root_pass, "--intermediate-pass-file", value.intermediate_pass, "--force"), env)
    assert result.status == 1
    assert "active issuer exists" in result.stderr


@pytest.mark.parametrize("boundary", BOUNDARIES, ids=BOUNDARIES)
def test_injected_failure_restores_root_and_bootstrap(tmp_path: Path, process_runner: Callable[..., ProcessResult], boundary: str) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment")
    _bootstrap(process_runner, value, env, toolset)
    before = _root_state(value)
    result = run(process_runner, _create_command(value, toolset), dict(env, PLATFORM_PKI_INTERMEDIATE_FAIL_AT=boundary))
    assert result.status == 1
    assert not (value.pki / "authorities/intermediates/g1-i1").exists()
    assert not (value.pki / "state/active-issuer").exists()
    assert (value.pki / "state/bootstrap-root").is_file()
    assert _root_state(value) == before
    assert record(value.pki / "state/rollover/journal")["committed"] == "true"
    reservation = value.pki / "state/generation-reservations/g1-i1"
    if reservation.exists():
        assert record(reservation)["status"] == "abandoned"


COMPLETE_DB_WRAPPER = """#!/usr/bin/env bash
set -euo pipefail
if [[ ${1:-} != ca ]]; then exec "$REAL_OPENSSL" "$@"; fi
"$REAL_OPENSSL" "$@"
config=''; previous=''
for argument in "$@"; do
  if [[ $previous == -config ]]; then config=$argument; break; fi
  previous=$argument
done
[[ -n $config ]] || exit 0
ca_dir=''
while IFS= read -r line; do
  if [[ $line == 'dir = '* ]]; then ca_dir=${line#dir = }; break; fi
done <"$config"
[[ -n $ca_dir ]] || exit 0
for file in index.txt.old index.txt.attr.old serial.old crlnumber.old; do
  printf 'post-signing-%s\n' "$file" >"$ca_dir/$file"
  chmod 600 "$ca_dir/$file"
done
"""


@pytest.mark.parametrize("publication", ROOT_PUBLICATIONS, ids=ROOT_PUBLICATIONS)
@pytest.mark.parametrize("checkpoint", ("pending", "done"), ids=("pending", "done"))
def test_root_database_publication_checkpoint_rolls_back_exact_snapshot(tmp_path: Path, process_runner: Callable[..., ProcessResult], publication: str, checkpoint: str) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment")
    _bootstrap(process_runner, value, env, toolset); _complete_root_db(value)
    before = _db_snapshot(value)
    wrapper = executable(tmp_path / "openssl", COMPLETE_DB_WRAPPER)
    crash_env = dict(env, PATH=f"{wrapper.parent}:{env['PATH']}", REAL_OPENSSL=command_path("openssl", env), PLATFORM_PKI_INTERMEDIATE_CRASH_AT=f"root-{publication}-{checkpoint}")
    assert run(process_runner, _create_command(value, toolset), crash_env).status == 137
    journal = value.pki / "state/rollover/journal"; journal_record = record(journal)
    pre = journal_record[f"root_{publication}_pre_identity"]
    post = journal_record[f"root_{publication}_post_identity"]
    assert post != "absent"
    assert pre == "absent" if publication == "newcert" else pre not in ("absent", post)
    assert run(process_runner, _recovery_command(value, toolset, journal_record["transaction"], "rollback"), env).status == 0
    assert _db_snapshot(value) == before
    root = value.pki / "authorities/roots/g1"
    target = root / (f"newcerts/{journal_record['issued_serial']}.pem" if publication == "newcert" else ROOT_DB[publication])
    current = "absent" if not target.exists() and not target.is_symlink() else file_object_identity(target)
    assert current != post


@pytest.mark.parametrize("checkpoint", ("cleanup-pending", "cleanup-removed", "cleanup-done"), ids=("pending", "removed", "done"))
def test_sensitive_stage_cleanup_resume(tmp_path: Path, process_runner: Callable[..., ProcessResult], checkpoint: str) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment")
    _bootstrap(process_runner, value, env, toolset)
    assert run(process_runner, _create_command(value, toolset), dict(env, PLATFORM_PKI_INTERMEDIATE_CRASH_AT=checkpoint)).status == 137
    journal = record(value.pki / "state/rollover/journal")
    assert run(process_runner, _recovery_command(value, toolset, journal["transaction"], "resume"), env).status == 0
    assert not Path(journal["root_stage"]).exists()
    assert (value.pki / "state/active-issuer").is_file()
    assert not (value.pki / "state/bootstrap-root").exists()
    assert record(value.pki / "state/rollover/journal")["committed"] == "true"


def test_cleanup_recovery_can_restart_at_each_checkpoint(tmp_path: Path, process_runner: Callable[..., ProcessResult]) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment")
    _bootstrap(process_runner, value, env, toolset)
    assert run(process_runner, _create_command(value, toolset), dict(env, PLATFORM_PKI_INTERMEDIATE_CRASH_AT="cleanup-pending")).status == 137
    transaction = record(value.pki / "state/rollover/journal")["transaction"]
    command = _recovery_command(value, toolset, transaction, "resume")
    for checkpoint in ("cleanup-pending", "cleanup-done"):
        assert run(process_runner, command, dict(env, PLATFORM_PKI_RECOVER_CRASH_AT=checkpoint)).status == 137
    assert run(process_runner, command, env).status == 0


def test_rollback_recovery_can_restart_at_every_checkpoint(tmp_path: Path, process_runner: Callable[..., ProcessResult]) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment")
    _bootstrap(process_runner, value, env, toolset); _complete_root_db(value); before = _db_snapshot(value)
    wrapper = executable(tmp_path / "openssl", COMPLETE_DB_WRAPPER)
    crash_env = dict(env, PATH=f"{wrapper.parent}:{env['PATH']}", REAL_OPENSSL=command_path("openssl", env), PLATFORM_PKI_INTERMEDIATE_CRASH_AT="after-bootstrap")
    assert run(process_runner, _create_command(value, toolset), crash_env).status == 137
    journal_path = value.pki / "state/rollover/journal"; journal = record(journal_path)
    for key in OPTIONAL_ROOT_DB:
        assert journal[f"root_{key}_pre_identity"] not in ("absent", journal[f"root_{key}_post_identity"])
    checkpoints = ["rollback-active-pending", "rollback-active-done", "rollback-bootstrap-pending", "rollback-bootstrap-done"]
    for key in ROOT_PUBLICATIONS:
        checkpoints.extend((f"rollback-root-{key}-pending", f"rollback-root-{key}-done"))
    checkpoints.extend(("rollback-authority-pending", "rollback-authority-done", "rollback-stage-pending", "rollback-stage-done", "rollback-reservation-pending", "rollback-reservation-done"))
    command = _recovery_command(value, toolset, journal["transaction"], "rollback")
    for checkpoint in checkpoints:
        assert run(process_runner, command, dict(env, PLATFORM_PKI_RECOVER_CRASH_AT=checkpoint)).status == 137
    assert run(process_runner, command, env).status == 0
    assert _db_snapshot(value) == before
    assert record(value.pki / "state/generation-reservations/g1-i1")["status"] == "abandoned"


def test_force_preserves_symlink_generation(tmp_path: Path, process_runner: Callable[..., ProcessResult]) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment"); _bootstrap(process_runner, value, env, toolset)
    foreign = tmp_path / "foreign"; foreign.mkdir(mode=0o700)
    sentinel = foreign / "sentinel"; sentinel.write_text("foreign-intermediate-state\n"); sentinel.chmod(0o600)
    generation = value.pki / "authorities/intermediates/g1-i1"; generation.symlink_to(foreign, target_is_directory=True)
    generation_before = filesystem_snapshot(generation); foreign_before = filesystem_snapshot(foreign)
    result = run(process_runner, [*_create_command(value, toolset), "--force"], env)
    assert result.status == 1
    assert generation.is_symlink() and foreign.is_dir()
    assert filesystem_snapshot(generation) == generation_before
    assert filesystem_snapshot(foreign) == foreign_before


@pytest.mark.parametrize("boundary", BOUNDARIES, ids=BOUNDARIES)
def test_crash_recovery_restores_root_and_retry_advances(tmp_path: Path, process_runner: Callable[..., ProcessResult], boundary: str) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment"); _bootstrap(process_runner, value, env, toolset)
    before = _root_state(value)
    assert run(process_runner, _create_command(value, toolset), dict(env, PLATFORM_PKI_INTERMEDIATE_CRASH_AT=boundary)).status == 137
    transaction = record(value.pki / "state/rollover/journal")["transaction"]
    assert run(process_runner, _recovery_command(value, toolset, transaction, "rollback"), env).status == 0
    assert _root_state(value) == before
    assert not (value.pki / "authorities/intermediates/g1-i1").exists()
    assert (value.pki / "state/bootstrap-root").is_file()
    assert record(value.pki / "state/generation-reservations/g1-i1")["status"] == "abandoned"
    require_success(run(process_runner, _create_command(value, toolset), env), "intermediate retry")
    assert record(value.pki / "state/active-issuer")["intermediate"] == "g1-i2"


@pytest.mark.parametrize("publication", ROOT_PUBLICATIONS, ids=ROOT_PUBLICATIONS)
def test_recovery_preserves_hostile_root_database_replacement(tmp_path: Path, process_runner: Callable[..., ProcessResult], publication: str) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment"); _bootstrap(process_runner, value, env, toolset)
    assert run(process_runner, _create_command(value, toolset), dict(env, PLATFORM_PKI_INTERMEDIATE_CRASH_AT="after-root-db")).status == 137
    journal = record(value.pki / "state/rollover/journal")
    root = value.pki / "authorities/roots/g1"
    target = root / (f"newcerts/{journal['issued_serial']}.pem" if publication == "newcert" else ROOT_DB[publication])
    target.unlink(missing_ok=True); target.write_text(f"hostile-{publication}\n"); target.chmod(0o600)
    target_before = filesystem_snapshot(target)
    result = run(process_runner, _recovery_command(value, toolset, journal["transaction"], "rollback"), env)
    assert result.status == 1
    assert filesystem_snapshot(target) == target_before


def test_signal_after_root_database_rolls_back(tmp_path: Path, process_runner: Callable[..., ProcessResult]) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment"); _bootstrap(process_runner, value, env, toolset)
    result = run(process_runner, _create_command(value, toolset), dict(env, PLATFORM_PKI_INTERMEDIATE_SIGNAL_AT="after-root-db"))
    assert result.status == 143
    assert not (value.pki / "authorities/intermediates/g1-i1").exists()
    assert (value.pki / "state/bootstrap-root").is_file()


def test_openssl_failure_does_not_publish_intermediate(tmp_path: Path, process_runner: Callable[..., ProcessResult]) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment"); _bootstrap(process_runner, value, env, toolset)
    wrapper = executable(tmp_path / "openssl", """#!/usr/bin/env bash
[[ ${1:-} != ca ]] || exit 42
exec "$REAL_OPENSSL" "$@"
""")
    failure_env = dict(env, PATH=f"{wrapper.parent}:{env['PATH']}", REAL_OPENSSL=command_path("openssl", env))
    result = run(process_runner, _create_command(value, toolset), failure_env)
    assert result.status == 42
    assert not (value.pki / "authorities/intermediates/g1-i1").exists()
    assert (value.pki / "state/bootstrap-root").is_file()


def test_intermediate_lock_contention(tmp_path: Path, process_runner: Callable[..., ProcessResult]) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment"); _bootstrap(process_runner, value, env, toolset)
    lock = value.pki / "locks/intermediate"
    lock.touch(mode=0o600)
    lock.chmod(0o600)
    with lock.open("r+") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = run(process_runner, _create_command(value, toolset), env)
    assert result.status == 1
    assert "Another intermediate CA operation is in progress" in result.stderr
    assert lock.is_file()


@pytest.mark.parametrize("hostile_case", ("key-symlink", "db-hardlink", "writable-dir"), ids=("key-symlink", "database-hardlink", "writable-directory"))
def test_force_preserves_hostile_partial_generation(tmp_path: Path, process_runner: Callable[..., ProcessResult], hostile_case: str) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment"); _bootstrap(process_runner, value, env, toolset)
    authority = value.pki / "authorities/intermediates/g1-i1"; (authority / "private").mkdir(mode=0o700, parents=True); (authority / "certs").mkdir(mode=0o700)
    external: Path | None = None
    if hostile_case == "key-symlink":
        victim = tmp_path / "victim"; victim.write_text("sentinel\n"); victim.chmod(0o600); (authority / "private/intermediate-ca.key").symlink_to(victim); external = victim
    elif hostile_case == "db-hardlink":
        serial = authority / "serial"; serial.write_text("sentinel\n"); serial.chmod(0o600); external = tmp_path / "hardlink"; os.link(serial, external)
    else:
        (authority / "certs").chmod(0o777)
    authority_before = filesystem_snapshot(authority)
    external_before = None if external is None else filesystem_snapshot(external)
    result = run(process_runner, [*_create_command(value, toolset), "--force"], env)
    assert result.status == 1
    assert authority.is_dir() and not authority.is_symlink()
    assert filesystem_snapshot(authority) == authority_before
    if external is not None:
        assert filesystem_snapshot(external) == external_before
