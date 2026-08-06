from __future__ import annotations

import fcntl
import os
import stat
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from ..harness import ManagedProcess, ProcessResult
from .create_test_support import (
    assert_passphrase_content_absent,
    assert_no_glob,
    command_path,
    digest,
    environment,
    executable,
    lstat_identity,
    mode,
    openssl,
    ready_ca,
    require_success,
    run,
    tools,
    workspace,
)


pytestmark = pytest.mark.pki

INVENTORY = """services:
  app:
    common_name: app.example.internal
    dns:
      - app.example.internal
      - app
    ips:
      - 192.0.2.10
    days: 35
  rotate:
    common_name: rotate.example.internal
    dns:
      - rotate.example.internal
    ips:
      - 192.0.2.11
  failure:
    common_name: failure.example.internal
    dns:
      - failure.example.internal
    ips:
      - 192.0.2.12
  external:
    key_custody: host-local
    target: host-01
    validation_boundary_sha256: 0000000000000000000000000000000000000000000000000000000000000000
    rollback_hold_seconds: 3600
    common_name: external.example.internal
    dns:
      - external.example.internal
"""


def _issue(value, toolset, service: str, *arguments: str | Path) -> list[str | Path]:
    return [toolset.issue, service, "--namespace", value.namespace, "--intermediate-pass-file", value.intermediate_pass, *arguments]


def _ready(process_runner, value, env, toolset) -> None:
    ready_ca(process_runner, value, env, toolset, INVENTORY)


def _ca_state(value) -> dict[str, tuple[object, ...] | None]:
    authority = value.pki / "authorities/intermediates/g1-i1"
    result: dict[str, tuple[object, ...] | None] = {}
    for name in (
        "index.txt", "index.txt.attr", "serial", "crlnumber",
        "index.txt.old", "index.txt.attr.old", "serial.old", "crlnumber.old",
    ):
        path = authority / name
        if not path.exists() and not path.is_symlink():
            result[f"db:{name}"] = None
            continue
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            pytest.fail("intermediate DB snapshot found a non-regular object", pytrace=False)
        result[f"db:{name}"] = (
            metadata.st_uid, metadata.st_gid, stat.S_IFMT(metadata.st_mode),
            mode(path), metadata.st_nlink, metadata.st_size, digest(path),
        )
    newcerts = authority / "newcerts"
    directory_metadata = newcerts.lstat()
    if newcerts.is_symlink() or not stat.S_ISDIR(directory_metadata.st_mode):
        pytest.fail("intermediate newcerts snapshot found a non-directory object", pytrace=False)
    result["newcerts-dir"] = (
        directory_metadata.st_uid, directory_metadata.st_gid,
        stat.S_IFMT(directory_metadata.st_mode), mode(newcerts),
        directory_metadata.st_nlink,
    )
    for path in sorted(newcerts.iterdir()):
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            pytest.fail("intermediate newcerts snapshot found a non-regular object", pytrace=False)
        result[f"newcert:{path.name}"] = (
            metadata.st_uid, metadata.st_gid, stat.S_IFMT(metadata.st_mode),
            mode(path), metadata.st_nlink, metadata.st_size, digest(path),
        )
    return result


def _assert_no_residue(value) -> None:
    assert all((value.pki / f"locks/{name}").is_file() for name in ("root", "intermediate", "inventory"))
    assert_no_glob(value.pki / "authorities/intermediates/g1-i1", ".platform-pki-service-issue.*")


def _replace_line(path: Path, prefix: str, replacement: str) -> None:
    lines = path.read_text().splitlines()
    assert any(line.startswith(prefix) for line in lines)
    path.write_text("\n".join(replacement if line.startswith(prefix) else line for line in lines) + "\n")
    path.chmod(0o600)


def _insert_after(path: Path, prefix: str, insertion: str) -> None:
    output: list[str] = []
    inserted = False
    for line in path.read_text().splitlines():
        output.append(line)
        if line.startswith(prefix):
            output.append(insertion); inserted = True
    assert inserted
    path.write_text("\n".join(output) + "\n"); path.chmod(0o600)


@pytest.mark.parametrize(
    ("arguments", "status", "stdout_fragment", "stderr_fragment"),
    (
        pytest.param(("--help",), 0, "Usage:", "", id="help"),
        pytest.param(("--version",), 0, "platform-pki-service-issue", "", id="version"),
        pytest.param(("--unknown",), 1, "", "invalid option: --unknown", id="unknown-option"),
        pytest.param((), 1, "", "missing required argument: SERVICE", id="missing-service"),
        pytest.param(("app", "--days", "nope"), 1, "", "Days value must be numeric: nope", id="invalid-days"),
        pytest.param(("app", "--days="), 1, "", "invalid option: --days=", id="empty-days"),
        pytest.param(("app", "--help"), 0, "Usage:", "", id="service-help-long"),
        pytest.param(("app", "-h"), 0, "Usage:", "", id="service-help-short"),
        pytest.param(("app", "--namespace", "--help"), 1, "", "", id="missing-option-value-before-help"),
        pytest.param(("app", "--unknown", "--help"), 1, "", "", id="unknown-before-help"),
        pytest.param(("app", "--days=", "--help"), 1, "", "", id="invalid-days-before-help"),
    ),
)
def test_parser_contract(tmp_path: Path, process_runner: Callable[..., ProcessResult], arguments: tuple[str, ...], status: int, stdout_fragment: str, stderr_fragment: str) -> None:
    toolset = tools(); result = run(process_runner, [toolset.issue, *arguments], environment(tmp_path / "environment"))
    assert result.status == status
    assert stdout_fragment in result.stdout
    assert stderr_fragment in result.stderr
    if arguments == ("--help",):
        assert "platform-pki-service-issue --version | -v" in result.stdout
        assert "--rotate-key" in result.stdout
    if arguments == ("--version",):
        assert result.stdout == f"platform-pki-service-issue {toolset.version}\n"
    if status == 0:
        assert result.stderr == ""
    if arguments and arguments[-1] == "--help" and status == 1:
        assert result.stdout == ""


def test_inventory_parser_temp_is_removed_on_cli_failure(tmp_path: Path, process_runner: Callable[..., ProcessResult]) -> None:
    toolset = tools(); env = environment(tmp_path / "environment"); temporary = tmp_path / "inventory-temp"; temporary.mkdir(mode=0o700)
    result = run(process_runner, [toolset.issue, "unknown", "--pki-dir", tmp_path / "missing"], dict(env, TMPDIR=os.fspath(temporary)))
    assert result.status == 1
    assert_no_glob(temporary, "platform-pki-service-issue.*")


def test_validity_margin_rejection_does_not_publish(tmp_path: Path, process_runner: Callable[..., ProcessResult]) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment"); _ready(process_runner, value, env, toolset)
    before = _ca_state(value)
    result = run(process_runner, _issue(value, toolset, "failure", "--days", "5000"), env)
    assert result.status == 1
    assert "exceeds issuer validity safety margin" in result.stderr
    assert not (value.pki / "services/failure/certs/tls.crt").exists()
    assert _ca_state(value) == before


def test_real_openssl_issuance_artifacts_lifetime_and_ca_database(tmp_path: Path, process_runner: Callable[..., ProcessResult]) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment"); _ready(process_runner, value, env, toolset)
    result = run(process_runner, _issue(value, toolset, "app"), env); require_success(result, "service issuance")
    service = value.pki / "services/app"; authority = value.pki / "authorities/intermediates/g1-i1"
    assert "[OK] Verified service certificate: app" in result.stdout
    assert f"[OK] Issued service certificate: {service / 'certs/tls.crt'}" in result.stdout
    paths = (service / "private/tls.key", service / "certs/tls.crt", service / "csr/tls.csr", service / "chain/ca-chain.crt", service / "chain/fullchain.crt", service / "openssl.cnf")
    assert all(path.is_file() for path in paths)
    assert tuple(mode(path) for path in paths) == (0o600, 0o644, 0o600, 0o644, 0o644, 0o600)
    verify = openssl(process_runner, ["verify", "-CAfile", value.pki / "authorities/roots/g1/certs/root-ca.crt", "-untrusted", authority / "certs/intermediate-ca.crt", service / "certs/tls.crt"], env)
    assert verify.status == 0
    assert openssl(process_runner, ["x509", "-in", service / "certs/tls.crt", "-checkend", str(34 * 86400), "-noout"], env).status == 0
    assert openssl(process_runner, ["x509", "-in", service / "certs/tls.crt", "-checkend", str(36 * 86400), "-noout"], env).status != 0
    assert (authority / "serial").read_text().strip() == "1001"
    assert len((authority / "index.txt").read_text().splitlines()) == 1
    assert (authority / "newcerts/1000.pem").is_file()
    _assert_no_residue(value)


def test_host_local_inventory_fails_before_ca_or_service_mutation(tmp_path: Path, process_runner: Callable[..., ProcessResult]) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment"); _ready(process_runner, value, env, toolset)
    before = _ca_state(value)
    result = run(process_runner, _issue(value, toolset, "external"), env)
    assert result.status == 1
    assert "Host-local service issuance requires authenticated CSR inputs: external" in result.stderr
    assert not (value.pki / "services/external").exists()
    assert _ca_state(value) == before
    _assert_no_residue(value)


def test_existing_certificate_refusal_preserves_service_and_ca(tmp_path: Path, process_runner: Callable[..., ProcessResult]) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment"); _ready(process_runner, value, env, toolset)
    require_success(run(process_runner, _issue(value, toolset, "app"), env), "service fixture")
    key = value.pki / "services/app/private/tls.key"; certificate = value.pki / "services/app/certs/tls.crt"
    key_before = digest(key); certificate_before = digest(certificate); ca_before = _ca_state(value)
    result = run(process_runner, _issue(value, toolset, "app", "--rotate-key"), env)
    assert result.status == 1
    assert "Service certificate already exists; use platform-pki-service-renew" in result.stderr
    if digest(key) != key_before or digest(certificate) != certificate_before or _ca_state(value) != ca_before:
        pytest.fail("existing-certificate refusal changed service or CA state", pytrace=False)


def test_existing_key_reuse_and_explicit_rotation_archive(tmp_path: Path, process_runner: Callable[..., ProcessResult]) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment"); _ready(process_runner, value, env, toolset)
    service = value.pki / "services/rotate"; key = service / "private/tls.key"; key.parent.mkdir(mode=0o700, parents=True)
    service.chmod(0o700); key.parent.chmod(0o700)
    require_success(openssl(process_runner, ["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:secp384r1", "-out", key], env), "key fixture"); key.chmod(0o600); old = digest(key)
    require_success(run(process_runner, _issue(value, toolset, "rotate", "--days", "31"), env), "key reuse issuance")
    assert digest(key) == old
    for relative in ("certs/tls.crt", "csr/tls.csr", "chain/ca-chain.crt", "chain/fullchain.crt", "openssl.cnf", "issuer"):
        (service / relative).unlink()
    require_success(run(process_runner, _issue(value, toolset, "rotate", "--days", "31", "--rotate-key"), env), "key rotation")
    assert digest(key) != old
    archived = tuple((service / "archive").glob("*/tls.key"))
    assert len(archived) == 1
    assert digest(archived[0]) == old


def test_openssl_signing_failure_restores_ca_and_service(tmp_path: Path, process_runner: Callable[..., ProcessResult]) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment"); _ready(process_runner, value, env, toolset); before = _ca_state(value)
    wrapper = executable(tmp_path / "openssl", """#!/usr/bin/env bash
[[ ${1:-} != ca ]] || exit 42
exec "$REAL_OPENSSL" "$@"
""")
    result = run(process_runner, _issue(value, toolset, "failure"), dict(env, PATH=f"{wrapper.parent}:{env['PATH']}", REAL_OPENSSL=command_path("openssl", env)))
    assert result.status == 42
    assert not (value.pki / "services/failure").exists()
    assert _ca_state(value) == before
    _assert_no_residue(value)


@pytest.mark.parametrize(
    ("config_case", "diagnostic"),
    (
        pytest.param("include", "must not contain include directives", id="include-directive"),
        pytest.param("database-escape", "signing path 'database' escapes", id="database-escape"),
        pytest.param("randfile-escape", "signing path 'RANDFILE' escapes", id="randfile-escape"),
    ),
)
def test_hostile_openssl_config_rejected_before_ca_mutation(tmp_path: Path, process_runner: Callable[..., ProcessResult], config_case: str, diagnostic: str) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment"); _ready(process_runner, value, env, toolset)
    config = value.pki / "authorities/intermediates/g1-i1/openssl.cnf"
    if config_case == "include":
        with config.open("a") as stream: stream.write(".include /tmp/external-openssl.cnf\n")
    elif config_case == "database-escape":
        _replace_line(config, "database =", "database = $dir/../../external-index.txt")
    else:
        _insert_after(config, "dir =", "RANDFILE = /tmp/external-random-state")
    before = _ca_state(value); result = run(process_runner, _issue(value, toolset, "failure"), env)
    assert result.status == 1
    assert diagnostic in result.stderr
    assert _ca_state(value) == before
    assert not (value.pki / "services/failure").exists()
    assert not (value.pki / "authorities/roots/g1/.platform-pki-root-operation.lock").exists()
    _assert_no_residue(value)


def test_inventory_parent_symlink_rejected_before_locks(tmp_path: Path, process_runner: Callable[..., ProcessResult]) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment"); _ready(process_runner, value, env, toolset)
    inventory = value.pki / "inventory"; real = value.root / "inventory-real"; inventory.rename(real); inventory.symlink_to(real, target_is_directory=True); before = _ca_state(value)
    result = run(process_runner, _issue(value, toolset, "failure"), env)
    assert result.status == 1
    assert "Service inventory ancestor must be a non-symlink directory" in result.stderr
    assert _ca_state(value) == before
    assert not (value.pki / "authorities/roots/g1/.platform-pki-root-operation.lock").exists()


def test_lowercase_serial_is_canonicalized_and_temp_removed(tmp_path: Path, process_runner: Callable[..., ProcessResult]) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment"); _ready(process_runner, value, env, toolset)
    authority = value.pki / "authorities/intermediates/g1-i1"; (authority / "serial").write_text("abcd\n"); temporary = tmp_path / "inventory-temp"; temporary.mkdir(mode=0o700)
    result = run(process_runner, _issue(value, toolset, "failure"), dict(env, TMPDIR=os.fspath(temporary))); require_success(result, "lowercase serial issuance")
    assert_no_glob(temporary, "platform-pki-service-issue.*")
    assert (authority / "serial").read_text().strip() == "ABCE"
    assert (authority / "newcerts/ABCD.pem").is_file()


def test_canonical_serial_collision_preserves_existing_newcert(tmp_path: Path, process_runner: Callable[..., ProcessResult]) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment"); _ready(process_runner, value, env, toolset)
    authority = value.pki / "authorities/intermediates/g1-i1"; (authority / "serial").write_text("00ab\n"); collision = authority / "newcerts/AB.pem"; collision.write_text("sentinel\n"); collision.chmod(0o600); before = _ca_state(value)
    result = run(process_runner, _issue(value, toolset, "failure"), env)
    assert result.status == 1
    assert "Intermediate CA issued-certificate destination already exists" in result.stderr
    assert _ca_state(value) == before
    assert not (value.pki / "services/failure").exists()


def test_certificate_verification_failure_restores_rotated_key_and_ca(tmp_path: Path, process_runner: Callable[..., ProcessResult]) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment"); _ready(process_runner, value, env, toolset)
    key = value.pki / "services/failure/private/tls.key"; key.parent.mkdir(mode=0o700, parents=True); require_success(openssl(process_runner, ["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:secp384r1", "-out", key], env), "key fixture"); key.chmod(0o600); key_before = digest(key); ca_before = _ca_state(value)
    key.parents[1].chmod(0o700); key.parent.chmod(0o700)
    replacement = executable(tmp_path / "platform-pki-common.sh", """#!/usr/bin/env bash
source "$REAL_COMMON"
pki_verify_service_certificate() { exit 43; }
""")
    result = run(process_runner, _issue(value, toolset, "failure", "--rotate-key"), dict(env, REAL_COMMON=os.fspath(toolset.common), PLATFORM_TOOLS_LIB_DIR=os.fspath(replacement.parent)))
    assert result.status == 43
    assert digest(key) == key_before
    assert not (value.pki / "services/failure/certs/tls.crt").exists()
    assert not (value.pki / "services/failure/archive").exists()
    assert _ca_state(value) == ca_before
    _assert_no_residue(value)


PUBLICATION_WRAPPER = """#!/usr/bin/env bash
set -euo pipefail
umask 077
count=0
[[ ! -f $MV_COUNTER ]] || count=$(<"$MV_COUNTER")
count=$((count + 1)); printf '%s\n' "$count" >"$MV_COUNTER"
if [[ $count == "$MV_TRIGGER_AT" ]]; then
  if [[ -n ${MV_SIGNAL:-} ]]; then kill "-$MV_SIGNAL" "$PPID"; exit 143; fi
  printf '%s\n' "$count" >"$MV_TRIGGER_EVIDENCE"
  exit 42
fi
exec "$REAL_MV" "$@"
"""


@pytest.mark.parametrize(("case", "status", "signal_name"), (pytest.param("failure", 1, "", id="failure"), pytest.param("hup", 129, "HUP", id="sighup"), pytest.param("term", 143, "TERM", id="sigterm")))
def test_publication_failure_or_signal_rolls_back_and_cleans_temp(tmp_path: Path, process_runner: Callable[..., ProcessResult], case: str, status: int, signal_name: str) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment"); _ready(process_runner, value, env, toolset); before = _ca_state(value)
    wrapper = executable(tmp_path / "mv", PUBLICATION_WRAPPER); temporary = tmp_path / "inventory-temp"; temporary.mkdir(mode=0o700)
    counter = tmp_path / "counter"; evidence = tmp_path / "trigger-evidence"
    failure_env = dict(env, PATH=f"{wrapper.parent}:{env['PATH']}", REAL_MV=command_path("mv", env), MV_COUNTER=os.fspath(counter), MV_TRIGGER_EVIDENCE=os.fspath(evidence), MV_TRIGGER_AT="3", MV_SIGNAL=signal_name, TMPDIR=os.fspath(temporary))
    result = run(process_runner, _issue(value, toolset, "failure"), failure_env)
    assert result.status == status
    assert not (value.pki / "services/failure").exists()
    assert _ca_state(value) == before
    _assert_no_residue(value); assert_no_glob(temporary, "platform-pki-service-issue.*")
    if case == "failure":
        assert counter.read_text() == "3\n"
        assert evidence.read_text() == "3\n"
        assert mode(counter) == mode(evidence) == 0o600


RACE_WRAPPER = """#!/usr/bin/env bash
set -euo pipefail
umask 077
count=0
[[ ! -f $RACE_COUNTER ]] || count=$(<"$RACE_COUNTER")
count=$((count + 1)); printf '%s\n' "$count" >"$RACE_COUNTER"
"$REAL_MV" "$@"
if [[ $count == 1 ]]; then
  foreign="${RACE_TARGET}.foreign"; printf '%s\n' "$RACE_SENTINEL" >"$foreign"; chmod 600 "$foreign"; "$REAL_MV" -f -- "$foreign" "$RACE_TARGET"
  python3 -c 'import os,sys; s=os.lstat(sys.argv[1]); print(":".join(str(v) for v in (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)))' "$RACE_TARGET" >"$RACE_IDENTITY"
fi
"""


@pytest.mark.parametrize(("race_case", "diagnostic"), (pytest.param("absent", "appeared after validation", id="absent-destination"), pytest.param("inode", "identity changed after validation", id="existing-inode")))
def test_publication_validation_race_preserves_foreign_state(tmp_path: Path, process_runner: Callable[..., ProcessResult], race_case: str, diagnostic: str) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment"); _ready(process_runner, value, env, toolset)
    ca_before = _ca_state(value)
    service = value.pki / "services/failure"
    if race_case == "inode":
        target = service / "csr/tls.csr"; target.parent.mkdir(mode=0o700, parents=True); target.write_text("original\n"); target.chmod(0o600)
        service.chmod(0o700); target.parent.chmod(0o700)
    else:
        target = service / "certs/tls.crt"
    sentinel = f"foreign-{race_case}-publication-race"; wrapper = executable(tmp_path / "mv", RACE_WRAPPER); race_identity = tmp_path / "race-identity"
    result = run(process_runner, _issue(value, toolset, "failure"), dict(env, PATH=f"{wrapper.parent}:{env['PATH']}", REAL_MV=command_path("mv", env), RACE_COUNTER=os.fspath(tmp_path / "counter"), RACE_TARGET=os.fspath(target), RACE_SENTINEL=sentinel, RACE_IDENTITY=os.fspath(race_identity)))
    assert result.status == 1
    assert diagnostic in result.stderr
    assert target.read_text().strip() == sentinel
    if lstat_identity(target) != race_identity.read_text().strip():
        pytest.fail("publication-race hostile object identity changed", pytrace=False)
    assert mode(race_identity) == 0o600
    assert not (service / "openssl.cnf").exists()
    assert _ca_state(value) == ca_before
    _assert_no_residue(value)


def test_rollback_identity_race_preserves_staging_for_recovery(tmp_path: Path, process_runner: Callable[..., ProcessResult]) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment"); _ready(process_runner, value, env, toolset)
    wrapper = executable(tmp_path / "mv", """#!/usr/bin/env bash
set -euo pipefail
umask 077
count=0; [[ ! -f $RACE_COUNTER ]] || count=$(<"$RACE_COUNTER"); count=$((count + 1)); printf '%s\n' "$count" >"$RACE_COUNTER"
[[ $count != 2 ]] || exit 42
"$REAL_MV" "$@"
if [[ $count == 1 ]]; then destination=${!#}; foreign="${destination}.foreign"; printf '%s\n' "$RACE_SENTINEL" >"$foreign"; chmod 600 "$foreign"; "$REAL_MV" -f -- "$foreign" "$destination"; python3 -c 'import os,sys; s=os.lstat(sys.argv[1]); print(":".join(str(v) for v in (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)))' "$destination" >"$RACE_IDENTITY"; fi
""")
    temporary = tmp_path / "inventory-temp"; temporary.mkdir(mode=0o700); sentinel = "foreign-published-replacement"; race_identity = tmp_path / "race-identity"
    result = run(process_runner, _issue(value, toolset, "failure"), dict(env, PATH=f"{wrapper.parent}:{env['PATH']}", REAL_MV=command_path("mv", env), RACE_COUNTER=os.fspath(tmp_path / "counter"), RACE_SENTINEL=sentinel, RACE_IDENTITY=os.fspath(race_identity), TMPDIR=os.fspath(temporary)))
    assert result.status == 1
    assert "Published issuance destination identity changed" in result.stderr
    assert "preserved staging and locks for recovery" in result.stderr
    hostile = value.pki / "services/failure/openssl.cnf"
    assert hostile.read_text().strip() == sentinel
    if lstat_identity(hostile) != race_identity.read_text().strip():
        pytest.fail("rollback-race hostile object identity changed", pytrace=False)
    assert mode(race_identity) == 0o600
    assert (value.pki / "locks/root").is_file() and (value.pki / "locks/intermediate").is_file()
    stages = tuple((value.pki / "authorities/intermediates/g1-i1").glob(".platform-pki-service-issue.??????"))
    assert len(stages) == 1 and stages[0].is_dir()
    assert_no_glob(temporary, "platform-pki-service-issue.*")


def test_archive_link_failure_restores_key_content_and_metadata(tmp_path: Path, process_runner: Callable[..., ProcessResult]) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment"); _ready(process_runner, value, env, toolset)
    ca_before = _ca_state(value)
    key = value.pki / "services/failure/private/tls.key"; key.parent.mkdir(mode=0o700, parents=True); require_success(openssl(process_runner, ["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:secp384r1", "-out", key], env), "key fixture"); key.chmod(0o600); before = (digest(key), mode(key), key.stat().st_mtime_ns)
    key.parents[1].chmod(0o700); key.parent.chmod(0o700)
    wrapper = executable(tmp_path / "ln", """#!/usr/bin/env bash
set -euo pipefail
umask 077
count=0
[[ ! -f $LN_COUNTER ]] || count=$(<"$LN_COUNTER")
count=$((count + 1)); printf '%s\n' "$count" >"$LN_COUNTER"
destination=${!#}
if [[ $destination == */archive/*/tls.key ]]; then
  printf '%s\n' "$count" >"$LN_TRIGGER_EVIDENCE"
  exit 42
fi
exec "$REAL_LN" "$@"
""")
    counter = tmp_path / "ln-counter"; evidence = tmp_path / "ln-trigger-evidence"
    result = run(process_runner, _issue(value, toolset, "failure", "--rotate-key"), dict(env, PATH=f"{wrapper.parent}:{env['PATH']}", REAL_LN=command_path("ln", env), LN_COUNTER=os.fspath(counter), LN_TRIGGER_EVIDENCE=os.fspath(evidence)))
    assert result.status == 1
    assert "Archived previous service private key" not in result.stderr
    assert (digest(key), mode(key), key.stat().st_mtime_ns) == before
    assert not (value.pki / "services/failure/archive").exists()
    assert not (value.pki / "services/failure/certs/tls.crt").exists()
    assert counter.read_text() == "8\n"
    assert evidence.read_text() == "4\n"
    assert mode(counter) == mode(evidence) == 0o600
    assert _ca_state(value) == ca_before
    _assert_no_residue(value)


@pytest.mark.parametrize(
    ("unsafe_case", "diagnostic"),
    (
        pytest.param("symlink", "Service private key must not be a symlink", id="key-symlink"),
        pytest.param("hardlink", "Service private key must not be hard-linked", id="key-hardlink"),
        pytest.param("mode", "Intermediate CA new-certificates directory is group- or world-writable", id="newcerts-mode"),
        pytest.param("type", "Service certificate must be a regular file", id="certificate-type"),
        pytest.param("inventory", "must not contain OpenSSL variable expansion syntax", id="inventory-variable"),
    ),
)
def test_unsafe_state_rejected_before_ca_mutation(tmp_path: Path, process_runner: Callable[..., ProcessResult], unsafe_case: str, diagnostic: str) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment"); _ready(process_runner, value, env, toolset); service = value.pki / "services/failure"
    if unsafe_case == "symlink":
        (service / "private").mkdir(mode=0o700, parents=True); service.chmod(0o700); (service / "private").chmod(0o700); (service / "private/tls.key").symlink_to(tmp_path / "victim")
    elif unsafe_case == "hardlink":
        key = service / "private/tls.key"; key.parent.mkdir(mode=0o700, parents=True); service.chmod(0o700); key.parent.chmod(0o700); key.write_text("sentinel\n"); key.chmod(0o600); os.link(key, tmp_path / "hardlink")
    elif unsafe_case == "mode":
        (value.pki / "authorities/intermediates/g1-i1/newcerts").chmod(0o777)
    elif unsafe_case == "type":
        (service / "certs/tls.crt").mkdir(mode=0o700, parents=True); service.chmod(0o700); (service / "certs").chmod(0o700)
    else:
        (value.pki / "inventory/services.yml").write_text("""services:
  failure:
    common_name: $ENV::SECRET
    dns:
      - failure.example.internal
    ips:
      - 192.0.2.12
"""); (value.pki / "inventory/services.yml").chmod(0o600)
    before = _ca_state(value); result = run(process_runner, _issue(value, toolset, "failure"), env)
    assert result.status == 1
    assert diagnostic in result.stderr
    assert _ca_state(value) == before
    assert not (value.pki / "authorities/roots/g1/.platform-pki-root-operation.lock").exists()


def test_fake_foreign_owner_rejected_before_root_lock(tmp_path: Path, process_runner: Callable[..., ProcessResult]) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment"); _ready(process_runner, value, env, toolset)
    before = _ca_state(value)
    wrapper = executable(tmp_path / "stat", """#!/usr/bin/env bash
if [[ $# -eq 3 && $1 == -c && $2 == %u && $3 == "$STAT_OWNER_TARGET" ]]; then printf '%s\n' "$STAT_FAKE_OWNER"; exit 0; fi
exec "$REAL_STAT" "$@"
""")
    result = run(process_runner, _issue(value, toolset, "failure"), dict(env, PATH=f"{wrapper.parent}:{env['PATH']}", REAL_STAT=command_path("stat", env), STAT_OWNER_TARGET=os.fspath(value.pki / "authorities/intermediates/g1-i1/index.txt"), STAT_FAKE_OWNER=str(os.getuid() + 1)))
    assert result.status == 1
    assert "Intermediate CA index is not owned by the current user" in result.stderr
    assert _ca_state(value) == before
    assert not (value.pki / "authorities/roots/g1/.platform-pki-root-operation.lock").exists()


def test_intermediate_lock_contention_preserves_stable_lock(tmp_path: Path, process_runner: Callable[..., ProcessResult]) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment"); _ready(process_runner, value, env, toolset); lock = value.pki / "locks/intermediate"
    before = _ca_state(value)
    with lock.open("r+") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB); result = run(process_runner, _issue(value, toolset, "failure"), env)
    assert result.status == 1
    assert "Another intermediate CA operation is in progress" in result.stderr
    assert lock.is_file()
    assert _ca_state(value) == before


def test_issuance_holds_lifecycle_locks_and_passed_gate_fd(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    process_starter: Callable[..., ManagedProcess],
) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment"); _ready(process_runner, value, env, toolset)
    marker = tmp_path / "paused"; wrapper = executable(tmp_path / "openssl", """#!/usr/bin/env bash
set -euo pipefail
if [[ ${1:-} == ca ]]; then : >"$OPENSSL_PAUSE_MARKER"; IFS= read -r -u "$OPENSSL_GATE_FD" _; fi
exec "$REAL_OPENSSL" "$@"
""")
    gate_read, gate_write = os.pipe()
    try:
        issue_env = dict(env, PATH=f"{wrapper.parent}:{env['PATH']}", REAL_OPENSSL=command_path("openssl", env), OPENSSL_PAUSE_MARKER=os.fspath(marker), OPENSSL_GATE_FD=str(gate_read))
        process = process_starter(_issue(value, toolset, "failure"), env=issue_env, timeout=120, pass_fds=(gate_read,))
        deadline = time.monotonic() + 10
        while not marker.exists() and process.observe().status is None and time.monotonic() < deadline:
            time.sleep(0.02)
        assert marker.exists()
        held_streams = []
        try:
            for name in ("root", "intermediate"):
                stream = (value.pki / f"locks/{name}").open("r+"); held_streams.append(stream)
                with pytest.raises(BlockingIOError): fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            replacement = run(process_runner, [toolset.intermediate, "--namespace", value.namespace, "--name", "Replacement", "--org", "Test", "--country", "PL", "--root-pass-file", value.root_pass, "--intermediate-pass-file", value.intermediate_pass, "--force"], env)
            assert replacement.status == 1
            assert "Another PKI lifecycle operation is in progress" in replacement.stderr
        finally:
            for stream in held_streams: stream.close()
        os.write(gate_write, b"release\n")
        issued = process.wait()
        assert issued.status == 0
        assert_passphrase_content_absent(issued, (value.intermediate_pass,))
    finally:
        os.close(gate_read); os.close(gate_write)
    _assert_no_residue(value)
