from __future__ import annotations

import fcntl
import os
import re
import stat
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import pytest

from src.platform_pki import ca_rollover_recovery as recovery_schema
from src.platform_pki import ca_rollover_migrate as rollover_migrate
from src.platform_pki import ca_rollover_status as rollover_status
from src.platform_pki import intermediate_create as intermediate_writer
from src.platform_pki.errors import ApplicationError
from src.platform_pki.filesystem import FileIdentity

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
from .migration_harness import run_differential_case


pytestmark = pytest.mark.pki
INTERMEDIATE_CREATE_ORACLE = (
    Path(__file__).parent
    / "oracles/platform-pki-ca-rollover/platform-pki-intermediate-create"
)
INTERMEDIATE_CREATE_ORACLE_LIB = INTERMEDIATE_CREATE_ORACLE.parent / "lib"

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
_INTERMEDIATE_TRANSACTION = re.compile(
    r"intermediate-bootstrap-[0-9]{8}-[0-9]{6}-[0-9]+"
)
_INTERMEDIATE_STAGE = re.compile(
    r"\.platform-pki-intermediate-create\.[A-Za-z0-9_-]+"
)
_IDENTITY_FIELD = re.compile(
    r"(?:^|_)(?:identity|pre_identity|post_identity|backup_identity)$"
)


def _command(value, toolset, *arguments: str | Path) -> list[str | Path]:
    return [*toolset.intermediate, "--namespace", value.namespace, *arguments]


def _bootstrap(process_runner, value, env, toolset) -> None:
    initialize(process_runner, value, env, toolset)
    require_success(create_root(process_runner, value, env, toolset), "root fixture")


def _create_command(value, toolset, *, unencrypted: bool = True) -> list[str | Path]:
    result: list[str | Path] = [
        *toolset.intermediate, "--namespace", value.namespace,
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


def _passphrase_observing_openssl(tmp_path: Path, value, env) -> tuple[Path, Path]:
    log = tmp_path / "openssl-passphrase-boundary.log"
    wrapper = executable(
        tmp_path / "openssl",
        f"""#!/usr/bin/env python3
import os
import pathlib
import sys

REAL_OPENSSL = {command_path("openssl", env)!r}
ROOT_PATH = {os.fspath(value.root_pass)!r}
INTERMEDIATE_PATH = {os.fspath(value.intermediate_pass)!r}
ROOT_SECRET = {value.root_pass.read_text()!r}
INTERMEDIATE_SECRET = {value.intermediate_pass.read_text()!r}
LOG = {os.fspath(log)!r}

arguments = sys.argv[1:]
argv_text = "\\0".join(arguments)
environment_text = "\\0".join(f"{{key}}={{item}}" for key, item in os.environ.items())
for forbidden in (ROOT_PATH, INTERMEDIATE_PATH, ROOT_SECRET.strip(), INTERMEDIATE_SECRET.strip()):
    if forbidden in argv_text or forbidden in environment_text:
        raise SystemExit(91)

sensitive = {{}}
for entry in pathlib.Path("/proc/self/fd").iterdir():
    try:
        descriptor = int(entry.name)
        if os.path.samefile(entry, ROOT_PATH):
            sensitive[descriptor] = "root"
        elif os.path.samefile(entry, INTERMEDIATE_PATH):
            sensitive[descriptor] = "intermediate"
    except (FileNotFoundError, OSError, ValueError):
        pass

command = arguments[0]
expected = {{"genpkey": ("intermediate", "-pass"), "req": ("intermediate", "-passin"), "ca": ("root", "-passin")}}.get(command)
fd_arguments = [argument for argument in arguments if argument.startswith("fd:")]
if expected is None:
    if sensitive or fd_arguments:
        raise SystemExit(92)
    observed = "none"
else:
    channel, option = expected
    if len(sensitive) != 1 or list(sensitive.values()) != [channel]:
        raise SystemExit(93)
    if option not in arguments:
        raise SystemExit(94)
    token = arguments[arguments.index(option) + 1]
    if len(fd_arguments) != 1 or token != fd_arguments[0]:
        raise SystemExit(95)
    try:
        descriptor = int(token.removeprefix("fd:"))
    except ValueError:
        raise SystemExit(96)
    if sensitive.get(descriptor) != channel:
        raise SystemExit(97)
    expected_content = ROOT_SECRET if channel == "root" else INTERMEDIATE_SECRET
    if os.pread(descriptor, 4096, 0).decode("utf-8") != expected_content:
        raise SystemExit(98)
    observed = channel

with open(LOG, "a", encoding="ascii") as stream:
    stream.write(f"{{command}}:{{observed}}:{{len(sensitive)}}\\n")
os.execv(REAL_OPENSSL, [REAL_OPENSSL, *arguments])
""",
    )
    return wrapper, log


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
    return [*toolset.recover, "recover", "--namespace", value.namespace, "--transaction", transaction, "--action", action, "--yes"]


def _normalize_intermediate_token(value: str) -> str:
    return _INTERMEDIATE_STAGE.sub(
        "<INTERMEDIATE-STAGE>",
        _INTERMEDIATE_TRANSACTION.sub("<INTERMEDIATE-BOOTSTRAP>", value),
    )


def _intermediate_writer_content_normalizer(*roots: Path):
    root_text = tuple(os.fspath(root) for root in roots)

    def normalize(relative: str, content: bytes) -> bytes:
        if re.search(
            r"(?:^|/)(?:private/intermediate-ca\.key|csr/intermediate-ca\.csr|"
            r"certs/(?:intermediate-ca\.crt|ca-chain\.crt)|newcerts/[0-9A-F]+\.pem)$",
            relative,
        ) or relative == "authorities/roots/g1/index.txt" or re.fullmatch(
            r"authorities/intermediates/\.platform-pki-intermediate-create\."
            r"[A-Za-z0-9_-]+/root/index\.txt",
            relative,
        ):
            return b"<DYNAMIC-OPENSSL-CONTENT>\n"
        try:
            text = content.decode("ascii")
        except UnicodeDecodeError:
            return content
        text = _normalize_intermediate_token(text)
        for root in root_text:
            text = text.replace(root, "<WORKSPACE>")
        lines = text.splitlines(keepends=True)
        if lines and all(
            re.fullmatch(r"[a-z][a-z0-9_]*=.*\n?", line) is not None
            for line in lines
        ):
            normalized = []
            rolled_back = "phase=rolled-back\n" in text
            for line in lines:
                body = line.removesuffix("\n")
                key, value = body.split("=", 1)
                if rolled_back and key in {
                    "stage_dir",
                    "stage_identity",
                    "root_stage",
                    "root_stage_identity",
                }:
                    value = "<CLEANED-STAGE>"
                elif _IDENTITY_FIELD.search(key) and value not in {
                    "absent",
                    "none",
                    "pending",
                }:
                    value = "<IDENTITY>"
                elif key == "fingerprint_sha256":
                    value = "<FINGERPRINT>"
                elif key == "recovery_step" and value in {
                    "reservation-done",
                    "complete",
                }:
                    value = "<TERMINAL-ROLLBACK>"
                normalized.append(f"{key}={value}\n")
            return "".join(normalized).encode("ascii")
        return text.encode("ascii")

    return normalize


@pytest.mark.parametrize(
    ("arguments", "status", "stdout_fragment", "stderr_fragment"),
    (
        pytest.param(("--help",), 0, "Usage:", "", id="help"),
        pytest.param(("--version",), 1, "", "invalid option: --version", id="version"),
        pytest.param(("--unknown",), 1, "", "invalid option: --unknown", id="unknown-option"),
        pytest.param(("--org", "Test", "--country", "PL"), 1, "", "missing required flag: --name CN", id="missing-name"),
        pytest.param(("--name", "Test", "--org", "Test", "--country", "PL", "--days", "zero"), 1, "", "Days value must be numeric: zero", id="invalid-days"),
        pytest.param(("--name", "Test", "--org", "Test", "--country", "PL", "--days="), 1, "", "invalid option: --days=", id="empty-days"),
    ),
)
def test_parser_contract(tmp_path: Path, process_runner: Callable[..., ProcessResult], arguments: tuple[str, ...], status: int, stdout_fragment: str, stderr_fragment: str) -> None:
    toolset = tools()
    result = run(process_runner, [*toolset.intermediate, *arguments], environment(tmp_path / "environment"))
    assert result.status == status
    assert stdout_fragment in result.stdout
    assert stderr_fragment in result.stderr
    if arguments == ("--help",):
        assert "Usage: platform-pki intermediate-create" in result.stdout
        assert "--allow-unencrypted-intermediate-key" in result.stdout
        assert result.stderr == ""
def test_writer_contract_has_exact_database_and_field_order() -> None:
    assert intermediate_writer.ROOT_DB_KEYS == (*ROOT_DB, "newcert")
    assert len(intermediate_writer.INTERMEDIATE_BOOTSTRAP_WRITER_FIELDS) == 56


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


@pytest.mark.parametrize(
    "case",
    (
        "root-key-mode",
        "root-certificate-mode",
        "required-database-mode",
        "optional-database-mode",
        "database-hardlink",
        "root-key-symlink",
    ),
)
def test_root_sources_require_exact_authoritative_policies(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    case: str,
) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment")
    _bootstrap(process_runner, value, env, toolset)
    root = value.pki / "authorities/roots/g1"
    external: Path | None = None
    if case == "root-key-mode":
        (root / "private/root-ca.key").chmod(0o640)
    elif case == "root-certificate-mode":
        (root / "certs/root-ca.crt").chmod(0o600)
    elif case == "required-database-mode":
        (root / "index.txt").chmod(0o640)
    elif case == "optional-database-mode":
        path = root / "index.txt.old"; path.write_text("unsafe optional database\n"); path.chmod(0o640)
    elif case == "database-hardlink":
        external = tmp_path / "serial-hardlink"; os.link(root / "serial", external)
    else:
        key = root / "private/root-ca.key"; external = tmp_path / "root-key"; key.rename(external); key.symlink_to(external)
    before = filesystem_snapshot(root)
    external_before = None if external is None else filesystem_snapshot(external)

    result = run(process_runner, _create_command(value, toolset), env)

    assert result.status == 1
    assert filesystem_snapshot(root) == before
    if external is not None:
        assert filesystem_snapshot(external) == external_before
    assert not (value.pki / "authorities/intermediates/g1-i1").exists()
    assert (value.pki / "state/bootstrap-root").is_file()


def test_root_database_source_replacement_is_detected_after_both_descriptor_copies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "serial"; source.write_text("1000\n"); source.chmod(0o600)
    staged = tmp_path / "staged"; backup = tmp_path / "backup"
    original_copy = intermediate_writer._copy_opened_file
    calls = 0

    def replace_after_first_copy(
        opened, destination: str, destination_mode: int
    ) -> FileIdentity:
        nonlocal calls
        copied = original_copy(opened, destination, destination_mode)
        calls += 1
        if calls == 1:
            replacement = tmp_path / "replacement"
            replacement.write_text("2000\n"); replacement.chmod(0o600)
            replacement.replace(source)
        return copied

    monkeypatch.setattr(intermediate_writer, "_copy_opened_file", replace_after_first_copy)

    with pytest.raises(ApplicationError, match="changed while being copied"):
        intermediate_writer._copy_root_database_source(
            os.fspath(source), os.fspath(staged), os.fspath(backup), required=True
        )

    assert calls == 2
    assert staged.read_bytes() == backup.read_bytes() == b"1000\n"
    assert source.read_bytes() == b"2000\n"


def test_root_certificate_replacement_after_staging_fails_before_mutation(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment")
    _bootstrap(process_runner, value, env, toolset)
    root = value.pki / "authorities/roots/g1"
    root_certificate = root / "certs/root-ca.crt"
    original_certificate = root_certificate.read_bytes()
    original_inode = root_certificate.stat().st_ino
    database_before = _db_snapshot(value)
    marker = tmp_path / "root-certificate-replaced"
    log = tmp_path / "openssl-race.log"
    wrapper = executable(
        tmp_path / "openssl",
        f"""#!/usr/bin/env python3
import os
import pathlib
import sys

REAL_OPENSSL = {command_path("openssl", env)!r}
ROOT_CERTIFICATE = pathlib.Path({os.fspath(root_certificate)!r})
MARKER = pathlib.Path({os.fspath(marker)!r})
LOG = pathlib.Path({os.fspath(log)!r})
arguments = sys.argv[1:]
with LOG.open("a", encoding="utf-8") as stream:
    stream.write(repr(arguments) + "\\n")
if arguments[0] == "genpkey" and not MARKER.exists():
    replacement = ROOT_CERTIFICATE.with_name("root-ca.crt.replacement")
    replacement.write_bytes(ROOT_CERTIFICATE.read_bytes())
    replacement.chmod(0o644)
    os.replace(replacement, ROOT_CERTIFICATE)
    MARKER.write_text("replaced\\n", encoding="ascii")
os.execv(REAL_OPENSSL, [REAL_OPENSSL, *arguments])
""",
    )
    race_environment = dict(env, PATH=f"{wrapper.parent}:{env['PATH']}")

    result = run(process_runner, _create_command(value, toolset), race_environment)

    assert result.status == 1
    assert "Root certificate identity changed during intermediate creation" in result.stderr
    assert marker.is_file()
    assert root_certificate.read_bytes() == original_certificate
    assert root_certificate.stat().st_ino != original_inode
    assert _db_snapshot(value) == database_before
    assert not (value.pki / "authorities/intermediates/g1-i1").exists()
    assert not (value.pki / "state/active-issuer").exists()
    assert (value.pki / "state/bootstrap-root").is_file()
    assert record(value.pki / "state/generation-reservations/g1-i1")["status"] == (
        "abandoned"
    )
    invocations = log.read_text().splitlines()
    assert any("'verify'" in invocation for invocation in invocations)
    assert sum("'x509'" in invocation for invocation in invocations) >= 4
    assert all(os.fspath(root_certificate) not in invocation for invocation in invocations)
    assert any("'/proc/self/fd/" in invocation for invocation in invocations)


def test_root_key_replacement_after_staging_fails_before_mutation(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment")
    _bootstrap(process_runner, value, env, toolset)
    root = value.pki / "authorities/roots/g1"
    root_key = root / "private/root-ca.key"
    original_key = root_key.read_bytes()
    original_inode = root_key.stat().st_ino
    database_before = _db_snapshot(value)
    marker = tmp_path / "root-key-replaced"
    log = tmp_path / "openssl-key-race.log"
    wrapper = executable(
        tmp_path / "openssl",
        f"""#!/usr/bin/env python3
import os
import pathlib
import sys

REAL_OPENSSL = {command_path("openssl", env)!r}
ROOT_KEY = pathlib.Path({os.fspath(root_key)!r})
MARKER = pathlib.Path({os.fspath(marker)!r})
LOG = pathlib.Path({os.fspath(log)!r})
arguments = sys.argv[1:]
with LOG.open("a", encoding="utf-8") as stream:
    stream.write(repr(arguments) + "\\n")
if arguments[0] == "genpkey" and not MARKER.exists():
    replacement = ROOT_KEY.with_name("root-ca.key.replacement")
    replacement.write_bytes(ROOT_KEY.read_bytes())
    replacement.chmod(0o600)
    os.replace(replacement, ROOT_KEY)
    MARKER.write_text("replaced\\n", encoding="ascii")
os.execv(REAL_OPENSSL, [REAL_OPENSSL, *arguments])
""",
    )
    race_environment = dict(env, PATH=f"{wrapper.parent}:{env['PATH']}")

    result = run(process_runner, _create_command(value, toolset), race_environment)

    assert result.status == 1
    assert "Root key identity changed during intermediate creation" in result.stderr
    assert marker.is_file()
    assert root_key.read_bytes() == original_key
    assert root_key.stat().st_ino != original_inode
    assert _db_snapshot(value) == database_before
    assert not (value.pki / "authorities/intermediates/g1-i1").exists()
    assert not (value.pki / "state/active-issuer").exists()
    assert (value.pki / "state/bootstrap-root").is_file()
    assert record(value.pki / "state/generation-reservations/g1-i1")["status"] == (
        "abandoned"
    )
    invocations = log.read_text().splitlines()
    assert any("'ca'" in invocation for invocation in invocations)
    assert any("'verify'" in invocation for invocation in invocations)
    assert all(os.fspath(root_key) not in invocation for invocation in invocations)


def test_passphrases_cross_only_the_applicable_openssl_descriptor_boundary(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    toolset = tools(); value = workspace(tmp_path / "case"); env = environment(tmp_path / "environment")
    _bootstrap(process_runner, value, env, toolset)
    wrapper, log = _passphrase_observing_openssl(tmp_path, value, env)
    observed_env = dict(env, PATH=f"{wrapper.parent}:{env['PATH']}")

    result = run(process_runner, _create_command(value, toolset, unencrypted=False), observed_env)

    require_success(result, "descriptor-observed intermediate creation")
    observations = log.read_text().splitlines()
    assert observations.count("genpkey:intermediate:1") == 1
    assert observations.count("req:intermediate:1") == 1
    assert observations.count("ca:root:1") == 1
    assert all(
        observation.endswith(":none:0")
        for observation in observations
        if not observation.startswith(("genpkey:", "req:", "ca:"))
    )
    assert any(observation.startswith("verify:none:0") for observation in observations)
    assert sum(observation.startswith("x509:none:0") for observation in observations) >= 4


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
    assert record(value.pki / "state/rollover/journal")["recovery_step"] == "complete"
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


@pytest.mark.parametrize(
    "boundary",
    (None, "after-root-db"),
    ids=("success", "root-database-failure"),
)
def test_frozen_bash_and_python_intermediate_writers_are_semantically_equivalent(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    boundary: str | None,
) -> None:
    toolset = tools()
    seed = workspace(tmp_path / "seed")
    seed_environment = environment(tmp_path / "seed-environment")
    initialize(process_runner, seed, seed_environment, toolset)
    require_success(
        create_root(process_runner, seed, seed_environment, toolset),
        "intermediate differential root",
    )
    # Its terminal journal binds the seed's absolute path and is not test input.
    (seed.pki / "state/rollover/journal").unlink()
    case_root = tmp_path / "differential"
    base_environment = {
        **seed_environment,
        "PLATFORM_TOOLS_LIB_DIR": os.fspath(INTERMEDIATE_CREATE_ORACLE_LIB),
    }
    if boundary is not None:
        base_environment["PLATFORM_PKI_INTERMEDIATE_FAIL_AT"] = boundary

    def argv(root: Path, command: Path | tuple[Path | str, ...]) -> tuple[str | Path, ...]:
        prefix = (command,) if isinstance(command, Path) else command
        return (
            *prefix,
            "--namespace",
            root / "namespace",
            "--name",
            "Differential Intermediate",
            "--org",
            "Platform Test",
            "--country",
            "PL",
            "--root-pass-file",
            root / "root.pass",
            "--allow-unencrypted-intermediate-key",
        )

    def normalize_output(root: Path, output: str) -> str:
        normalized = _normalize_intermediate_token(
            output.replace(os.fspath(root), "<WORKSPACE>")
        )
        return re.sub(
            r"Certificate is to be certified until .* \([0-9]+ days\)",
            "Certificate is to be certified until <DYNAMIC-DATE>",
            normalized,
        )

    result = run_differential_case(
        seed.root,
        case_root,
        Path("namespace/pki"),
        lambda root: argv(root, INTERMEDIATE_CREATE_ORACLE),
        lambda root: argv(root, toolset.intermediate),
        base_environment,
        output_normalizers=(normalize_output,),
        content_normalizers=(
            _intermediate_writer_content_normalizer(
                seed.root,
                case_root / "bash",
                case_root / "python",
            ),
        ),
        path_normalizers=(_normalize_intermediate_token,),
        runner=process_runner,
        run_options={"timeout": 120},
    )

    result.assert_equivalent()
    assert result.bash.process.status == (0 if boundary is None else 1)
    if boundary is not None:
        bash_pki = case_root / "bash/namespace/pki"
        terminal = record(bash_pki / "state/rollover/journal")
        assert terminal["phase"] == "rolled-back"
        assert terminal["recovery_action"] == "rollback"
        assert terminal["recovery_step"] == "reservation-done"
        assert terminal["committed"] == "true"
        parsed = recovery_schema.parse_recovery_semantics(
            (bash_pki / "state/rollover/journal").read_bytes(), pki_dir=bash_pki
        )
        assert recovery_schema.is_terminal_bootstrap_record(parsed)
        assert not recovery_schema.is_terminal_bootstrap_record(
            replace(parsed, committed=False)
        )
        assert not recovery_schema.is_terminal_bootstrap_record(
            replace(parsed, phase="recovering")
        )
        assert not recovery_schema.is_terminal_bootstrap_record(
            replace(parsed, recovery_step="root-index-done")
        )
        malformed = (bash_pki / "state/rollover/journal").read_bytes().replace(
            b"recovery_step=reservation-done\n",
            b"recovery_step=root-index-done\n",
        )
        with pytest.raises(
            recovery_schema.RecoveryRecordError,
            match="recovery path root_stage is outside its contract",
        ):
            recovery_schema.parse_recovery_semantics(malformed, pki_dir=bash_pki)
        assert not (bash_pki / "state/rollover/recovery-required").exists()
        retained = []
        rollover_status._require_no_unresolved_journal(
            os.fspath(bash_pki), retained, []
        )
        for opened in retained:
            opened.close()
        assert isinstance(
            rollover_migrate._terminal_journal_identity(
                os.fspath(bash_pki / "state/rollover/journal"),
                os.fspath(bash_pki),
            ),
            FileIdentity,
        )
        retry_environment = dict(base_environment)
        retry_environment.pop("PLATFORM_PKI_INTERMEDIATE_FAIL_AT")
        require_success(
            run(
                process_runner,
                argv(case_root / "bash", toolset.intermediate),
                retry_environment,
            ),
            "Python retry from frozen intermediate rollback",
        )
        assert record(
            bash_pki / "state/active-issuer"
        )["intermediate"] == "g1-i2"


@pytest.mark.parametrize(
    ("boundary", "action"),
    (
        pytest.param("root-index-pending", "rollback", id="root-database-pending"),
        pytest.param("cleanup-pending", "resume", id="cleanup-pending"),
    ),
)
def test_sigkill_persisted_state_matches_frozen_writer_and_python_recovers(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    boundary: str,
    action: str,
) -> None:
    toolset = tools()
    seed = workspace(tmp_path / "seed")
    seed_environment = environment(tmp_path / "seed-environment")
    initialize(process_runner, seed, seed_environment, toolset)
    require_success(
        create_root(process_runner, seed, seed_environment, toolset),
        "intermediate SIGKILL differential root",
    )
    # Its terminal journal binds the seed's absolute path and is not test input.
    (seed.pki / "state/rollover/journal").unlink()
    case_root = tmp_path / "differential"
    crash_environment = {
        **seed_environment,
        "PLATFORM_TOOLS_LIB_DIR": os.fspath(INTERMEDIATE_CREATE_ORACLE_LIB),
        "PLATFORM_PKI_INTERMEDIATE_CRASH_AT": boundary,
    }

    def argv(root: Path, command: Path | tuple[Path | str, ...]) -> tuple[str | Path, ...]:
        prefix = (command,) if isinstance(command, Path) else command
        return (
            *prefix,
            "--namespace",
            root / "namespace",
            "--name",
            "Differential Intermediate",
            "--org",
            "Platform Test",
            "--country",
            "PL",
            "--root-pass-file",
            root / "root.pass",
            "--allow-unencrypted-intermediate-key",
        )

    def normalize_output(root: Path, output: str) -> str:
        normalized = _normalize_intermediate_token(
            output.replace(os.fspath(root), "<WORKSPACE>")
        )
        return re.sub(
            r"Certificate is to be certified until .* \([0-9]+ days\)",
            "Certificate is to be certified until <DYNAMIC-DATE>",
            normalized,
        )

    result = run_differential_case(
        seed.root,
        case_root,
        Path("namespace/pki"),
        lambda root: argv(root, INTERMEDIATE_CREATE_ORACLE),
        lambda root: argv(root, toolset.intermediate),
        crash_environment,
        output_normalizers=(normalize_output,),
        content_normalizers=(
            _intermediate_writer_content_normalizer(
                seed.root,
                case_root / "bash",
                case_root / "python",
            ),
        ),
        path_normalizers=(_normalize_intermediate_token,),
        runner=process_runner,
        run_options={"timeout": 120},
    )

    result.assert_equivalent()
    assert result.bash.process.status == result.python.process.status == 137
    python_root = case_root / "python"
    python_pki = python_root / "namespace/pki"
    journal_before = record(python_pki / "state/rollover/journal")
    root_stage = Path(journal_before["root_stage"])
    recovery_environment = dict(crash_environment)
    recovery_environment.pop("PLATFORM_PKI_INTERMEDIATE_CRASH_AT")
    unified = Path(__file__).parents[2] / "bin/platform-pki"

    recovered = run(
        process_runner,
        [
            unified,
            "ca-rollover",
            "recover",
            "--namespace",
            python_root / "namespace",
            "--transaction",
            journal_before["transaction"],
            "--action",
            action,
            "--yes",
        ],
        recovery_environment,
    )

    assert recovered.status == 0, recovered.stderr
    terminal = record(python_pki / "state/rollover/journal")
    assert terminal["committed"] == "true"
    assert not root_stage.exists()
    if action == "rollback":
        assert terminal["phase"] == "rolled-back"
        assert (python_pki / "state/bootstrap-root").is_file()
        assert not (python_pki / "state/active-issuer").exists()
        assert record(
            python_pki / "state/generation-reservations/g1-i1"
        )["status"] == "abandoned"
    else:
        assert terminal["phase"] == "complete"
        assert not (python_pki / "state/bootstrap-root").exists()
        assert (python_pki / "state/active-issuer").is_file()
        assert (python_pki / "authorities/intermediates/g1-i1").is_dir()
