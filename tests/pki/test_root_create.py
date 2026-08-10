from __future__ import annotations

import os
import re
import signal
from collections.abc import Callable
from pathlib import Path

import pytest

from src.platform_pki import root_create as root_writer

from ..harness import ProcessResult
from .create_test_support import (
    assert_filesystem_snapshot_unchanged,
    assert_passphrase_content_absent,
    assert_no_glob,
    command_path,
    create_root,
    digest,
    environment,
    executable,
    filesystem_snapshot,
    initialize,
    mode,
    openssl,
    record,
    require_success,
    run,
    tools,
    workspace,
)
from .migration_harness import run_differential_case


pytestmark = pytest.mark.pki
ROOT_CREATE_ORACLE = (
    Path(__file__).parent / "oracles/platform-pki-ca-rollover/platform-pki-root-create"
)
ROOT_CREATE_ORACLE_LIB = ROOT_CREATE_ORACLE.parent / "lib"
_ROOT_TRANSACTION = re.compile(r"root-bootstrap-[0-9]{8}-[0-9]{6}-[0-9]+")
_FULL_IDENTITY = re.compile(
    r"(?P<object>[0-9]+:[0-9]+):(?P<uid>[0-9]+):(?P<mode>[0-7]+):"
    r"(?P<links>[0-9]+):(?P<size>[0-9]+):"
    r"(?P<mtime>[0-9]{4}-.+ [+-][0-9]{4}):"
    r"(?P<ctime>[0-9]{4}-.+ [+-][0-9]{4}):"
    r"(?P<kind>regular empty file|regular file|directory)"
)
_OBJECT_IDENTITY = re.compile(
    r"(?P<object>[0-9]+:[0-9]+):(?P<uid>[0-9]+):(?P<mode>[0-7]+):"
    r"(?P<links>[0-9]+):(?P<size>[0-9]+):"
    r"(?P<kind>regular empty file|regular file|directory)"
)
_DIRECTORY_IDENTITY = re.compile(
    r"(?P<object>[0-9]+:[0-9]+):(?P<uid>[0-9]+):(?P<mode>[0-7]+):directory"
)
_ROOT_IDENTITY_FIELDS = frozenset(
    {
        "authority_identity",
        "stage_identity",
        "transaction_identity",
        "reservation_identity",
        "reservation_reserved_identity",
        "reservation_consumed_identity",
        "reservation_abandoned_identity",
        "bootstrap_identity",
    }
)
_DYNAMIC_RESERVATION_SIZE_FIELDS = frozenset(
    {
        "reservation_identity",
        "reservation_reserved_identity",
        "reservation_consumed_identity",
        "reservation_abandoned_identity",
    }
)


def _root_command(value, toolset, *arguments: str | Path) -> list[str | Path]:
    return [toolset.root, "--namespace", value.namespace, *arguments]


def _normalize_root_token(value: str) -> str:
    return _ROOT_TRANSACTION.sub("<ROOT-BOOTSTRAP>", value)


def _normalize_root_identity(
    value: str,
    labels: dict[str, str],
    *,
    dynamic_size: bool,
) -> str:
    full = _FULL_IDENTITY.fullmatch(value)
    object_state = _OBJECT_IDENTITY.fullmatch(value)
    directory = _DIRECTORY_IDENTITY.fullmatch(value)
    match = full or object_state or directory
    if match is None:
        raise ValueError("Root writer differential identity is malformed")
    object_label = labels.setdefault(
        match["object"], f"<OBJECT-{len(labels) + 1}>"
    )
    if directory is not None:
        return f"{object_label}:{match['uid']}:{match['mode']}:directory"
    size = "<DYNAMIC-SIZE>" if dynamic_size else match["size"]
    normalized = (
        f"{object_label}:{match['uid']}:{match['mode']}:{match['links']}:"
        f"{size}"
    )
    if full is not None:
        normalized += ":<MTIME>:<CTIME>"
    return f"{normalized}:{match['kind']}"


def _root_writer_content_normalizer(*roots: Path):
    root_text = tuple(os.fspath(root) for root in roots)

    def normalize(_relative: str, content: bytes) -> bytes:
        try:
            text = content.decode("ascii")
        except UnicodeDecodeError:
            return content
        lines = text.splitlines(keepends=True)
        if not lines or any(
            re.fullmatch(r"[a-z][a-z0-9_]*=.*\n?", line) is None
            for line in lines
        ):
            return content

        labels: dict[str, str] = {}
        normalized = []
        for line in lines:
            body = line.removesuffix("\n")
            key, value = body.split("=", 1)
            value = _normalize_root_token(value)
            for root in root_text:
                value = value.replace(root, "<WORKSPACE>")
            if key in _ROOT_IDENTITY_FIELDS and value not in {"absent", "none"}:
                value = _normalize_root_identity(
                    value,
                    labels,
                    dynamic_size=key in _DYNAMIC_RESERVATION_SIZE_FIELDS,
                )
            normalized.append(f"{key}={value}\n")
        return "".join(normalized).encode("ascii")

    return normalize


def _deterministic_openssl(tmp_path: Path) -> Path:
    fingerprint = ":".join(("AB",) * 32)
    return executable(
        tmp_path / "openssl",
        f"""#!/usr/bin/env python3
import pathlib
import sys

arguments = sys.argv[1:]
command = arguments[0]

def option(name):
    index = arguments.index(name)
    return pathlib.Path(arguments[index + 1])

if command == "genpkey":
    option("-out").write_bytes(b"DETERMINISTIC ROOT PRIVATE KEY\\n")
elif command == "req":
    option("-out").write_bytes(b"DETERMINISTIC ROOT CERTIFICATE\\n")
elif command == "x509" and "-pubkey" in arguments:
    sys.stdout.write("DETERMINISTIC ROOT PUBLIC KEY\\n")
elif command == "pkey" and "-pubout" in arguments:
    option("-out").write_bytes(b"DETERMINISTIC ROOT PUBLIC KEY\\n")
elif command == "x509" and "-fingerprint" in arguments:
    sys.stdout.write("sha256 Fingerprint={fingerprint}\\n")
else:
    raise SystemExit(97)
""",
    )


@pytest.mark.parametrize(
    ("arguments", "status", "stdout_fragment", "stderr_fragment"),
    (
        pytest.param(("--help",), 0, "Usage:", "", id="help"),
        pytest.param(("--version",), 0, "platform-pki-root-create", "", id="version"),
        pytest.param(("--unknown",), 1, "", "invalid option: --unknown", id="unknown-option"),
        pytest.param(("--org", "Test", "--country", "PL"), 1, "", "missing required flag: --name CN", id="missing-name"),
        pytest.param(("--name", "", "--org", "Test", "--country", "PL"), 1, "", "must not be empty", id="empty-name"),
        pytest.param(("--name", "Test", "--org", "Test", "--country", "PL", "--days", "zero"), 1, "", "Days value must be numeric: zero", id="invalid-days"),
    ),
)
def test_parser_contract(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    arguments: tuple[str, ...],
    status: int,
    stdout_fragment: str,
    stderr_fragment: str,
) -> None:
    toolset = tools()
    env = environment(tmp_path / "environment")
    result = run(process_runner, [toolset.root, *arguments], env)
    assert result.status == status
    assert stdout_fragment in result.stdout
    assert stderr_fragment in result.stderr
    if arguments == ("--help",):
        assert "platform-pki-root-create --version | -v" in result.stdout
        assert "--allow-unencrypted-root-key" in result.stdout
        assert result.stderr == ""
    if arguments == ("--version",):
        assert result.stdout == f"platform-pki-root-create {toolset.version}\n"
        assert result.stderr == ""


@pytest.mark.parametrize("tty", (False, True), ids=("no-color", "tty-color"))
def test_direct_compatibility_help_matches_frozen_bashly_help(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    tty: bool,
) -> None:
    toolset = tools()
    env = environment(tmp_path / "environment")
    pty_mode = None
    if tty:
        env.pop("NO_COLOR")
        pty_mode = "canonical"
    expected = run(
        process_runner,
        [ROOT_CREATE_ORACLE, "--help"],
        env,
        pty_mode=pty_mode,
    )
    actual = run(
        process_runner,
        [toolset.root, "--help"],
        env,
        pty_mode=pty_mode,
    )
    assert (actual.status, actual.stdout, actual.stderr) == (
        expected.status,
        expected.stdout,
        expected.stderr,
    )


def test_environment_days_rejects_non_numeric_value(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    toolset = tools()
    value = workspace(tmp_path / "case")
    env = environment(tmp_path / "environment")
    env["PLATFORM_PKI_ROOT_DAYS"] = "zero"
    result = run(
        process_runner,
        _root_command(
            value,
            toolset,
            "--name",
            "Test",
            "--org",
            "Test",
            "--country",
            "PL",
            "--root-pass-file",
            value.root_pass,
        ),
        env,
    )
    assert result.status == 1
    assert result.stdout == ""
    assert "Days value must be numeric: zero" in result.stderr


def test_handled_signal_is_delivered_after_deferred_state_assignment() -> None:
    delivered = []
    assigned = False

    def handler(signum: int, _frame: object) -> None:
        assert assigned
        delivered.append(signum)

    previous_mask = signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGTERM})
    previous_handler = signal.signal(signal.SIGTERM, handler)
    try:
        with root_writer._defer_handled_signals():
            os.kill(os.getpid(), signal.SIGTERM)
            assert delivered == []
            assigned = True
        assert delivered == [signal.SIGTERM]
    finally:
        signal.signal(signal.SIGTERM, previous_handler)
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


@pytest.mark.parametrize(
    ("kind", "diagnostic"),
    (
        pytest.param("dollar", "PKI directory must not contain OpenSSL variable expansion syntax", id="openssl-variable"),
        pytest.param("newline", "PKI directory must not contain newlines", id="newline"),
    ),
)
def test_invalid_pki_path_creates_no_state(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    kind: str,
    diagnostic: str,
) -> None:
    toolset = tools()
    value = workspace(tmp_path / "case")
    env = environment(tmp_path / "environment")
    invalid = tmp_path / ("pki-$variable" if kind == "dollar" else "pki\nnewline")
    result = run(
        process_runner,
        _root_command(
            value,
            toolset,
            "--pki-dir",
            invalid,
            "--name",
            "Test",
            "--org",
            "Test",
            "--country",
            "PL",
            "--root-pass-file",
            value.root_pass,
        ),
        env,
    )
    assert result.status == 1
    assert result.stdout == ""
    assert diagnostic in result.stderr
    assert not invalid.exists()
    assert not value.namespace.exists()


def test_dn_newline_injection_creates_no_state(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    toolset = tools()
    value = workspace(tmp_path / "case")
    env = environment(tmp_path / "environment")
    result = run(
        process_runner,
        _root_command(
            value,
            toolset,
            "--name",
            "Test\nsubjectAltName = DNS:invalid",
            "--org",
            "Test",
            "--country",
            "PL",
            "--root-pass-file",
            value.root_pass,
        ),
        env,
    )
    assert result.status == 1
    assert result.stdout == ""
    assert "must not contain newlines" in result.stderr
    assert not value.namespace.exists()


def test_encrypted_root_real_openssl_artifacts(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    toolset = tools()
    value = workspace(tmp_path / "case")
    env = environment(tmp_path / "environment")
    initialize(process_runner, value, env, toolset)
    result = create_root(process_runner, value, env, toolset)
    require_success(result, "root creation")
    authority = value.pki / "authorities/roots/g1"
    key = authority / "private/root-ca.key"
    certificate = authority / "certs/root-ca.crt"
    config = authority / "openssl.cnf"
    assert f"[OK] Created root CA generation g1: {certificate}" in result.stdout
    assert result.stderr == ""
    assert (mode(key), mode(certificate), mode(config)) == (0o600, 0o644, 0o600)
    assert openssl(process_runner, ["pkey", "-in", key, "-passin", f"file:{value.root_pass}", "-noout"], env).status == 0
    assert openssl(process_runner, ["pkey", "-in", key, "-passin", "pass:incorrect", "-noout"], env).status != 0
    cert_public = openssl(process_runner, ["x509", "-in", certificate, "-pubkey", "-noout"], env)
    key_public = openssl(process_runner, ["pkey", "-in", key, "-passin", f"file:{value.root_pass}", "-pubout"], env)
    assert cert_public.status == key_public.status == 0
    assert cert_public.stdout == key_public.stdout
    subject = openssl(process_runner, ["x509", "-in", certificate, "-noout", "-subject", "-nameopt", "RFC2253"], env)
    assert subject.status == 0
    assert subject.stdout == "subject=CN=Pytest Root CA,O=Platform Test,C=PL\n"


def test_interactive_passphrase_uses_pty_and_encrypts_key(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    toolset = tools()
    value = workspace(tmp_path / "case")
    env = environment(tmp_path / "environment")
    initialize(process_runner, value, env, toolset)
    secret = value.root_pass.read_text().strip()
    result = run(
        process_runner,
        _root_command(value, toolset, "--name", "Interactive Root", "--org", "Platform Test", "--country", "PL"),
        env,
        input=(f"{secret}\n" * 8),
        pty_mode="canonical",
        controlling_terminal=True,
    )
    assert result.status == 0
    assert_passphrase_content_absent(result, (value.root_pass,))
    key = value.pki / "authorities/roots/g1/private/root-ca.key"
    assert openssl(process_runner, ["pkey", "-in", key, "-passin", f"file:{value.root_pass}", "-noout"], env).status == 0
    assert secret not in result.stdout
    assert secret not in result.stderr


@pytest.mark.parametrize(
    ("source", "days", "minimum", "maximum"),
    (
        pytest.param("default", None, 3649, 3651, id="fallback-3650"),
        pytest.param("environment", None, 1, 3, id="environment-2"),
        pytest.param("cli", 5, 4, 6, id="cli-overrides-environment"),
    ),
)
def test_root_lifetime_precedence(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    source: str,
    days: int | None,
    minimum: int,
    maximum: int,
) -> None:
    toolset = tools()
    value = workspace(tmp_path / "case")
    env = environment(tmp_path / "environment")
    if source != "default":
        env["PLATFORM_PKI_ROOT_DAYS"] = "2"
    initialize(process_runner, value, env, toolset)
    require_success(create_root(process_runner, value, env, toolset, days=days), "root creation")
    certificate = value.pki / "authorities/roots/g1/certs/root-ca.crt"
    assert openssl(process_runner, ["x509", "-in", certificate, "-checkend", str(minimum * 86400), "-noout"], env).status == 0
    assert openssl(process_runner, ["x509", "-in", certificate, "-checkend", str(maximum * 86400), "-noout"], env).status != 0


@pytest.mark.parametrize(
    ("case", "diagnostic"),
    (
        pytest.param("missing", "Passphrase file is missing", id="missing"),
        pytest.param("open-mode", "permissions are too open", id="permissions"),
        pytest.param("short", "at least 16 characters", id="short"),
        pytest.param("conflict", "conflicting options", id="conflicting-unencrypted"),
    ),
)
def test_passphrase_file_validation(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    case: str,
    diagnostic: str,
) -> None:
    toolset = tools()
    value = workspace(tmp_path / "case")
    env = environment(tmp_path / "environment")
    initialize(process_runner, value, env, toolset)
    require_success(create_root(process_runner, value, env, toolset), "root fixture")
    selected = tmp_path / "selected.pass"
    if case == "open-mode":
        selected.write_text("sufficient-test-value\n")
        selected.chmod(0o644)
    elif case == "short":
        selected.write_text("short\n")
        selected.chmod(0o600)
    arguments: list[str | Path] = ["--name", "Test", "--org", "Test", "--country", "PL", "--root-pass-file", selected, "--force"]
    if case == "conflict":
        arguments = ["--name", "Test", "--org", "Test", "--country", "PL", "--root-pass-file", value.root_pass, "--allow-unencrypted-root-key", "--force"]
    result = run(process_runner, _root_command(value, toolset, *arguments), env)
    assert result.status == 1
    assert diagnostic in result.stderr


def test_unencrypted_root_warns_and_matches_certificate(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    toolset = tools()
    value = workspace(tmp_path / "case")
    env = environment(tmp_path / "environment")
    initialize(process_runner, value, env, toolset)
    result = create_root(process_runner, value, env, toolset, unencrypted=True)
    require_success(result, "unencrypted root creation")
    assert "Creating an unencrypted root CA private key" in result.stderr
    authority = value.pki / "authorities/roots/g1"
    key = authority / "private/root-ca.key"
    certificate = authority / "certs/root-ca.crt"
    key_public = openssl(process_runner, ["pkey", "-in", key, "-pubout"], env)
    cert_public = openssl(process_runner, ["x509", "-in", certificate, "-pubkey", "-noout"], env)
    assert key_public.status == cert_public.status == 0
    assert key_public.stdout == cert_public.stdout


def test_force_refuses_existing_bootstrap_without_replacement(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    toolset = tools()
    value = workspace(tmp_path / "case")
    env = environment(tmp_path / "environment")
    initialize(process_runner, value, env, toolset)
    require_success(create_root(process_runner, value, env, toolset), "root fixture")
    authority = value.pki / "authorities/roots/g1"
    bootstrap = value.pki / "state/bootstrap-root"
    authority_before = filesystem_snapshot(authority)
    bootstrap_before = filesystem_snapshot(bootstrap)
    result = run(process_runner, _root_command(value, toolset, "--name", "Replacement", "--org", "Test", "--country", "PL", "--root-pass-file", value.root_pass, "--force"), env)
    assert result.status == 1
    assert "bootstrap root already exists" in result.stderr
    assert_filesystem_snapshot_unchanged(authority, authority_before, "root authority")
    assert_filesystem_snapshot_unchanged(bootstrap, bootstrap_before, "bootstrap manifest")


def test_explicit_pki_directory_is_used(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    toolset = tools()
    value = workspace(tmp_path / "case")
    env = environment(tmp_path / "environment")
    custom = tmp_path / "custom-pki"
    initialize(process_runner, value, env, toolset, pki_dir=custom)
    result = run(process_runner, _root_command(value, toolset, "--pki-dir", custom, "--name", "Custom Root", "--org", "Test", "--country", "PL", "--root-pass-file", value.root_pass), env)
    require_success(result, "custom root creation")
    assert (custom / "authorities/roots/g1/certs/root-ca.crt").is_file()


def test_non_ascii_pki_path_is_rejected_before_control_state_mutation(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    toolset = tools()
    value = workspace(tmp_path / "case")
    env = environment(tmp_path / "environment")
    pki = tmp_path / f"pki-non-ascii-{chr(0xE9)}"
    initialize(process_runner, value, env, toolset, pki_dir=pki)
    before = filesystem_snapshot(pki)

    result = run(
        process_runner,
        _root_command(
            value,
            toolset,
            "--pki-dir",
            pki,
            "--name",
            "Test",
            "--org",
            "Test",
            "--country",
            "PL",
            "--allow-unencrypted-root-key",
        ),
        env,
    )

    assert result.status == 1
    assert result.stdout == ""
    assert "PKI directory must contain only ASCII characters for recovery records" in (
        result.stderr
    )
    assert_filesystem_snapshot_unchanged(pki, before, "PKI directory")


def test_symlinked_pki_path_component_is_rejected_before_mutation(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    toolset = tools()
    value = workspace(tmp_path / "case")
    env = environment(tmp_path / "environment")
    initialize(process_runner, value, env, toolset)
    real_namespace = value.root / "namespace-real"
    value.namespace.rename(real_namespace)
    value.namespace.symlink_to(real_namespace, target_is_directory=True)
    real_pki = real_namespace / "pki"
    before = filesystem_snapshot(real_pki)

    result = create_root(process_runner, value, env, toolset, unencrypted=True)

    assert result.status == 1
    assert (
        f"PKI directory path component must not be a symlink: {value.namespace}"
        in result.stderr
    )
    assert_filesystem_snapshot_unchanged(real_pki, before, "PKI directory")


ROOT_BOUNDARIES = ("after-journal", "after-reservation", "after-reservation-consumed", "after-authority", "after-bootstrap")


@pytest.mark.parametrize(
    "boundary",
    (None, *ROOT_BOUNDARIES),
    ids=("success", *ROOT_BOUNDARIES),
)
def test_frozen_bash_and_python_root_writers_are_semantically_equivalent(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    boundary: str | None,
) -> None:
    toolset = tools()
    seed = workspace(tmp_path / "seed")
    seed_environment = environment(tmp_path / "seed-environment")
    initialize(process_runner, seed, seed_environment, toolset)
    fake_openssl = _deterministic_openssl(tmp_path)
    case_root = tmp_path / "differential"
    base_environment = {
        **seed_environment,
        "PATH": f"{fake_openssl.parent}:{seed_environment['PATH']}",
        "PLATFORM_TOOLS_LIB_DIR": os.fspath(ROOT_CREATE_ORACLE_LIB),
    }
    if boundary is not None:
        base_environment["PLATFORM_PKI_ROOT_FAIL_AT"] = boundary

    def argv(root: Path, command: Path) -> tuple[str | Path, ...]:
        return (
            command,
            "--namespace",
            root / "namespace",
            "--name",
            "Differential Root",
            "--org",
            "Platform Test",
            "--country",
            "PL",
            "--allow-unencrypted-root-key",
        )

    def normalize_output(root: Path, output: str) -> str:
        return _normalize_root_token(
            output.replace(os.fspath(root), "<WORKSPACE>")
        )

    result = run_differential_case(
        seed.root,
        case_root,
        Path("namespace/pki"),
        lambda root: argv(root, ROOT_CREATE_ORACLE),
        lambda root: argv(root, toolset.root),
        base_environment,
        output_normalizers=(normalize_output,),
        content_normalizers=(
            _root_writer_content_normalizer(
                seed.root,
                case_root / "bash",
                case_root / "python",
            ),
        ),
        path_normalizers=(_normalize_root_token,),
        runner=process_runner,
        run_options={"timeout": 120},
    )

    result.assert_equivalent()
    assert result.bash.process.status == (0 if boundary is None else 1)
    after = {entry.path: entry for entry in result.bash.after}
    journal = after["state/rollover/journal"]
    assert (journal.kind, journal.mode, journal.links) == ("file", 0o600, 1)
    for side in ("bash", "python"):
        pki = case_root / side / "namespace/pki"
        journal_record = record(pki / "state/rollover/journal")
        assert tuple(journal_record) == root_writer.ROOT_BOOTSTRAP_WRITER_FIELDS
        assert journal_record["committed"] == "true"
        if boundary is None:
            assert journal_record["phase"] == "complete"
            assert (pki / "authorities/roots/g1/private/root-ca.key").read_bytes() == (
                b"DETERMINISTIC ROOT PRIVATE KEY\n"
            )
            assert (pki / "authorities/roots/g1/certs/root-ca.crt").read_bytes() == (
                b"DETERMINISTIC ROOT CERTIFICATE\n"
            )
        else:
            assert journal_record["phase"] == "rolled-back"
            assert journal_record["recovery_action"] == "rollback"
            assert journal_record["recovery_step"] == "complete"
            assert not (pki / "authorities/roots/g1").exists()
            assert not (pki / "state/bootstrap-root").exists()
            assert record(pki / "state/generation-reservations/g1")["status"] == (
                "abandoned"
            )


@pytest.mark.parametrize("boundary", ROOT_BOUNDARIES, ids=ROOT_BOUNDARIES)
def test_injected_failure_rolls_back_and_closes_journal(
    tmp_path: Path, process_runner: Callable[..., ProcessResult], boundary: str
) -> None:
    toolset = tools()
    value = workspace(tmp_path / "case")
    env = environment(tmp_path / "environment")
    initialize(process_runner, value, env, toolset)
    env["PLATFORM_PKI_ROOT_FAIL_AT"] = boundary
    result = create_root(process_runner, value, env, toolset, unencrypted=True)
    assert result.status == 1
    assert not (value.pki / "authorities/roots/g1").exists()
    assert not (value.pki / "state/bootstrap-root").exists()
    assert record(value.pki / "state/rollover/journal")["committed"] == "true"
    reservation = value.pki / "state/generation-reservations/g1"
    if reservation.exists():
        assert record(reservation)["status"] == "abandoned"


def test_recovery_can_restart_at_every_rollback_checkpoint(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    toolset = tools()
    value = workspace(tmp_path / "case")
    env = environment(tmp_path / "environment")
    initialize(process_runner, value, env, toolset)
    crash_env = dict(env, PLATFORM_PKI_ROOT_CRASH_AT="after-bootstrap")
    assert create_root(process_runner, value, crash_env, toolset, unencrypted=True).status == 137
    transaction = record(value.pki / "state/rollover/journal")["transaction"]
    checkpoints = (
        "rollback-bootstrap-pending", "rollback-bootstrap-done",
        "rollback-authority-pending", "rollback-authority-done",
        "rollback-reservation-pending", "rollback-reservation-done",
    )
    command = [toolset.recover, "recover", "--namespace", value.namespace, "--transaction", transaction, "--action", "rollback", "--yes"]
    for checkpoint in checkpoints:
        assert run(process_runner, command, dict(env, PLATFORM_PKI_RECOVER_CRASH_AT=checkpoint)).status == 137
    assert run(process_runner, command, env).status == 0
    assert record(value.pki / "state/generation-reservations/g1")["status"] == "abandoned"


def test_handled_failure_retry_allocates_next_generation(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    toolset = tools()
    value = workspace(tmp_path / "case")
    env = environment(tmp_path / "environment")
    initialize(process_runner, value, env, toolset)
    assert create_root(process_runner, value, dict(env, PLATFORM_PKI_ROOT_FAIL_AT="after-reservation"), toolset, unencrypted=True).status == 1
    require_success(create_root(process_runner, value, env, toolset, unencrypted=True), "root retry")
    assert record(value.pki / "state/bootstrap-root")["root"] == "g2"
    assert record(value.pki / "state/generation-reservations/g1")["status"] == "abandoned"
    assert record(value.pki / "state/generation-reservations/g2")["status"] == "consumed"


@pytest.mark.parametrize("boundary", ROOT_BOUNDARIES, ids=ROOT_BOUNDARIES)
def test_crash_recovery_abandons_generation_and_retry_advances(
    tmp_path: Path, process_runner: Callable[..., ProcessResult], boundary: str
) -> None:
    toolset = tools()
    value = workspace(tmp_path / "case")
    env = environment(tmp_path / "environment")
    initialize(process_runner, value, env, toolset)
    assert create_root(process_runner, value, dict(env, PLATFORM_PKI_ROOT_CRASH_AT=boundary), toolset, unencrypted=True).status == 137
    transaction = record(value.pki / "state/rollover/journal")["transaction"]
    recovered = run(process_runner, [toolset.recover, "recover", "--namespace", value.namespace, "--transaction", transaction, "--action", "rollback", "--yes"], env)
    assert recovered.status == 0
    assert not (value.pki / "authorities/roots/g1").exists()
    assert not (value.pki / "state/bootstrap-root").exists()
    assert record(value.pki / "state/generation-reservations/g1")["status"] == "abandoned"
    require_success(create_root(process_runner, value, env, toolset, unencrypted=True), "root retry")
    assert record(value.pki / "state/bootstrap-root")["root"] == "g2"


def test_signal_rolls_back_authority(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    toolset = tools()
    value = workspace(tmp_path / "case")
    env = environment(tmp_path / "environment")
    initialize(process_runner, value, env, toolset)
    result = create_root(process_runner, value, dict(env, PLATFORM_PKI_ROOT_SIGNAL_AT="after-authority"), toolset, unencrypted=True)
    assert result.status == 143
    assert not (value.pki / "authorities/roots/g1").exists()
    assert not (value.pki / "state/bootstrap-root").exists()


def test_openssl_failure_does_not_publish_root(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    toolset = tools()
    value = workspace(tmp_path / "case")
    env = environment(tmp_path / "environment")
    initialize(process_runner, value, env, toolset)
    wrapper = executable(tmp_path / "openssl", """#!/usr/bin/env bash
[[ ${1:-} != req ]] || exit 42
exec "$REAL_OPENSSL" "$@"
""")
    failure_env = dict(env, PATH=f"{wrapper.parent}:{env['PATH']}", REAL_OPENSSL=command_path("openssl", env))
    result = create_root(process_runner, value, failure_env, toolset, unencrypted=True)
    assert result.status == 42
    assert not (value.pki / "authorities/roots/g1").exists()


def test_force_preserves_symlink_generation(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    toolset = tools()
    value = workspace(tmp_path / "case")
    env = environment(tmp_path / "environment")
    initialize(process_runner, value, env, toolset)
    foreign = tmp_path / "foreign"
    foreign.mkdir(mode=0o700)
    sentinel = foreign / "sentinel"
    sentinel.write_text("foreign-root-state\n")
    sentinel.chmod(0o600)
    generation = value.pki / "authorities/roots/g1"
    generation.symlink_to(foreign, target_is_directory=True)
    generation_before = filesystem_snapshot(generation)
    foreign_before = filesystem_snapshot(foreign)
    result = run(process_runner, _root_command(value, toolset, "--name", "Hostile", "--org", "Test", "--country", "PL", "--allow-unencrypted-root-key", "--force"), env)
    assert result.status == 1
    assert generation.is_symlink()
    assert foreign.is_dir()
    assert filesystem_snapshot(generation) == generation_before
    assert filesystem_snapshot(foreign) == foreign_before


@pytest.mark.parametrize("hostile_case", ("key-symlink", "db-hardlink", "writable-dir"), ids=("key-symlink", "database-hardlink", "writable-directory"))
def test_force_preserves_hostile_partial_generation(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    hostile_case: str,
) -> None:
    toolset = tools()
    value = workspace(tmp_path / "case")
    env = environment(tmp_path / "environment")
    initialize(process_runner, value, env, toolset)
    authority = value.pki / "authorities/roots/g1"
    (authority / "private").mkdir(mode=0o700, parents=True)
    (authority / "certs").mkdir(mode=0o700)
    external: Path | None = None
    if hostile_case == "key-symlink":
        victim = tmp_path / "victim"
        victim.write_text("sentinel\n")
        victim.chmod(0o600)
        (authority / "private/root-ca.key").symlink_to(victim)
        external = victim
    elif hostile_case == "db-hardlink":
        serial = authority / "serial"
        serial.write_text("sentinel\n")
        serial.chmod(0o600)
        external = tmp_path / "hardlink"
        os.link(serial, external)
    else:
        (authority / "certs").chmod(0o777)
    authority_before = filesystem_snapshot(authority)
    external_before = None if external is None else filesystem_snapshot(external)
    result = run(process_runner, _root_command(value, toolset, "--name", "Hostile", "--org", "Test", "--country", "PL", "--allow-unencrypted-root-key", "--force"), env)
    assert result.status == 1
    assert authority.is_dir() and not authority.is_symlink()
    assert filesystem_snapshot(authority) == authority_before
    if external is not None:
        assert filesystem_snapshot(external) == external_before
    assert_no_glob(authority, ".platform-pki-root-create.*")
