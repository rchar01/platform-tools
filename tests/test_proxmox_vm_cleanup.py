from __future__ import annotations

import os
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]
TOOL = ROOT / "bin/platform-proxmox-vm-cleanup"
FAKES = ROOT / "tests/proxmox-vm-cleanup/fake-bin"
NONCE_RE = re.compile(r"^[a-f0-9]{64}$")


def _which(name: str) -> str:
    for directory in os.environ["PATH"].split(os.pathsep):
        path = Path(directory) / name
        if path.exists():
            return os.fspath(path.resolve())
    raise RuntimeError(f"required test command missing: {name}")


@pytest.fixture
def cleanup_env(tmp_path, process_runner, process_starter):
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    for path in FAKES.iterdir():
        (fake_bin / path.name).symlink_to(path)
    logs = {name: tmp_path / f"{name}.log" for name in ("qm", "operations", "ssh", "argv", "fd")}
    auth_dir = tmp_path / "authorizations"
    env = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "FAKE_QM_LOG": os.fspath(logs["qm"]),
        "FAKE_QM_OPERATION_LOG": os.fspath(logs["operations"]),
        "FAKE_SSH_LOG": os.fspath(logs["ssh"]),
        "FAKE_REMOTE_CHILD_ARGV_LOG": os.fspath(logs["argv"]),
        "FAKE_FD_LOG": os.fspath(logs["fd"]),
        "PLATFORM_VM_CLEANUP_AUTH_DIR": os.fspath(auth_dir),
        "REAL_MV": _which("mv"), "REAL_LN": _which("ln"),
        "REAL_RM": _which("rm"), "REAL_BASH": _which("bash"),
        "REAL_STAT": _which("stat"),
        "FAKE_VM_EXISTS": "1", "FAKE_VM_STATUS": "stopped",
        "FAKE_VM_NAME": "fixture-vm", "FAKE_DESTROY_SUPPORTS_UNREFERENCED": "1",
    }

    class CleanupTool:
        def reset(self):
            for path in logs.values():
                path.write_text("")

        def run(self, *args: str, update=None, input: str | bytes | None = None, pty=False):
            self.reset()
            effective = {**env, **(update or {})}
            if pty:
                return process_runner((TOOL, *args), env=effective, input=input, pty_mode="canonical")
            return process_runner((TOOL, *args), env=effective, input=input)

        def run_fd3(self, *args: str, payload: bytes, update=None):
            self.reset()
            read_fd, write_fd = os.pipe()
            try:
                view = memoryview(payload)
                while view:
                    view = view[os.write(write_fd, view):]
                os.close(write_fd)
                write_fd = -1
                return process_runner(
                    (TOOL, *args),
                    env={**env, **(update or {})},
                    fd_mappings=((read_fd, 3),),
                )
            finally:
                for descriptor in (read_fd, write_fd):
                    if descriptor >= 0:
                        os.close(descriptor)

        def start_fd3(self, *args: str, payload: bytes):
            read_fd, write_fd = os.pipe()
            try:
                view = memoryview(payload)
                while view:
                    view = view[os.write(write_fd, view):]
                os.close(write_fd)
                write_fd = -1
                return process_starter(
                    (TOOL, *args),
                    env=env,
                    fd_mappings=((read_fd, 3),),
                )
            finally:
                for descriptor in (read_fd, write_fd):
                    if descriptor >= 0:
                        os.close(descriptor)

        def log(self, name):
            return logs[name].read_text() if logs[name].exists() else ""

        def operations(self):
            return self.log("operations").splitlines()

        def inspect(self, *args: str):
            result = self.run("--vmid", "101", *args, "--remote-inspect")
            assert result.status == 0
            line = next(line for line in result.stdout.splitlines() if line.startswith("PLATFORM_VM_CLEANUP_AUTHORIZATION="))
            token = line.partition("=")[2]
            assert NONCE_RE.fullmatch(token)
            return token

    return CleanupTool(), auth_dir, tmp_path, env


@pytest.mark.parametrize(
    ("args", "status", "message"),
    [
        (("--help", "--unknown"), 0, "Usage:"),
        (("--unknown", "--help"), 1, "invalid option: --unknown"),
        (("--vmid", "101", "--help"), 0, "Usage:"),
        (("--yes", "--ssh", "pve.example", "-h"), 0, "Usage:"),
        (("--vmid", "abc", "--help"), 0, "Usage:"),
        (("--vmid", "--help"), 1, "must be numeric"),
        (("--ssh", "--help", "--vmid", "101"), 1, "--ssh must use host"),
        ((), 1, "missing required flag: --vmid VMID"),
        (("--vmid=",), 1, "invalid option: --vmid="),
        (("--vmid", "101", "positional", "--yes"), 1, "invalid argument: positional"),
    ],
)
def test_parser_contract(cleanup_env, args, status, message):
    tool, *_ = cleanup_env
    result = tool.run(*args)
    assert result.status == status and message in result.stdout + result.stderr
    assert tool.operations() == []


def test_help_version_private_options_and_last_values(cleanup_env):
    tool, *_ = cleanup_env
    result = tool.run("--help")
    assert result.status == 0 and result.stderr == ""
    for option in ("--remote-inspect", "--remote-destroy", "--remote-cancel", "--authorization-token"):
        assert option not in result.stdout
    result = tool.run("--version")
    assert result.stdout.strip() == f"platform-proxmox-vm-cleanup {(ROOT / 'VERSION').read_text().strip()}"
    result = tool.run("--vmid=100", "--vmid", "101", "--name=first", "--name", "second", "--yes", update={"FAKE_VM_NAME": "second"})
    assert result.status == 0 and "ARG=100" not in tool.log("qm") and "name: second" in result.stdout
    assert tool.operations() == ["status", "config", "status", "config", "destroy", "status", "config", "destroy"]


@pytest.mark.parametrize("target", [
    "-oProxyCommand=touch-bad", "root@pve.example extra", "root@pve.example;touch-bad",
    "root@@pve.example", "root@", "@pve.example", "bad_user!@pve.example", "[::1]",
    "root@pve.example\n-oProxyCommand=bad",
])
def test_ssh_target_validation(cleanup_env, target):
    tool, *_ = cleanup_env
    result = tool.run("--ssh", target, "--vmid", "101", "--yes")
    assert result.status == 1 and tool.log("ssh") == "" and tool.log("qm") == ""


@pytest.mark.parametrize("target", ["pve.example", "operator_1@pve-1.example", "root@192.0.2.10"])
def test_ssh_target_is_one_operand(cleanup_env, target):
    tool, *_ = cleanup_env
    result = tool.run("--ssh", target, "--vmid", "101", "--yes")
    assert result.status == 0 and f"ARG={target}" in tool.log("ssh")
    assert tool.operations() == ["status", "config", "status", "config", "destroy", "status", "config", "destroy"]


@pytest.mark.parametrize("output", ["status: paused", "garbage", "status: running\nextra"])
def test_status_parser_rejects_unsupported_or_ambiguous_output(cleanup_env, output):
    tool, *_ = cleanup_env
    result = tool.run("--vmid", "101", "--yes", update={"FAKE_QM_STATUS_OUTPUT": output})
    assert result.status == 1 and "malformed or unsupported qm status" in result.stderr
    assert tool.operations() == ["status"]


def test_missing_and_qm_errors_are_distinguished(cleanup_env):
    tool, *_ = cleanup_env
    result = tool.run("--vmid", "404", "--yes", update={"FAKE_VM_EXISTS": "0"})
    assert result.status == 1 and "does not exist" in result.stderr and "permission denied" not in result.stderr
    assert tool.operations() == ["status"]
    result = tool.run("--vmid", "101", "--yes", update={"FAKE_QM_STATUS_ERROR_AT": "1", "FAKE_QM_STATUS_ERROR": "permission denied by fake qm"})
    assert result.status == 42 and "permission denied" in result.stderr and "does not exist" not in result.stderr
    assert tool.operations() == ["status"]
    result = tool.run("--vmid", "101", "--yes", update={"FAKE_QM_CONFIG_ERROR_AT": "1"})
    assert result.status == 42 and tool.operations() == ["status", "config"]


@pytest.mark.parametrize("update", [{"FAKE_CONFIG_HAS_NAME": "0"}, {"FAKE_CONFIG_DUPLICATE_NAME": "1"}])
def test_config_requires_one_name(cleanup_env, update):
    tool, *_ = cleanup_env
    result = tool.run("--vmid", "101", "--yes", update=update)
    assert result.status == 1 and "no unique non-empty name" in result.stderr
    assert tool.operations() == ["status", "config"]


def test_tty_confirmation_wrong_eof_and_success(cleanup_env):
    tool, *_ = cleanup_env
    result = tool.run("--vmid", "101")
    assert result.status == 1 and "requires a TTY" in result.stderr
    assert tool.operations() == ["status", "config"]
    result = tool.run("--vmid", "101", input="wrong\n", pty=True)
    assert result.status == 1 and "Confirmation did not match" in result.stdout + result.stderr
    assert tool.operations() == ["status", "config"]
    result = tool.run("--vmid", "101", input=None, pty=True)
    assert result.status == 1 and "Confirmation input unavailable" in result.stdout + result.stderr
    assert tool.operations() == ["status", "config"]
    result = tool.run("--vmid", "101", input="101\n", pty=True)
    assert result.status == 0 and "Type VMID 101 to destroy:" in result.stdout
    assert tool.operations() == ["status", "config", "status", "config", "destroy", "status", "config", "destroy"]


@pytest.mark.parametrize(
    ("update", "status", "message", "operations"),
    [
        ({"FAKE_VM_NAME_AT_2": "renamed-vm"}, 1, "name changed", ["status", "config", "status", "config"]),
        ({"FAKE_QM_STATUS_OUTPUT_AT_2": "status: running"}, 1, "status changed", ["status", "config", "status", "config"]),
        ({"FAKE_VM_MISSING_AT": "2"}, 1, "does not exist", ["status", "config", "status"]),
        ({"FAKE_QM_STATUS_ERROR_AT": "2", "FAKE_QM_STATUS_ERROR": "second permission failure"}, 42, "second permission", ["status", "config", "status"]),
        ({"FAKE_VM_NAME_AT_3": "probe-window-rename"}, 1, "name changed", ["status", "config", "status", "config", "destroy", "status", "config"]),
        ({"FAKE_CONFIG_MEMORY_AT_3": "4096"}, 1, "configuration changed", ["status", "config", "status", "config", "destroy", "status", "config"]),
    ],
)
def test_target_drift_aborts_before_mutation(cleanup_env, update, status, message, operations):
    tool, *_ = cleanup_env
    result = tool.run("--vmid", "101", "--yes", update=update)
    assert result.status == status and message in result.stderr and tool.operations() == operations


@pytest.mark.parametrize(
    ("update", "status", "operations", "contains_unreferenced"),
    [
        ({"FAKE_VM_STATUS": "stopped"}, 0, ["status", "config", "status", "config", "destroy", "status", "config", "destroy"], True),
        ({"FAKE_VM_STATUS": "running"}, 0, ["status", "config", "status", "config", "destroy", "status", "config", "stop", "status", "config", "destroy"], True),
        ({"FAKE_VM_STATUS": "running", "FAKE_DESTROY_SUPPORTS_UNREFERENCED": "0"}, 0, ["status", "config", "status", "config", "destroy", "status", "config", "stop", "status", "config", "destroy"], False),
    ],
)
def test_destroy_order_and_capability(cleanup_env, update, status, operations, contains_unreferenced):
    tool, *_ = cleanup_env
    result = tool.run("--vmid", "101", "--yes", update=update)
    assert result.status == status and tool.operations() == operations
    assert ("ARG=--destroy-unreferenced-disks" in tool.log("qm")) is contains_unreferenced


def test_post_stop_drift_probe_and_operation_failures(cleanup_env):
    tool, *_ = cleanup_env
    cases = [
        ({"FAKE_VM_STATUS": "running", "FAKE_QM_STATUS_OUTPUT_AT_4": "status: running"}, 1, "expected 'stopped'", ["status", "config", "status", "config", "destroy", "status", "config", "stop", "status", "config"]),
        ({"FAKE_VM_STATUS": "running", "FAKE_VM_NAME_AT_4": "renamed"}, 1, "name changed", ["status", "config", "status", "config", "destroy", "status", "config", "stop", "status", "config"]),
        ({"FAKE_VM_STATUS": "running", "FAKE_DESTROY_PROBE_INVALID": "1"}, 1, "Could not verify", ["status", "config", "status", "config", "destroy"]),
        ({"FAKE_VM_STATUS": "running", "FAKE_QM_FAIL_OPERATION": "stop"}, 42, "simulated qm stop", ["status", "config", "status", "config", "destroy", "status", "config", "stop"]),
        ({"FAKE_QM_FAIL_TARGET_DESTROY": "1"}, 42, "simulated qm destroy", ["status", "config", "status", "config", "destroy", "status", "config", "destroy"]),
    ]
    for update, status, message, operations in cases:
        result = tool.run("--vmid", "101", "--yes", update=update)
        assert result.status == status and message in result.stderr
        assert tool.operations() == operations


def test_authorization_metadata_framing_and_fd3_closure(cleanup_env):
    tool, auth_dir, *_ = cleanup_env
    token = tool.inspect()
    path = auth_dir / token
    assert auth_dir.stat().st_mode & 0o777 == 0o700 and auth_dir.stat().st_nlink == 2
    assert path.stat().st_mode & 0o777 == 0o600 and path.stat().st_nlink == 1

    result = tool.run_fd3("--vmid", "101", "--remote-destroy", payload=b"\n")
    assert result.status == 1 and "authorization input has an invalid shape" in result.stderr
    assert tool.log("qm") == ""

    for payload, message in [(b"", "unavailable or not newline-terminated"), (token.encode(), "unavailable or not newline-terminated"), ((token + "\nextra").encode(), "trailing unterminated data"), ((token + "\nextra\n").encode(), "exactly one line")]:
        result = tool.run_fd3("--vmid", "101", "--remote-destroy", payload=payload)
        assert result.status == 1 and message in result.stderr and tool.log("qm") == ""

    valid = tool.inspect()
    result = tool.run_fd3("--vmid", "101", "--remote-destroy", payload=f"{valid}\n".encode(), update={"FAKE_REQUIRE_FD3_CLOSED": "1"})
    assert result.status == 0 and valid not in result.stdout + result.stderr
    for command in ("stat", "mv", "qm"):
        assert f"{command} FD3=closed" in tool.log("fd")

    unknown = "0" * 64
    result = tool.run_fd3("--vmid", "101", "--remote-destroy", payload=f"{unknown}\n".encode())
    assert result.status == 1 and "was not found or was already consumed" in result.stderr
    assert unknown not in result.stdout + result.stderr and tool.log("qm") == ""


@pytest.mark.parametrize("parent_fd3_open", [False, True])
def test_fd3_helpers_preserve_parent_and_close_sources(
    cleanup_env, monkeypatch, parent_fd3_open
):
    tool, *_ = cleanup_env
    saved_fd3 = None
    try:
        try:
            saved_fd3 = os.dup(3)
        except OSError:
            pass

        if parent_fd3_open:
            probe_fd = os.open("/dev/null", os.O_RDONLY)
            if probe_fd != 3:
                os.dup2(probe_fd, 3)
                os.close(probe_fd)
            parent_before = os.fstat(3)
        else:
            try:
                os.close(3)
            except OSError:
                pass
            parent_before = None

        real_pipe = os.pipe
        helper_pipe = []

        def tracked_pipe():
            descriptors = real_pipe()
            if not helper_pipe:
                helper_pipe.append(
                    tuple((descriptor, os.fstat(descriptor)) for descriptor in descriptors)
                )
            return descriptors

        def assert_helper_pipe_released():
            assert len(helper_pipe) == 1
            for descriptor, identity in helper_pipe[0]:
                try:
                    current = os.fstat(descriptor)
                except OSError:
                    continue
                assert current != identity

        monkeypatch.setattr(os, "pipe", tracked_pipe)

        result = tool.run_fd3("--vmid", "101", "--remote-destroy", payload=b"\n")
        assert result.status == 1 and "authorization input has an invalid shape" in result.stderr
        assert_helper_pipe_released()

        helper_pipe.clear()
        process = tool.start_fd3("--vmid", "101", "--remote-destroy", payload=b"\n")
        assert_helper_pipe_released()
        started_result = process.wait()
        assert started_result.status == 1
        assert "authorization input has an invalid shape" in started_result.stderr

        if parent_before is None:
            with pytest.raises(OSError):
                os.fstat(3)
        else:
            assert os.fstat(3) == parent_before
    finally:
        if saved_fd3 is None:
            try:
                os.close(3)
            except OSError:
                pass
        else:
            os.dup2(saved_fd3, 3)
            os.close(saved_fd3)


def test_authorization_metadata_expiry_forgery_replacement_and_replay(cleanup_env):
    tool, auth_dir, *_ = cleanup_env
    token = tool.inspect()
    path = auth_dir / token
    hardlink = auth_dir / "hardlink"
    hardlink.hardlink_to(path)
    result = tool.run_fd3("--vmid", "101", "--remote-destroy", payload=f"{token}\n".encode())
    assert result.status == 1 and "mode 600 with one link" in result.stderr
    assert tool.operations() == []
    hardlink.unlink()
    tool.run_fd3("--vmid", "101", "--remote-cancel", payload=f"{token}\n".encode())

    token = tool.inspect()
    forged = "f" * 64
    (auth_dir / forged).write_bytes((auth_dir / token).read_bytes())
    (auth_dir / forged).chmod(0o600)
    result = tool.run_fd3("--vmid", "101", "--remote-destroy", payload=f"{forged}\n".encode())
    assert result.status == 1 and "nonce does not match" in result.stderr and (auth_dir / token).exists()
    assert tool.operations() == []

    (auth_dir / token).chmod(0o640)
    result = tool.run_fd3("--vmid", "101", "--remote-destroy", payload=f"{token}\n".encode())
    assert result.status == 1 and "mode 600 with one link" in result.stderr
    assert tool.operations() == []
    (auth_dir / token).chmod(0o600)
    tool.run_fd3("--vmid", "101", "--remote-cancel", payload=f"{token}\n".encode())

    token = tool.inspect()
    path = auth_dir / token
    path.write_text(re.sub(r"^created=.*$", "created=1", path.read_text(), flags=re.M))
    path.chmod(0o600)
    result = tool.run_fd3("--vmid", "101", "--remote-destroy", payload=f"{token}\n".encode())
    assert result.status == 1 and "has expired" in result.stderr
    assert tool.operations() == []

    stale = tool.inspect()
    stale_path = auth_dir / stale
    stale_path.write_text(re.sub(r"^created=.*$", "created=1", stale_path.read_text(), flags=re.M))
    stale_path.chmod(0o600)
    current = tool.inspect()
    assert not stale_path.exists() and (auth_dir / current).exists()
    result = tool.run_fd3("--vmid", "101", "--remote-cancel", payload=f"{current}\n".encode())
    assert result.status == 0

    token = tool.inspect()
    result = tool.run_fd3("--vmid", "101", "--remote-destroy", payload=f"{token}\n".encode(), update={"FAKE_AUTH_REPLACE_ON_MV": "1"})
    assert result.status == 1 and "changed during consumption" in result.stderr and tool.log("qm") == ""
    result = tool.run_fd3("--vmid", "101", "--remote-destroy", payload=f"{token}\n".encode())
    assert result.status == 1 and "already consumed" in result.stderr
    assert tool.operations() == []


@pytest.mark.parametrize("point", ["LINK", "UNLINK"])
def test_interrupted_publication_pairs_are_safely_reaped(cleanup_env, point):
    tool, auth_dir, *_ = cleanup_env
    result = tool.run("--vmid", "101", "--remote-inspect", update={f"FAKE_AUTH_INTERRUPT_AFTER_{point}": "1"})
    assert result.status == 1
    assert tool.operations() == ["status", "config"]
    temporary = next(auth_dir.glob(".tmp.*"))
    token = temporary.name.split(".")[2]
    final = auth_dir / token
    assert temporary.stat().st_mode & 0o777 == 0o600 and temporary.stat().st_nlink == 2
    assert temporary.stat().st_ino == final.stat().st_ino
    current = tool.inspect()
    assert temporary.exists() and final.exists()
    tool.run_fd3("--vmid", "101", "--remote-cancel", payload=f"{current}\n".encode())
    os.utime(temporary, (1, 1)); os.utime(final, (1, 1))
    current = tool.inspect()
    assert not temporary.exists() and not final.exists()
    tool.run_fd3("--vmid", "101", "--remote-cancel", payload=f"{current}\n".encode())


def test_interrupted_consume_and_foreign_artifacts(cleanup_env):
    tool, auth_dir, tmp_path, _env = cleanup_env
    token = tool.inspect()
    result = tool.run_fd3("--vmid", "101", "--remote-destroy", payload=f"{token}\n".encode(), update={"FAKE_AUTH_INTERRUPT_AFTER_MV": "1"})
    assert result.status == 1 and not (auth_dir / token).exists()
    assert tool.operations() == []
    consumed = next(auth_dir.glob(f".consumed.{token}.*"))
    assert consumed.stat().st_mode & 0o777 == 0o600 and consumed.stat().st_nlink == 1
    os.utime(consumed, (1, 1)); current = tool.inspect()
    assert not consumed.exists()
    tool.run_fd3("--vmid", "101", "--remote-cancel", payload=f"{current}\n".encode())

    target = tmp_path / "foreign"
    target.write_text("foreign\n")
    nonce = "e" * 64
    link = auth_dir / f".tmp.{nonce}.999"
    link.symlink_to(target)
    foreign = auth_dir / f".consumed.{nonce}.999.1"
    foreign.write_text("foreign\n"); foreign.chmod(0o640); os.utime(foreign, (1, 1))
    current = tool.inspect()
    assert link.is_symlink() and foreign.exists()
    tool.run_fd3("--vmid", "101", "--remote-cancel", payload=f"{current}\n".encode())


def test_authorization_conflicts_and_state_drift(cleanup_env):
    tool, *_ = cleanup_env
    token = tool.inspect()
    result = tool.run_fd3("--vmid", "102", "--remote-destroy", payload=f"{token}\n".encode())
    assert result.status == 1 and "conflicts with --vmid" in result.stderr and tool.operations() == []
    token = tool.inspect("--name", "fixture-vm")
    result = tool.run_fd3("--vmid", "101", "--name", "other", "--remote-destroy", payload=f"{token}\n".encode())
    assert result.status == 1 and "conflicts with --name" in result.stderr and tool.operations() == []
    for update, message in [({"FAKE_VM_NAME": "renamed"}, "name changed"), ({"FAKE_VM_STATUS": "running"}, "status changed")]:
        token = tool.inspect()
        result = tool.run_fd3("--vmid", "101", "--remote-destroy", payload=f"{token}\n".encode(), update=update)
        assert result.status == 1 and message in result.stderr
        assert tool.operations() == ["status", "config"]


def test_concurrent_nonce_has_one_consumer_and_cannot_replay(cleanup_env):
    tool, *_ = cleanup_env
    token = tool.inspect()
    tool.reset()
    processes = [tool.start_fd3("--vmid", "101", "--remote-destroy", payload=f"{token}\n".encode()) for _ in range(2)]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda process: process.wait(), processes))
    assert sorted(result.status == 0 for result in results) == [False, True]
    assert sum("[OK] Destroyed VMID 101" in result.stdout for result in results) == 1
    assert tool.operations() == ["status", "config", "destroy", "status", "config", "destroy"]
    result = tool.run_fd3("--vmid", "101", "--remote-destroy", payload=f"{token}\n".encode())
    assert result.status == 1 and "already consumed" in result.stderr and tool.log("qm") == ""


def test_self_streamed_ssh_hides_nonce_from_argv_logs_and_proc(cleanup_env):
    tool, _auth_dir, tmp_path, _env = cleanup_env
    identity = tmp_path / "id_ed25519"
    identity.write_text("synthetic identity\n")
    result = tool.run(
        "--ssh", "root@pve.example", "--identity-file", os.fspath(identity),
        "--vmid", "101", "--name", "fixture;still-one-name", "--yes",
        update={"FAKE_VM_NAME": "fixture;still-one-name", "FAKE_REQUIRE_FD3_CLOSED": "1"},
    )
    assert result.status == 0
    ssh_log, argv_log = tool.log("ssh"), tool.log("argv")
    assert f"ARG=-i\nARG={identity}\nARG=-o\nARG=IdentitiesOnly=yes\n" in ssh_log
    assert "MODE=inspect" in ssh_log and "MODE=destroy" in ssh_log and "LOGIN_SHELL=sh" in ssh_log
    assert "fixture;still-one-name" not in ssh_log and not re.search(r"[a-f0-9]{64}", ssh_log + argv_log)
    assert "CAPTURED_ARGV\n" in argv_log and "ARG=--remote-destroy" in argv_log
    assert "PROC=" in argv_log and "PROC=--remote-destroy\n" in argv_log
    assert "authorization-token" not in argv_log and "PROC=authorization-token\n" not in argv_log
    assert "PLATFORM_VM_CLEANUP_AUTHORIZATION=" not in result.stdout + result.stderr
    for command in ("stat", "mv", "qm"):
        assert f"{command} FD3=closed" in tool.log("fd")


def test_remote_drift_failures_cancel_and_tty_refusal(cleanup_env):
    tool, auth_dir, *_ = cleanup_env
    cases = [
        ({"FAKE_VM_NAME_AT_2": "remote-renamed"}, 1, "name changed", ["status", "config", "status", "config"]),
        ({"FAKE_QM_STATUS_OUTPUT_AT_2": "status: running"}, 1, "status changed", ["status", "config", "status", "config"]),
        ({"FAKE_VM_EXISTS": "0"}, 1, "does not exist", ["status"]),
        ({"FAKE_QM_STATUS_ERROR_AT": "1", "FAKE_QM_STATUS_ERROR": "remote permission denied"}, 42, "remote permission denied", ["status"]),
        ({"FAKE_SSH_FAIL_INSPECT": "1"}, 43, "simulated SSH inspection", []),
        ({"FAKE_SSH_FAIL_DESTROY": "1"}, 44, "simulated SSH destruction", ["status", "config"]),
    ]
    for update, status, message, operations in cases:
        result = tool.run("--ssh", "root@pve.example", "--vmid", "101", "--yes", update=update)
        assert result.status == status and message in result.stderr
        assert tool.operations() == operations
        if update.get("FAKE_SSH_FAIL_DESTROY"):
            assert "MODE=cancel" in tool.log("ssh")
    result = tool.run("--ssh", "root@pve.example", "--vmid", "101")
    assert result.status == 1 and "requires a TTY" in result.stderr
    assert "MODE=destroy" not in tool.log("ssh") and "MODE=cancel" in tool.log("ssh")
    assert tool.operations() == ["status", "config"]
    assert not list(auth_dir.glob("[a-f0-9]*"))
