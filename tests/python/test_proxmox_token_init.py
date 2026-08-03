from __future__ import annotations

import os
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[2]
TOOL = ROOT / "bin/platform-proxmox-token-init"
FAKES = ROOT / "tests/proxmox-token-init/fake-bin"
SECRET = "12345678-1234-1234-1234-123456789abc"


@pytest.fixture
def token_env(tmp_path, process_runner, request):
    previous_umask = os.umask(0o077)
    request.addfinalizer(lambda: os.umask(previous_umask))
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    for path in FAKES.iterdir():
        (fake_bin / path.name).symlink_to(path)
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    logs = {name: tmp_path / f"{name}.log" for name in ("pveum", "jq", "ssh", "ln", "mv", "sequence")}
    for path in logs.values():
        path.touch()
    for name in ("awk", "bash", "basename", "cat", "chmod", "dirname", "mkdir", "mktemp", "rm"):
        (fake_bin / name).symlink_to(_which(name))
    env = {
        **os.environ,
        "HOME": os.fspath(home),
        "PATH": os.fspath(fake_bin),
        "FAKE_PVEUM_LOG": os.fspath(logs["pveum"]),
        "FAKE_JQ_LOG": os.fspath(logs["jq"]),
        "FAKE_SSH_LOG": os.fspath(logs["ssh"]),
        "FAKE_LN_LOG": os.fspath(logs["ln"]),
        "FAKE_MV_LOG": os.fspath(logs["mv"]),
        "FAKE_SEQUENCE_LOG": os.fspath(logs["sequence"]),
        "REAL_JQ": os.fspath(_which("jq")),
        "REAL_LN": os.fspath(_which("ln")),
        "REAL_MV": os.fspath(_which("mv")),
        "REAL_STAT": os.fspath(_which("stat")),
        "FAKE_USER_EXISTS": "0",
        "FAKE_TOKEN_EXISTS": "0",
        "FAKE_EXPECTED_USER": "tofu@pve",
        "FAKE_EXPECTED_TOKEN_ID": "platform",
        "FAKE_TOKEN_SECRET": SECRET,
    }

    class TokenTool:
        def run(self, *args: str, env_update: dict[str, str] | None = None):
            for path in logs.values():
                path.write_text("")
            return process_runner((TOOL, *args), env={**env, **(env_update or {})})

        def log(self, name: str) -> str:
            return logs[name].read_text()

    return TokenTool(), home, tmp_path, fake_bin


def _which(name: str) -> Path:
    for directory in os.environ["PATH"].split(os.pathsep):
        candidate = Path(directory) / name
        if candidate.exists():
            return candidate.resolve()
    raise RuntimeError(f"required test command missing: {name}")


@pytest.mark.parametrize(
    ("args", "status", "stream", "message"),
    [
        (("--help", "--unknown"), 0, "stdout", "Usage:"),
        (("--unknown", "--help"), 1, "stderr", "invalid option: --unknown"),
        (("--version", "--unknown"), 0, "stdout", "platform-proxmox-token-init"),
        (("--ssh",), 1, "stderr", "--ssh requires an argument"),
        (("--token-id=",), 1, "stderr", "invalid option: --token-id="),
        (("--proxmox-user", ""), 1, "stderr", "must not be empty"),
        (("positional",), 1, "stderr", "invalid argument: positional"),
        (("--comment", "safe\nunsafe", "--check"), 1, "stderr", "must not contain control characters"),
    ],
)
def test_parser_contract(token_env, args, status, stream, message):
    tool, *_ = token_env
    result = tool.run(*args)
    assert result.status == status
    assert message in getattr(result, stream)
    if status:
        assert tool.log("pveum") == ""


def test_help_version_and_missing_local_prerequisites(token_env):
    tool, _home, tmp_path, _fake_bin = token_env
    result = tool.run("--help")
    assert result.status == 0 and result.stderr == ""
    assert "--proxmox-user, --user USERID" in result.stdout
    assert "--emit-token-line" not in result.stdout
    result = tool.run("--version")
    assert result.stdout.strip() == f"platform-proxmox-token-init {(ROOT / 'VERSION').read_text().strip()}"

    missing = tmp_path / "missing"
    missing.mkdir()
    (missing / "bash").symlink_to(_which("bash"))
    result = tool.run(env_update={"PATH": os.fspath(missing)})
    assert result.status == 1
    assert "pveum is required" in result.stderr
    result = tool.run("--check", env_update={"PATH": os.fspath(missing)})
    assert result.status == 1
    assert "Local Proxmox marker missing: /etc/pve" in result.stderr
    assert "Local command missing: pveum" in result.stderr


def test_operand_boundaries_last_value_and_optional_jq(token_env):
    tool, _home, tmp_path, fake_bin = token_env
    marker = tmp_path / "injected"
    result = tool.run(
        "--user", "first@pve", "--proxmox-user", "second@pve",
        "--token-id", "first-token", "--token-id", "second-token",
        "--role", "Custom Role", "--path", "/pool/a;still-one-arg",
        "--comment", f"automation; touch {marker}",
        env_update={"FAKE_EXPECTED_USER": "second@pve", "FAKE_EXPECTED_TOKEN_ID": "second-token"},
    )
    assert result.status == 0 and not marker.exists()
    log = tool.log("pveum")
    for value in ("second@pve", "second-token", "Custom\\ Role", "/pool/a\\;still-one-arg"):
        assert f"ARG={value}" in log
    assert f"ARG=automation\\;\\ touch\\ {marker}" in log
    assert f"second@pve!second-token={SECRET}" in result.stdout

    no_jq = tmp_path / "no-jq"
    no_jq.mkdir()
    (no_jq / "pveum").symlink_to(fake_bin / "pveum")
    for name in ("awk", "bash", "cat"):
        (no_jq / name).symlink_to(_which(name))
    result = tool.run(env_update={"PATH": os.fspath(no_jq)})
    assert result.status == 0 and tool.log("jq") == ""
    assert '"full-tokenid":"tofu@pve!platform"' in result.stdout
    assert "Install jq" in result.stderr


def test_ssh_validation_and_literal_destination(token_env):
    tool, _home, tmp_path, _fake_bin = token_env
    result = tool.run("--ssh=-oProxyCommand=touch-bad", "--check")
    assert result.status == 1 and "must not start with -" in result.stderr
    assert tool.log("ssh") == ""
    marker = tmp_path / "injected"
    destination = f"root@pve;touch {marker}"
    result = tool.run("--ssh", destination, "--check")
    assert result.status == 0 and not marker.exists()
    assert f"ARG=root@pve\\;touch\\ {marker}" in tool.log("ssh")


def test_existing_identity_still_ensures_acl(token_env):
    tool, *_ = token_env
    result = tool.run(env_update={"FAKE_USER_EXISTS": "1", "FAKE_TOKEN_EXISTS": "1"})
    assert result.status == 0
    assert "User already exists" in result.stdout and "cannot show the existing secret" in result.stderr
    assert "ARG=add" not in tool.log("pveum") and "ARG=aclmod" in tool.log("pveum")


def test_private_atomic_publication_and_force_order(token_env):
    tool, home, _tmp_path, _fake_bin = token_env
    destination = home / "tokens/proxmox.token"
    result = tool.run("--write-token-file", os.fspath(destination))
    assert result.status == 0
    assert destination.read_text().strip() == f"tofu@pve!platform={SECRET}"
    assert destination.stat().st_mode & 0o777 == 0o600
    assert destination.parent.stat().st_mode & 0o777 == 0o700
    assert tool.log("ln") == f"CALL ln\nSOURCE_MODE=600\nDESTINATION={destination}\nEND\n"
    assert tool.log("mv") == ""
    assert SECRET not in result.stdout + result.stderr
    assert not list(destination.parent.glob(f".{destination.name}.tmp.*"))

    destination.write_text("keep existing\n")
    result = tool.run("--write-token-file", os.fspath(destination))
    assert result.status == 1 and "Refusing to overwrite non-empty" in result.stderr
    assert destination.read_text() == "keep existing\n" and tool.log("pveum") == ""

    result = tool.run(
        "--write-token-file", os.fspath(destination), "--force",
        env_update={"FAKE_SEQUENCE_PATH": os.fspath(destination)},
    )
    assert result.status == 0 and destination.stat().st_mode & 0o777 == 0o600
    assert tool.log("mv") == f"CALL mv\nSOURCE_MODE=600\nDESTINATION={destination}\nEND\n"
    sequence = tool.log("sequence").splitlines()
    assert sequence[-2:] == [f"STAT {destination}", f"MV {destination}"]


@pytest.mark.parametrize("force", [False, True])
@pytest.mark.parametrize("kind", ["nonempty", "empty", "symlink"])
def test_concurrent_publication_is_never_replaced(token_env, force, kind):
    tool, home, _tmp_path, _fake_bin = token_env
    destination = home / f"tokens/race-{force}-{kind}.token"
    destination.parent.mkdir()
    update = {"FAKE_TOKEN_RACE_PATH": os.fspath(destination)}
    target = home / "tokens/foreign-target"
    if kind == "empty":
        update["FAKE_TOKEN_RACE_EMPTY"] = "1"
    elif kind == "symlink":
        target.write_text("foreign symlink target\n")
        update["FAKE_TOKEN_RACE_SYMLINK_TARGET"] = os.fspath(target)
    args = ["--write-token-file", os.fspath(destination)]
    if force:
        args.append("--force")
    result = tool.run(*args, env_update=update)
    assert result.status == 1 and "created concurrently" in result.stderr
    assert tool.log("mv") == "" and SECRET not in result.stdout + result.stderr
    assert not list(destination.parent.glob(f".{destination.name}.tmp.*"))
    if kind == "symlink":
        assert destination.is_symlink() and target.read_text() == "foreign symlink target\n"
    elif kind == "empty":
        assert destination.exists() and destination.stat().st_size == 0
    else:
        assert destination.read_text() == "concurrent token file\n"


def test_force_identity_change_publish_failure_and_symlink(token_env):
    tool, home, _tmp_path, _fake_bin = token_env
    destination = home / "tokens/token"
    destination.parent.mkdir()
    destination.write_text("original\n")
    result = tool.run("--write-token-file", os.fspath(destination), "--force", env_update={"FAKE_TOKEN_REPLACE_PATH": os.fspath(destination)})
    assert result.status == 1 and "changed after preflight" in result.stderr
    assert destination.read_text() == "foreign replacement\n" and tool.log("mv") == ""
    assert SECRET not in result.stdout + result.stderr
    assert not list(destination.parent.glob(f".{destination.name}.tmp.*"))

    destination.write_text("original\n")
    result = tool.run("--write-token-file", os.fspath(destination), "--force", env_update={"FAKE_MV_FAIL": "1", "FAKE_MV_FAIL_PATH": os.fspath(destination)})
    assert result.status == 1 and "Failed to publish" in result.stderr
    assert destination.read_text() == "original\n"
    assert tool.log("mv") == f"CALL mv\nSOURCE_MODE=600\nDESTINATION={destination}\nEND\n"
    assert SECRET not in result.stdout + result.stderr
    assert not list(destination.parent.glob(f".{destination.name}.tmp.*"))

    target = home / "tokens/target"
    target.write_text("target\n")
    link = home / "tokens/link"
    link.symlink_to(target)
    result = tool.run("--write-token-file", os.fspath(link), "--force")
    assert result.status == 1 and "must not be a symbolic link" in result.stderr
    assert target.read_text() == "target\n" and tool.log("pveum") == ""


@pytest.mark.parametrize(
    ("update", "status", "message", "acl"),
    [
        ({"FAKE_INVALID_JSON": "1"}, 0, "Refusing to print raw pveum output", True),
        ({"FAKE_TOKEN_ADD_FAIL": "1"}, 1, "Refusing to print failed pveum JSON output", False),
        ({"FAKE_FULL_TOKEN": "other@pve!platform"}, 1, "Generated Proxmox token ID mismatch", False),
    ],
)
def test_secret_is_redacted_on_invalid_creation(token_env, update, status, message, acl):
    tool, home, *_ = token_env
    secret = "abcdefab-cdef-abcd-efab-cdefabcdefab"
    destination = home / "tokens/invalid"
    result = tool.run("--write-token-file", os.fspath(destination), env_update={**update, "FAKE_TOKEN_SECRET": secret})
    assert result.status == status and message in result.stderr
    assert secret not in result.stdout + result.stderr and not destination.exists()
    assert ("ARG=aclmod" in tool.log("pveum")) is acl


def test_destination_parent_checks_and_check_jq_requirement(token_env):
    tool, home, *_ = token_env
    unsafe = home / "unsafe"
    unsafe.mkdir(mode=0o720)
    unsafe.chmod(0o720)
    for args in [
        ("--ssh", "root@pve.example", "--write-token-file", os.fspath(unsafe / "token"), "--check"),
        ("--write-token-file", os.fspath(unsafe / "token")),
    ]:
        result = tool.run(*args)
        assert result.status == 1 and "must not be writable by group" in result.stderr
    target = home / "target"
    target.mkdir(mode=0o700)
    link = home / "link"
    link.symlink_to(target)
    result = tool.run("--ssh", "root@pve.example", "--write-token-file", os.fspath(link / "token"), "--check")
    assert result.status == 1 and "must not be a symbolic link" in result.stderr
    regular = home / "regular"
    regular.write_text("x")
    result = tool.run("--ssh", "root@pve.example", "--write-token-file", os.fspath(regular / "token"), "--check")
    assert result.status == 1 and "is not a directory" in result.stderr

    result = tool.run("--ssh", "root@pve.example", "--check")
    assert result.status == 0 and "REQUIRE_JQ=false" in tool.log("ssh")
    result = tool.run("--ssh", "root@pve.example", "--write-token-file", os.fspath(home / "check.token"), "--check")
    assert result.status == 0 and "REQUIRE_JQ=true" in tool.log("ssh")
    assert "Remote command available: jq" in result.stdout and not (home / "check.token").exists()
    for error in ("[ERROR] Remote command missing: pveum", "[ERROR] Remote command missing: jq"):
        args = ["--ssh", "root@pve.example", "--check"]
        if error.endswith("jq"):
            args[2:2] = ["--write-token-file", os.fspath(home / "check.token")]
        result = tool.run(*args, env_update={"FAKE_REMOTE_CHECK_STATUS": "1", "FAKE_REMOTE_CHECK_ERROR": error})
        assert result.status == 1 and error[8:] in result.stderr


def test_self_streamed_ssh_and_protocol_redaction(token_env):
    tool, home, tmp_path, _fake_bin = token_env
    destination = home / "tokens/remote.token"
    marker = tmp_path / "remote-injected"
    result = tool.run(
        "--ssh", "root@pve.example", "--write-token-file", os.fspath(destination),
        "--role", "Remote Role", "--path", "/remote;path", "--comment", f"remote; touch {marker}",
    )
    assert result.status == 0
    assert destination.read_text() == f"tofu@pve!platform={SECRET}\n"
    assert destination.stat().st_mode & 0o777 == 0o600
    assert destination.parent == home / "tokens"
    assert destination.parent.stat().st_mode & 0o777 == 0o700
    assert not marker.exists() and "ARG=bash\\ -s\\ --" in tool.log("ssh")
    pveum_log = tool.log("pveum")
    assert "ARG=Remote\\ Role" in pveum_log
    assert "ARG=/remote\\;path" in pveum_log
    assert f"ARG=remote\\;\\ touch\\ {marker}" in pveum_log
    assert SECRET not in result.stdout + result.stderr
    assert not list(destination.parent.glob(f".{destination.name}.tmp.*"))

    failed = home / "tokens/remote-fail.token"
    result = tool.run("--ssh", "root@pve.example", "--write-token-file", os.fspath(failed), env_update={"FAKE_SSH_PROTOCOL_FAIL": "1"})
    assert result.status == 1 and "PLATFORM_PROXMOX_TOKEN_LINE=<redacted>" in result.stderr
    assert SECRET not in result.stderr and "Remote Proxmox token bootstrap failed" in result.stderr
    assert not failed.exists()
    assert not list(failed.parent.glob(f".{failed.name}.tmp.*"))
