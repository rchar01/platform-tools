from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import Callable, Generator
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from .harness import ProcessResult


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "bin/platform-ssh-init"
VERSION = (ROOT / "VERSION").read_text().strip()
SYSTEM_PATH = os.environ["PATH"]

FAKE_KEYGEN = r"""#!/usr/bin/env bash
set -euo pipefail
key_path=''
derive=false
while [[ $# -gt 0 ]]; do
  printf '<%s>\n' "$1" >>"$SSH_KEYGEN_LOG"
  case $1 in
    -f)
      key_path=$2
      printf '<%s>\n' "$2" >>"$SSH_KEYGEN_LOG"
      shift 2
      ;;
    -y)
      derive=true
      shift
      ;;
    *) shift ;;
  esac
done
if [[ $derive == true ]]; then
  if [[ $SSH_KEYGEN_DERIVE_FAIL == 1 ]]; then
    printf '%s\n' 'partial public key'
    exit 42
  fi
  if [[ -n $SSH_KEYGEN_DERIVE_RACE_PATH ]]; then
    printf '%s\n' 'race winner' >"$SSH_KEYGEN_DERIVE_RACE_PATH"
  fi
  printf '%s\n' 'ssh-ed25519 AAAAC3NzaFakeReconstructed'
else
  : >"$key_path"
  printf '%s\n' 'ssh-ed25519 AAAAC3NzaFakeGenerated fake-comment' >"${key_path}.pub"
fi
"""

FAKE_SSH = r"""#!/usr/bin/env bash
set -euo pipefail
for arg in "$@"; do
  printf '<%s>\n' "$arg" >>"$SSH_LOG"
done
[[ $SSH_FAIL_STATUS == 0 ]] || exit "$SSH_FAIL_STATUS"
"""


@dataclass
class SshCase:
    base: Path
    home: Path
    fake_bin: Path
    keygen_log: Path
    ssh_log: Path
    runner: Callable[..., ProcessResult]
    cwd: Path = ROOT
    path: str = field(default_factory=lambda: SYSTEM_PATH)
    derive_fail: str = "0"
    derive_race_path: str = ""
    ssh_fail_status: str = "0"

    def run(self, *args: str | Path) -> ProcessResult:
        env = {
            **os.environ,
            "HOME": os.fspath(self.home),
            "PATH": self.path,
            "SSH_KEYGEN_LOG": os.fspath(self.keygen_log),
            "SSH_LOG": os.fspath(self.ssh_log),
            "SSH_KEYGEN_DERIVE_FAIL": self.derive_fail,
            "SSH_KEYGEN_DERIVE_RACE_PATH": self.derive_race_path,
            "SSH_FAIL_STATUS": self.ssh_fail_status,
        }
        return self.runner((TOOL, *args), cwd=self.cwd, env=env)

    def use_fakes(self) -> None:
        self.path = f"{self.fake_bin}:{SYSTEM_PATH}"


@pytest.fixture
def ssh_case(
    process_runner: Callable[..., ProcessResult],
) -> Generator[SshCase, None, None]:
    previous_umask = os.umask(0o077)
    temporary_parent = ROOT / ".tmp"
    temporary_parent.mkdir(exist_ok=True)
    base = Path(tempfile.mkdtemp(prefix="pytest-platform-ssh-init.", dir=temporary_parent))
    home = base / "home"
    fake_bin = base / "fake-bin"
    home.mkdir(mode=0o700)
    fake_bin.mkdir()
    keygen = fake_bin / "ssh-keygen"
    ssh = fake_bin / "ssh"
    keygen.write_text(FAKE_KEYGEN)
    ssh.write_text(FAKE_SSH)
    keygen.chmod(0o755)
    ssh.chmod(0o755)
    keygen_log = base / "ssh-keygen.log"
    ssh_log = base / "ssh.log"
    keygen_log.touch()
    ssh_log.touch()
    try:
        yield SshCase(base, home, fake_bin, keygen_log, ssh_log, process_runner)
    finally:
        shutil.rmtree(base)
        os.umask(previous_umask)


def assert_status(result: ProcessResult, status: int) -> None:
    assert result.status == status, result.stderr


def assert_mode(path: Path, mode: int) -> None:
    assert path.stat().st_mode & 0o777 == mode


def assert_absent(path: Path) -> None:
    assert not path.exists()
    assert not path.is_symlink()


def assert_no_temporary_public_keys(key: Path) -> None:
    assert not tuple(key.parent.glob(f"{key.name}.pub.tmp.*"))


def test_help(ssh_case: SshCase) -> None:
    result = ssh_case.run("--help")
    assert_status(result, 0)
    assert "Usage:" in result.stdout
    assert "platform-ssh-init --version | -v" in result.stdout
    assert "CONFIG_FILE" in result.stdout
    assert result.stderr == ""


def test_version(ssh_case: SshCase) -> None:
    result = ssh_case.run("--version")
    assert_status(result, 0)
    assert result.stdout == f"platform-ssh-init {VERSION}\n"
    assert result.stderr == ""


@pytest.mark.parametrize(
    ("args", "messages"),
    (
        (("--unknown",), ("invalid option: --unknown",)),
        (("--key-path",), ("--key-path requires an argument",)),
        (
            ("--key-path", ""),
            ("validation error in --key-path PATH:", "must not be empty"),
        ),
        (("one.env", "two.env"), ("invalid argument: two.env",)),
    ),
    ids=("unknown-option", "missing-option-value", "empty-key-path", "extra-positional"),
)
def test_parser_errors_have_no_side_effect(
    ssh_case: SshCase, args: tuple[str, ...], messages: tuple[str, ...]
) -> None:
    result = ssh_case.run(*args)
    assert_status(result, 1)
    for message in messages:
        assert message in result.stderr
    if args == ("--unknown",):
        assert result.stdout == ""
    assert_absent(ssh_case.home / ".ssh")


def test_real_ssh_keygen_creates_keypair(ssh_case: SshCase) -> None:
    key = ssh_case.home / "real/id_ed25519"
    result = ssh_case.run("--key-path", key, "--empty-passphrase", "--print-public-key")
    assert_status(result, 0)
    assert key.is_file()
    assert key.with_suffix(".pub").is_file()
    assert not key.is_symlink()
    assert not key.with_suffix(".pub").is_symlink()
    assert_mode(key.parent, 0o700)
    assert_mode(key, 0o600)
    assert_mode(key.with_suffix(".pub"), 0o644)
    derived = ssh_case.runner(("ssh-keygen", "-y", "-f", key), env=os.environ)
    assert_status(derived, 0)
    assert derived.stdout.strip() in result.stdout


@pytest.mark.parametrize("dangling", (False, True), ids=("existing-target", "dangling"))
def test_private_key_symlink_is_rejected(ssh_case: SshCase, dangling: bool) -> None:
    ssh_case.use_fakes()
    directory = ssh_case.home / "unsafe-targets"
    directory.mkdir()
    target = directory / "target"
    target.write_text("target\n")
    target.chmod(0o644)
    key = directory / ("private-dangling" if dangling else "private-link")
    key.symlink_to(directory / "missing" if dangling else target)
    result = ssh_case.run("--key-path", key)
    assert_status(result, 1)
    assert "SSH private key path must not be a symbolic link" in result.stderr
    assert_mode(target, 0o644)


@pytest.mark.parametrize("dangling", (False, True), ids=("existing-target", "dangling"))
def test_public_key_symlink_is_rejected(ssh_case: SshCase, dangling: bool) -> None:
    ssh_case.use_fakes()
    directory = ssh_case.home / "unsafe-targets"
    directory.mkdir()
    target = directory / "target"
    target.write_text("target\n")
    target.chmod(0o600)
    key = directory / ("public-dangling-key" if dangling else "public-link-key")
    public = Path(f"{key}.pub")
    public.symlink_to(directory / "missing" if dangling else target)
    result = ssh_case.run("--key-path", key)
    assert_status(result, 1)
    assert "SSH public key path must not be a symbolic link" in result.stderr
    assert_absent(key)
    assert_mode(target, 0o600)


def test_nonregular_private_key_is_rejected(ssh_case: SshCase) -> None:
    ssh_case.use_fakes()
    key = ssh_case.home / "unsafe-targets/private-directory"
    key.mkdir(parents=True)
    result = ssh_case.run("--key-path", key)
    assert_status(result, 1)
    assert "SSH private key path is not a regular file" in result.stderr


def test_nonregular_public_key_is_rejected(ssh_case: SshCase) -> None:
    ssh_case.use_fakes()
    key = ssh_case.home / "unsafe-targets/public-fifo-key"
    key.parent.mkdir()
    public = Path(f"{key}.pub")
    os.mkfifo(public)
    result = ssh_case.run("--key-path", key)
    assert_status(result, 1)
    assert "SSH public key path is not a regular file" in result.stderr
    assert_absent(key)


def test_symlink_key_directory_component_is_rejected(ssh_case: SshCase) -> None:
    ssh_case.use_fakes()
    target = ssh_case.home / "key-dir-target"
    target.mkdir(mode=0o700)
    link = ssh_case.home / "key-dir-link"
    link.symlink_to(target, target_is_directory=True)
    key = link / "id_ed25519"
    result = ssh_case.run("--key-path", key)
    assert_status(result, 1)
    assert "SSH key directory component must not be a symbolic link" in result.stderr
    assert_absent(target / "id_ed25519")


def test_nondirectory_key_path_component_is_rejected(ssh_case: SshCase) -> None:
    ssh_case.use_fakes()
    component = ssh_case.home / "key-dir-file"
    component.write_text("not a directory\n")
    result = ssh_case.run("--key-path", component / "nested/id_ed25519")
    assert_status(result, 1)
    assert "SSH key directory component is not a directory" in result.stderr


def test_group_writable_key_directory_is_rejected(ssh_case: SshCase) -> None:
    ssh_case.use_fakes()
    directory = ssh_case.home / "group-writable-key-dir"
    directory.mkdir(mode=0o720)
    directory.chmod(0o720)
    key = directory / "id_ed25519"
    result = ssh_case.run("--key-path", key)
    assert_status(result, 1)
    assert "SSH key directory component must not be writable by group or other users" in result.stderr
    assert_absent(key)


def test_safe_relative_key_path_is_created(ssh_case: SshCase) -> None:
    ssh_case.use_fakes()
    cwd = ssh_case.base / "relative-cwd"
    cwd.mkdir(mode=0o700)
    ssh_case.cwd = cwd
    result = ssh_case.run("--key-path", "relative keys/id_ed25519")
    assert_status(result, 0)
    key = cwd / "relative keys/id_ed25519"
    assert key.is_file()
    assert not key.is_symlink()
    assert_mode(key.parent, 0o700)


def test_relative_symlink_component_is_rejected(ssh_case: SshCase) -> None:
    ssh_case.use_fakes()
    cwd = ssh_case.base / "relative-cwd"
    cwd.mkdir(mode=0o700)
    target = cwd / "relative-target"
    target.mkdir(mode=0o700)
    (cwd / "relative-link").symlink_to(target, target_is_directory=True)
    ssh_case.cwd = cwd
    result = ssh_case.run("--key-path", "relative-link/id_ed25519")
    assert_status(result, 1)
    assert "SSH key directory component must not be a symbolic link" in result.stderr
    assert_absent(target / "id_ed25519")


@pytest.mark.parametrize("empty_passphrase", (True, False), ids=("empty", "encrypted-default"))
def test_keygen_argv(ssh_case: SshCase, empty_passphrase: bool) -> None:
    ssh_case.use_fakes()
    key = ssh_case.home / "fake/key"
    args: list[str | Path] = ["--key-path", key]
    if empty_passphrase:
        args.append("--empty-passphrase")
    result = ssh_case.run(*args)
    assert_status(result, 0)
    logged = ssh_case.keygen_log.read_text().splitlines()
    assert "<-t>" in logged
    assert "<ed25519>" in logged
    if empty_passphrase:
        index = logged.index("<-N>")
        assert logged[index + 1] == "<>"
    else:
        assert "<-N>" not in logged


def existing_private_key(ssh_case: SshCase, name: str) -> Path:
    key = ssh_case.home / name / "id_ed25519"
    key.parent.mkdir()
    key.write_text("controlled private fixture\n")
    key.chmod(0o600)
    return key


def test_existing_key_is_reused_and_public_key_reconstructed(ssh_case: SshCase) -> None:
    ssh_case.use_fakes()
    key = existing_private_key(ssh_case, "reuse")
    key.chmod(0o644)
    result = ssh_case.run("--key-path", key, "--print-public-key")
    assert_status(result, 0)
    assert "[OK] SSH key already exists:" in result.stdout
    assert "ssh-ed25519 AAAAC3NzaFakeReconstructed" in result.stdout
    logged = ssh_case.keygen_log.read_text()
    assert "<-y>" in logged
    assert "<-t>" not in logged
    assert_mode(key, 0o600)
    assert_mode(Path(f"{key}.pub"), 0o644)


def test_failed_public_key_derivation_is_atomic(ssh_case: SshCase) -> None:
    ssh_case.use_fakes()
    key = existing_private_key(ssh_case, "derive-failure")
    ssh_case.derive_fail = "1"
    result = ssh_case.run("--key-path", key)
    assert_status(result, 1)
    assert "Failed to derive public key" in result.stderr
    assert_absent(Path(f"{key}.pub"))
    assert_no_temporary_public_keys(key)


def test_public_key_publication_race_preserves_winner(ssh_case: SshCase) -> None:
    ssh_case.use_fakes()
    key = existing_private_key(ssh_case, "derive-race")
    public = Path(f"{key}.pub")
    ssh_case.derive_race_path = os.fspath(public)
    result = ssh_case.run("--key-path", key)
    assert_status(result, 1)
    assert "Refusing to replace public key path" in result.stderr
    assert public.read_text() == "race winner\n"
    assert_no_temporary_public_keys(key)


def test_config_is_data_and_cli_values_win(ssh_case: SshCase) -> None:
    ssh_case.use_fakes()
    config = ssh_case.base / "ssh.env"
    config.write_text(
        'export SSH_KEY_PATH="${HOME}/from-config/id_ed25519"\n'
        'SSH_KEY_COMMENT="config comment"\n'
        'SSH_HOST="config.example"\n'
        'SSH_USER="config-user"\n'
        'SSH_ALIAS="config-alias"\n'
        'SSH_TEST_COMMAND="config command"\n'
    )
    result = ssh_case.run(
        "--host",
        "cli.example",
        config,
        "--key-path",
        "~/from-cli/id_ed25519",
        "--comment",
        "cli comment",
        "--alias",
        "cli-alias",
    )
    assert_status(result, 0)
    assert (ssh_case.home / "from-cli/id_ed25519").is_file()
    assert not (ssh_case.home / "from-cli/id_ed25519").is_symlink()
    assert_absent(ssh_case.home / "from-config")
    assert "Host cli-alias" in result.stdout
    assert "  HostName cli.example" in result.stdout
    assert '  IdentityFile "~/from-cli/id_ed25519"' in result.stdout
    assert "<cli comment>" in ssh_case.keygen_log.read_text()


def test_config_command_substitution_is_not_evaluated(ssh_case: SshCase) -> None:
    ssh_case.use_fakes()
    marker = ssh_case.base / "command-substitution-ran"
    key = ssh_case.home / "unsafe/key"
    config = ssh_case.base / "unsafe.env"
    config.write_text(f"SSH_KEY_PATH={key}\nSSH_KEY_COMMENT=$(touch {marker})\n")
    result = ssh_case.run(config)
    assert_status(result, 1)
    assert "Config values must not contain command substitution" in result.stderr
    assert_absent(marker)
    assert_absent(key.parent)


@pytest.mark.parametrize(
    ("option", "value", "variable"),
    (
        ("--host", "safe.example\nProxyCommand bad", "SSH_HOST"),
        ("--alias", "safe\nMatch all", "SSH_ALIAS"),
        ("--user", "deploy\nProxyCommand bad", "SSH_USER"),
        ("--comment", "comment\nssh-rsa injected", "SSH_KEY_COMMENT"),
    ),
    ids=("host", "alias", "user", "comment"),
)
def test_control_characters_are_rejected(
    ssh_case: SshCase, option: str, value: str, variable: str
) -> None:
    ssh_case.use_fakes()
    key = ssh_case.home / "injection/id_ed25519"
    args = ["--key-path", key, option, value]
    if option == "--alias":
        args[2:2] = ["--host", "safe.example"]
    result = ssh_case.run(*args)
    assert_status(result, 1)
    assert f"{variable} must not contain control characters" in result.stderr
    assert_absent(key)


def test_key_path_control_characters_are_rejected(ssh_case: SshCase) -> None:
    ssh_case.use_fakes()
    key = ssh_case.home / "control-path\nIdentityFile injected"
    result = ssh_case.run("--key-path", key)
    assert_status(result, 1)
    assert "SSH_KEY_PATH must not contain control characters" in result.stderr
    assert_absent(key)


@pytest.mark.parametrize(("option", "variable"), (("--host", "SSH_HOST"), ("--user", "SSH_USER")))
def test_ssh_operand_must_not_start_with_dash(
    ssh_case: SshCase, option: str, variable: str
) -> None:
    ssh_case.use_fakes()
    key = ssh_case.home / "injection/id_ed25519"
    result = ssh_case.run("--key-path", key, f"{option}=-oProxyCommand=bad")
    assert_status(result, 1)
    assert f"{variable} must not start with -" in result.stderr
    assert_absent(key)


def test_alias_requires_host_before_key_creation(ssh_case: SshCase) -> None:
    ssh_case.use_fakes()
    key = ssh_case.home / "alias-only/id_ed25519"
    result = ssh_case.run("--key-path", key, "--alias", "alias-only")
    assert_status(result, 1)
    assert "SSH_ALIAS requires SSH_HOST" in result.stderr
    assert_absent(key)
    assert_absent(key.parent)


@pytest.mark.parametrize("kind", ("dangling", "existing"))
def test_write_config_rejects_ssh_directory_symlink_before_keygen(
    ssh_case: SshCase, kind: str
) -> None:
    ssh_case.use_fakes()
    target = ssh_case.home / ("missing-ssh-dir" if kind == "dangling" else "linked-ssh-dir")
    if kind == "existing":
        target.mkdir(mode=0o700)
    (ssh_case.home / ".ssh").symlink_to(target, target_is_directory=True)
    key = ssh_case.home / "preflight/id_ed25519"
    result = ssh_case.run("--key-path", key, "--host", "safe.example", "--alias", "safe", "--write-config")
    assert_status(result, 1)
    assert "SSH directory must not be a symbolic link" in result.stderr
    assert_absent(key)
    if kind == "existing":
        assert_absent(target / "config")


def test_write_config_rejects_nondirectory_ssh_path_before_keygen(ssh_case: SshCase) -> None:
    ssh_case.use_fakes()
    (ssh_case.home / ".ssh").write_text("not a directory\n")
    key = ssh_case.home / "preflight/id_ed25519"
    result = ssh_case.run("--key-path", key, "--host", "safe.example", "--alias", "safe", "--write-config")
    assert_status(result, 1)
    assert "SSH directory is not a directory" in result.stderr
    assert_absent(key)


@pytest.mark.parametrize("kind", ("dangling", "existing"))
def test_write_config_rejects_config_symlink_before_keygen(
    ssh_case: SshCase, kind: str
) -> None:
    ssh_case.use_fakes()
    ssh_dir = ssh_case.home / ".ssh"
    ssh_dir.mkdir(mode=0o700)
    target = ssh_case.home / ("missing-config" if kind == "dangling" else "config-target")
    if kind == "existing":
        target.write_text("target config\n")
        target.chmod(0o644)
    (ssh_dir / "config").symlink_to(target)
    key = ssh_case.home / "preflight/id_ed25519"
    result = ssh_case.run("--key-path", key, "--host", "safe.example", "--alias", "safe", "--write-config")
    assert_status(result, 1)
    assert "SSH config must not be a symbolic link" in result.stderr
    assert_absent(key)
    if kind == "existing":
        assert target.read_text() == "target config\n"
        assert_mode(target, 0o644)


def test_write_config_rejects_nonregular_config_before_keygen(ssh_case: SshCase) -> None:
    ssh_case.use_fakes()
    config = ssh_case.home / ".ssh/config"
    config.mkdir(parents=True)
    config.parent.chmod(0o700)
    key = ssh_case.home / "preflight/id_ed25519"
    result = ssh_case.run("--key-path", key, "--host", "safe.example", "--alias", "safe", "--write-config")
    assert_status(result, 1)
    assert "SSH config is not a regular file" in result.stderr
    assert_absent(key)


def test_write_config_rejects_group_writable_ssh_directory(ssh_case: SshCase) -> None:
    ssh_case.use_fakes()
    ssh_dir = ssh_case.home / ".ssh"
    ssh_dir.mkdir(mode=0o720)
    ssh_dir.chmod(0o720)
    key = ssh_case.home / "preflight/id_ed25519"
    result = ssh_case.run("--key-path", key, "--host", "safe.example", "--alias", "safe", "--write-config")
    assert_status(result, 1)
    assert "SSH directory must not be writable by group or other users" in result.stderr
    assert_absent(key)


@pytest.mark.parametrize(
    ("mode", "message"),
    (
        (0o400, "SSH config must be readable and writable by its owner"),
        (0o620, "SSH config must not be writable by group or other users"),
    ),
    ids=("owner-not-writable", "group-writable"),
)
def test_write_config_rejects_unsafe_config_mode(
    ssh_case: SshCase, mode: int, message: str
) -> None:
    ssh_case.use_fakes()
    config = ssh_case.home / ".ssh/config"
    config.parent.mkdir(mode=0o700)
    config.write_text("Host existing\n")
    config.chmod(mode)
    key = ssh_case.home / "preflight/id_ed25519"
    result = ssh_case.run("--key-path", key, "--host", "safe.example", "--alias", "safe", "--write-config")
    assert_status(result, 1)
    assert message in result.stderr
    assert_absent(key)


@pytest.mark.parametrize("keyword", ("Host", "host", "hOsT"))
def test_duplicate_alias_is_case_insensitive_and_preflighted(
    ssh_case: SshCase, keyword: str
) -> None:
    ssh_case.use_fakes()
    config = ssh_case.home / ".ssh/config"
    config.parent.mkdir(mode=0o700)
    original = f"{keyword} duplicate\n  HostName existing.example\n"
    config.write_text(original)
    config.chmod(0o600)
    key = ssh_case.home / f"duplicate-{keyword}/id_ed25519"
    result = ssh_case.run("--key-path", key, "--host", "new.example", "--alias", "duplicate", "--write-config")
    assert_status(result, 1)
    assert "SSH config already contains Host duplicate" in result.stderr
    assert_absent(key)
    assert_absent(key.parent)
    assert config.read_text() == original


def test_write_config_writes_exact_block_and_modes(ssh_case: SshCase) -> None:
    ssh_case.use_fakes()
    key = ssh_case.home / "write path/id_ed25519"
    result = ssh_case.run(
        "--key-path", key, "--host", "write.example", "--user", "deploy", "--alias", "write-alias", "--write-config"
    )
    assert_status(result, 0)
    config = ssh_case.home / ".ssh/config"
    contents = config.read_text()
    assert not config.is_symlink()
    assert "Host write-alias" in contents
    assert f'  IdentityFile "{key}"' in contents
    assert_mode(config.parent, 0o700)
    assert_mode(config, 0o600)


def test_ssh_test_preserves_exact_argv_boundaries(ssh_case: SshCase) -> None:
    ssh_case.use_fakes()
    key = existing_private_key(ssh_case, "write path")
    Path(f"{key}.pub").write_text("ssh-ed25519 fake\n")
    command = f'printf "%s %s" one two; touch {ssh_case.base / "should-not-run-locally"}'
    result = ssh_case.run(
        "--key-path", key, "--host", "test.example", "--user", "tester", "--test-command", command, "--test"
    )
    assert_status(result, 0)
    assert ssh_case.ssh_log.read_text().splitlines() == [
        "<-i>",
        f"<{key}>",
        "<-o>",
        "<IdentitiesOnly=yes>",
        "<tester@test.example>",
        f"<{command}>",
    ]
    assert_absent(ssh_case.base / "should-not-run-locally")


def test_ssh_failure_status_is_propagated(ssh_case: SshCase) -> None:
    ssh_case.use_fakes()
    key = existing_private_key(ssh_case, "write")
    Path(f"{key}.pub").write_text("ssh-ed25519 fake\n")
    ssh_case.ssh_fail_status = "23"
    result = ssh_case.run("--key-path", key, "--host", "test.example", "--user", "tester", "--test")
    assert_status(result, 23)
    assert "[OK] SSH access test succeeded" not in result.stdout


def test_ssh_test_requires_host_before_key_creation(ssh_case: SshCase) -> None:
    ssh_case.use_fakes()
    key = ssh_case.home / "missing-host/id_ed25519"
    result = ssh_case.run("--key-path", key, "--test")
    assert_status(result, 1)
    assert "Required config variable SSH_HOST is missing or empty" in result.stderr
    assert_absent(key)
