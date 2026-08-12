from __future__ import annotations

import hashlib
import os
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

from ..harness import ProcessResult
from .migration_harness import run_differential_case
from .support import BIN, REPOSITORY, assert_result, environment, executable, executable_directory, mode, write_executable


pytestmark = pytest.mark.pki
TOOL = BIN / "platform-pki-init"
ORACLE = REPOSITORY / "tests/pki/oracles/platform-pki-init/platform-pki-init"
UNIFIED = BIN / "platform-pki"
ORACLE_COMMIT = "ee03cddc626338ea7d066dd71519204bddb46db3"
ORACLE_SHA256 = "bebb970bea2fbd46ed807854e14680416f9cef6e0e2b63557a7675ecc1e28e9e"
COMMON_SHA256 = "dee644be8ab6236cb368a553493f55b53a90c3aead291550f7e635c080a5494f"
TEMPLATE_SHA256 = "6faf52e34ab66d402b9777277383f5963aad417e748ea24de977de103e3cf2fe"


INTERFACES = (
    pytest.param((ORACLE,), id="bash-oracle"),
    pytest.param((TOOL,), id="python-compatibility"),
    pytest.param((UNIFIED, "init"), id="python-unified"),
)


def run(process_runner: Callable[..., ProcessResult], env: Mapping[str, str], *args: object) -> ProcessResult:
    return process_runner([TOOL, *args], env=env, timeout=30)


def run_interface(
    process_runner: Callable[..., ProcessResult],
    env: Mapping[str, str],
    tool: tuple[Path | str, ...],
    *args: object,
) -> ProcessResult:
    effective = dict(env)
    if tool == (ORACLE,):
        effective.setdefault(
            "PLATFORM_TOOLS_LIB_DIR",
            os.fspath(REPOSITORY / "tests/pki/oracles/final-bash-source/lib"),
        )
        effective.setdefault(
            "PLATFORM_TOOLS_TEMPLATE_DIR", os.fspath(REPOSITORY / "templates")
        )
    return process_runner([*tool, *args], env=effective, timeout=30)


def test_init_cli_contract(process_runner, isolated_environment) -> None:
    version = (REPOSITORY / "VERSION").read_text().strip()
    result = run(process_runner, isolated_environment, "--help")
    assert_result(result, 0, stderr="")
    assert "Usage:" in result.stdout
    assert "platform-pki-init --version | -v" in result.stdout
    oracle_help = run_interface(
        process_runner, isolated_environment, (ORACLE,), "--help"
    )
    assert result == ProcessResult(result.args, 0, oracle_help.stdout, "")

    result = run(process_runner, isolated_environment, "--version")
    assert_result(result, 0, stdout=f"platform-pki-init {version}\n", stderr="")

    for arguments, message in ((["--unknown"], "invalid option: --unknown"), (["--namespace", ""], "must not be empty")):
        result = run(process_runner, isolated_environment, *arguments)
        assert_result(result, 1, stdout="")
        assert message in result.stderr


def test_frozen_oracle_and_assets_match_recorded_provenance() -> None:
    plan = (REPOSITORY / "docs/plans/platform-pki-python-migration.md").read_text(
        encoding="utf-8"
    )

    assert hashlib.sha256(ORACLE.read_bytes()).hexdigest() == ORACLE_SHA256
    assert hashlib.sha256((REPOSITORY / "tests/pki/oracles/final-bash-source/lib/platform-pki-common.sh").read_bytes()).hexdigest() == COMMON_SHA256
    assert hashlib.sha256((REPOSITORY / "templates/pki/services.yml.example").read_bytes()).hexdigest() == TEMPLATE_SHA256
    assert ORACLE_COMMIT in plan
    assert os.access(ORACLE, os.X_OK)


@pytest.mark.parametrize("tool", INTERFACES)
def test_init_three_interfaces_fresh_repeat_force_and_preflight(
    tmp_path,
    process_runner,
    isolated_environment,
    tool,
) -> None:
    namespace = tmp_path / tool[0].name
    pki = namespace / "pki"
    example = pki / "inventory/services.yml.example"

    result = run_interface(
        process_runner, isolated_environment, tool, "--namespace", namespace
    )
    assert_result(
        result,
        0,
        stdout=(
            f"[OK] Wrote {example}\n"
            f"[OK] PKI directory ready: {pki}\n"
        ),
        stderr="",
    )

    example.write_text("retained example\n")
    example.chmod(0o600)
    result = run_interface(
        process_runner, isolated_environment, tool, "--namespace", namespace
    )
    assert_result(
        result,
        0,
        stdout=(
            f"[INFO] Kept existing file: {example}\n"
            f"[OK] PKI directory ready: {pki}\n"
        ),
        stderr="",
    )
    assert example.read_text() == "retained example\n"

    result = run_interface(
        process_runner,
        isolated_environment,
        tool,
        "--namespace",
        namespace,
        "--force",
    )
    assert_result(
        result,
        0,
        stdout=(
            f"[OK] Wrote {example}\n"
            f"[OK] PKI directory ready: {pki}\n"
        ),
        stderr="",
    )
    assert example.read_bytes() == (REPOSITORY / "templates/pki/services.yml.example").read_bytes()

    rejected = tmp_path / f"{tool[0].name}-rejected"
    result = run_interface(
        process_runner,
        isolated_environment,
        tool,
        "--namespace",
        rejected,
        "--pki-dir",
        rejected,
    )
    assert_result(result, 1, stdout="")
    assert result.stderr == (
        f"[ERROR] PKI directory must not equal or contain the namespace: {rejected}\n"
    )
    assert not rejected.exists()


@pytest.mark.parametrize("tool", INTERFACES)
def test_init_three_interfaces_expand_home_paths(
    process_runner,
    isolated_environment,
    tool,
) -> None:
    home = Path(isolated_environment["HOME"])
    home.parent.chmod(0o700)
    home.chmod(0o700)
    namespace = home / "expanded-namespace"
    pki = home / "expanded-pki"

    result = run_interface(
        process_runner,
        isolated_environment,
        tool,
        "--namespace",
        "~/expanded-namespace",
        "--pki-dir",
        "~/expanded-pki",
    )

    assert_result(result, 0, stderr="")
    assert f"[OK] PKI directory ready: {pki}\n" in result.stdout
    assert namespace.is_dir() and mode(namespace) == 0o700
    assert (pki / "inventory/services.yml.example").is_file()


def test_init_creates_modes_and_force_only_refreshes_example(tmp_path, process_runner, isolated_environment) -> None:
    namespace = tmp_path / "namespace"
    pki = namespace / "pki"
    result = run(process_runner, isolated_environment, "--namespace", namespace)
    assert_result(result, 0, stderr="")
    assert f"[OK] PKI directory ready: {pki}" in result.stdout
    directories = (
        namespace, pki, pki / "inventory", pki / "authorities", pki / "authorities/roots",
        pki / "authorities/intermediates", pki / "state", pki / "state/generation-reservations",
        pki / "state/rollover", pki / "locks", pki / "services", pki / "export",
        pki / "export/ansible", pki / "backups",
    )
    assert all(path.is_dir() and mode(path) == 0o700 for path in directories)
    example = pki / "inventory/services.yml.example"
    assert example.is_file() and mode(example) == 0o600

    root = pki / "authorities/roots/g1"
    intermediate = pki / "authorities/intermediates/g1-i1"
    for directory in (root, root / "private", root / "certs", intermediate):
        directory.mkdir(mode=0o700)
    sentinels = {
        pki / "inventory/services.yml": "custom inventory\n",
        example: "custom example\n",
        root / "index.txt": "custom index\n",
        intermediate / "serial": "custom serial\n",
        root / "private/root-ca.key": "private key sentinel\n",
        root / "certs/root-ca.crt": "certificate sentinel\n",
    }
    for path, content in sentinels.items():
        path.write_text(content)
        path.chmod(0o600)

    assert_result(run(process_runner, isolated_environment, "--namespace", namespace), 0, stderr="")
    assert (pki / "inventory/services.yml").read_text() == sentinels[pki / "inventory/services.yml"]
    assert example.read_text() == "custom example\n"

    assert_result(run(process_runner, isolated_environment, "--namespace", namespace, "--force"), 0, stderr="")
    assert example.read_bytes() == (REPOSITORY / "templates/pki/services.yml.example").read_bytes()
    for path in sentinels.keys() - {example}:
        assert path.read_text() == sentinels[path]
    assert mode(root / "private/root-ca.key") == 0o600


@pytest.mark.parametrize(
    ("arguments", "message", "absent"),
    [
        (["--namespace", "/"], "Namespace must not be the filesystem root", None),
        (["--namespace", "relative/path"], "Namespace must be an absolute path", None),
        (["--namespace", "{tmp}/trailing/"], "Namespace must not end with a slash", None),
        (["--namespace", "{tmp}/equal", "--pki-dir", "{tmp}/equal"], "PKI directory must not equal or contain the namespace", "{tmp}/equal"),
        (["--namespace", "{tmp}/overlap/pki.env/namespace", "--pki-dir", "{tmp}/overlap"], "PKI directory must not equal or contain the namespace", "{tmp}/overlap"),
    ],
)
def test_init_rejects_unsafe_namespace_relationships(tmp_path, process_runner, isolated_environment, arguments, message, absent) -> None:
    rendered = [value.replace("{tmp}", os.fspath(tmp_path)) for value in arguments]
    result = run(process_runner, isolated_environment, *rendered)
    assert_result(result, 1, stdout="")
    assert message in result.stderr
    if absent:
        assert not Path(absent.replace("{tmp}", os.fspath(tmp_path))).exists()


def test_init_rejects_symlink_namespace_and_creation_race(tmp_path, process_runner, isolated_environment, executable_directory) -> None:
    victim = tmp_path / "victim"
    victim.mkdir(mode=0o755)
    alias = tmp_path / "namespace-link"
    alias.symlink_to(victim, target_is_directory=True)
    result = run(process_runner, isolated_environment, "--namespace", alias)
    assert_result(result, 1, stdout="")
    assert "Namespace path component must not be a symlink" in result.stderr
    assert mode(victim) == 0o755

    race_bin = executable_directory / "race-bin"
    write_executable(race_bin / "mkdir", """#!/usr/bin/env bash
set -euo pipefail
target=${!#}
if [[ $target == "$RACE_TARGET" ]]; then
  ln -s "$RACE_VICTIM" "$target"
  : >"$RACE_MARKER"
  exit 1
fi
exec "$REAL_MKDIR" "$@"
""")
    race_target = tmp_path / "race-namespace"
    race_marker = tmp_path / "race-triggered"
    result = run(
        process_runner,
        environment(isolated_environment, PATH=f"{race_bin}:{isolated_environment['PATH']}", RACE_TARGET=os.fspath(race_target), RACE_VICTIM=os.fspath(victim), RACE_MARKER=os.fspath(race_marker), REAL_MKDIR=executable("mkdir")),
        "--namespace", race_target,
    )
    assert_result(result, 1, stdout="")
    assert race_marker.is_file()
    assert race_target.is_symlink()
    assert race_target.readlink() == victim
    assert "Cannot create Namespace path component" in result.stderr
    assert mode(victim) == 0o755
    assert not (victim / "pki").exists()


def test_init_rejects_existing_links(tmp_path, process_runner, isolated_environment) -> None:
    namespace = tmp_path / "nested"
    pki = namespace / "pki"
    victim = tmp_path / "victim"
    (pki).mkdir(parents=True)
    namespace.chmod(0o755)
    pki.chmod(0o755)
    victim.mkdir(mode=0o755)
    victim.chmod(0o755)
    (pki / "authorities").symlink_to(victim, target_is_directory=True)
    result = run(process_runner, isolated_environment, "--namespace", namespace)
    assert_result(result, 1, stdout="")
    assert "Existing PKI state must not contain symlinks" in result.stderr
    assert mode(namespace) == mode(pki) == mode(victim) == 0o755

    for kind in ("hard", "symbolic"):
        case = tmp_path / kind
        assert_result(run(process_runner, isolated_environment, "--namespace", case), 0)
        case_pki = case / "pki"
        private = case_pki / "services/custom/private"
        private.mkdir(parents=True, mode=0o700)
        (case_pki / "services/custom").chmod(0o700)
        private.chmod(0o700)
        key = private / "tls.key"
        key.write_text(f"{kind} link key sentinel\n")
        example = case_pki / "inventory/services.yml.example"
        example.unlink()
        if kind == "hard":
            os.link(key, example)
        else:
            example.symlink_to(key)
        result = run(process_runner, isolated_environment, "--namespace", case, "--force")
        assert_result(result, 1, stdout="")
        assert ("hard-linked files" if kind == "hard" else "symlinks") in result.stderr
        assert key.read_text() == f"{kind} link key sentinel\n"


@pytest.mark.parametrize("collision", ["directory", "fifo", "file"])
def test_init_rejects_destination_type_collisions_without_partial_state(tmp_path, process_runner, isolated_environment, collision) -> None:
    namespace = tmp_path / collision
    pki = namespace / "pki"
    pki.mkdir(parents=True)
    namespace.chmod(0o755)
    pki.chmod(0o755)
    if collision == "directory":
        (pki / "state").mkdir()
        (pki / "authorities").write_text("collision\n")
        absent = pki / "inventory"
    elif collision == "fifo":
        os.mkfifo(pki / "locks")
        absent = pki / "authorities/roots/g1"
    else:
        (pki / "services").write_text("not a directory\n")
        absent = pki / "authorities/roots/g1"
    result = run(process_runner, isolated_environment, "--namespace", namespace)
    assert_result(result, 1, stdout="")
    assert "PKI directory destination must be a non-symlink directory" in result.stderr
    assert mode(namespace) == mode(pki) == 0o755
    assert not absent.exists()


def test_init_rejects_unsafe_existing_modes(tmp_path, process_runner, isolated_environment) -> None:
    unsafe = tmp_path / "unsafe-mode"
    (unsafe / "pki/state").mkdir(parents=True)
    unsafe.chmod(0o755)
    (unsafe / "pki").chmod(0o755)
    (unsafe / "pki/state").chmod(0o777)
    result = run(process_runner, isolated_environment, "--namespace", unsafe)
    assert_result(result, 1, stdout="")
    assert "PKI directory destination is group- or world-writable" in result.stderr
    assert mode(unsafe / "pki/state") == 0o777
    assert not (unsafe / "pki/inventory").exists()

    for name, prepare, message, expected in (
        ("writable-file", lambda p: (p / "inventory/services.yml.example").chmod(0o666), "PKI file destination is group- or world-writable", 0o666),
        ("writable-private", lambda p: ((p / "services/custom/private").mkdir(parents=True), (p / "services/custom").chmod(0o700), (p / "services/custom/private").chmod(0o777)), "Private directory is group- or world-writable", 0o777),
        ("open-key", lambda p: ((p / "services/custom/private").mkdir(parents=True), (p / "services/custom").chmod(0o700), (p / "services/custom/private").chmod(0o700), (p / "services/custom/private/tls.key").write_text("open key\n"), (p / "services/custom/private/tls.key").chmod(0o644)), "Private key permissions are too open", 0o644),
    ):
        namespace = tmp_path / name
        assert_result(run(process_runner, isolated_environment, "--namespace", namespace), 0)
        pki = namespace / "pki"
        prepare(pki)
        result = run(process_runner, isolated_environment, "--namespace", namespace)
        assert_result(result, 1, stdout="")
        assert message in result.stderr
        target = pki / ("inventory/services.yml.example" if name == "writable-file" else "services/custom/private" if name == "writable-private" else "services/custom/private/tls.key")
        assert mode(target) == expected


def test_init_template_discovery_and_missing_templates(tmp_path, process_runner, isolated_environment, executable_directory) -> None:
    custom = tmp_path / "custom-templates/pki"
    custom.mkdir(parents=True)
    for source in (REPOSITORY / "templates/pki").iterdir():
        if source.is_file():
            (custom / source.name).write_bytes(source.read_bytes())
    (custom / "services.yml.example").write_text("custom template source\n")
    explicit_bin = executable_directory / "explicit/bin"
    explicit_bin.mkdir(parents=True)
    (explicit_bin / TOOL.name).write_bytes(TOOL.read_bytes())
    (explicit_bin / TOOL.name).chmod(0o755)
    result = process_runner(
        [explicit_bin / TOOL.name, "--namespace", tmp_path / "custom-namespace", "--pki-dir", tmp_path / "custom-pki"],
        env=environment(isolated_environment, PLATFORM_TOOLS_TEMPLATE_DIR=os.fspath(custom.parent)), timeout=30,
    )
    assert_result(result, 0, stderr="")
    assert (tmp_path / "custom-pki/inventory/services.yml.example").read_text() == "custom template source\n"

    (custom / "services.yml.example").unlink()
    incomplete = tmp_path / "incomplete"
    result = run(process_runner, environment(isolated_environment, PLATFORM_TOOLS_TEMPLATE_DIR=os.fspath(custom.parent)), "--namespace", incomplete)
    assert_result(result, 1, stdout="")
    assert "Required PKI template is missing or unsafe" in result.stderr
    assert not incomplete.exists()


def test_init_ignores_common_library_directory(
    tmp_path, process_runner, isolated_environment
) -> None:
    library = tmp_path / "bad-lib/platform-pki-common.sh"
    library.mkdir(mode=0o700, parents=True)
    namespace = tmp_path / "bad-library-namespace"

    result = run(
        process_runner,
        environment(
            isolated_environment,
            PLATFORM_TOOLS_LIB_DIR=os.fspath(library.parent),
        ),
        "--namespace",
        namespace,
    )

    assert_result(result, 0, stderr="")
    assert (namespace / "pki/inventory/services.yml.example").is_file()


def test_init_failed_template_rename_cleans_temporary_file(tmp_path, process_runner, isolated_environment, executable_directory) -> None:
    fake_bin = executable_directory / "failing-bin"
    write_executable(fake_bin / "mv", "#!/usr/bin/env bash\n: >\"$MV_FAIL_MARKER\"\nexit 1\n")
    namespace = tmp_path / "rename-failure"
    marker = tmp_path / "mv-fail-triggered"
    result = run(process_runner, environment(isolated_environment, PATH=f"{fake_bin}:{isolated_environment['PATH']}", MV_FAIL_MARKER=os.fspath(marker)), "--namespace", namespace)
    assert_result(result, 1, stdout="")
    assert marker.is_file()
    assert "Failed to replace template:" in result.stderr
    assert not list(namespace.rglob(".platform-pki-init.*"))


@pytest.mark.parametrize("templates_present", [True, False], ids=["installed-layout", "missing-templates"])
def test_init_installed_share_layout(tmp_path, process_runner, isolated_environment, executable_directory, templates_present) -> None:
    installed_bin = executable_directory / "installed/bin"
    share = tmp_path / "installed/share"
    share.mkdir(parents=True)
    installed_bin.mkdir(parents=True)
    (installed_bin / TOOL.name).write_bytes(TOOL.read_bytes())
    (installed_bin / TOOL.name).chmod(0o755)
    if templates_present:
        destination = share / "templates/pki"
        destination.mkdir(parents=True)
        for source in (REPOSITORY / "templates/pki").iterdir():
            if source.is_file():
                (destination / source.name).write_bytes(source.read_bytes())
    namespace = tmp_path / "installed-namespace"
    result = process_runner([installed_bin / TOOL.name, "--namespace", namespace], env=environment(isolated_environment, PLATFORM_TOOLS_SHARE_DIR=os.fspath(share)), timeout=30)
    if templates_present:
        assert_result(result, 0, stderr="")
        assert (namespace / "pki/inventory/services.yml.example").is_file()
        assert not (namespace / "pki/inventory/services.yml").exists()
    else:
        assert_result(result, 1, stdout="")
        assert "PKI templates not found" in result.stderr
        assert not namespace.exists()


def _normalize_case_root(root: Path, output: str) -> str:
    return output.replace(os.fspath(root), "<CASE>")


def _differential_environment(isolated_environment: Mapping[str, str]) -> dict[str, str]:
    return environment(
        isolated_environment,
        PLATFORM_TOOLS_LIB_DIR=os.fspath(
            REPOSITORY / "tests/pki/oracles/final-bash-source/lib"
        ),
        PLATFORM_TOOLS_TEMPLATE_DIR=os.fspath(REPOSITORY / "templates"),
    )


def _run_init_differential(
    seed: Path,
    case_root: Path,
    isolated_environment: Mapping[str, str],
    *arguments: str,
    extra_environment: Mapping[str, str] | None = None,
):
    base_environment = _differential_environment(isolated_environment)
    if extra_environment is not None:
        base_environment.update(extra_environment)
    return run_differential_case(
        seed,
        case_root,
        Path("containing-root"),
        lambda root: (
            ORACLE,
            "--namespace",
            root / "containing-root/namespace",
            *arguments,
        ),
        lambda root: (
            UNIFIED,
            "init",
            "--namespace",
            root / "containing-root/namespace",
            *arguments,
        ),
        base_environment,
        output_normalizers=(_normalize_case_root,),
        run_options={"timeout": 30},
    )


def _differential_seed(tmp_path: Path) -> tuple[Path, Path]:
    seed = tmp_path / "seed"
    containing_root = seed / "containing-root"
    containing_root.mkdir(mode=0o700, parents=True)
    seed.chmod(0o700)
    containing_root.chmod(0o700)
    return seed, containing_root


def _initialize_seed(
    seed: Path,
    containing_root: Path,
    process_runner: Callable[..., ProcessResult],
    isolated_environment: Mapping[str, str],
) -> Path:
    namespace = containing_root / "namespace"
    result = run_interface(
        process_runner,
        isolated_environment,
        (ORACLE,),
        "--namespace",
        namespace,
    )
    assert_result(result, 0, stderr="")
    return namespace


def test_bash_python_fresh_creation_is_equivalent(
    tmp_path, isolated_environment
) -> None:
    seed, _ = _differential_seed(tmp_path)

    result = _run_init_differential(
        seed, tmp_path / "fresh-case", isolated_environment
    )

    result.assert_equivalent()


def test_bash_python_repeat_and_force_replacement_are_equivalent(
    tmp_path, process_runner, isolated_environment
) -> None:
    seed, containing_root = _differential_seed(tmp_path)
    namespace = _initialize_seed(
        seed, containing_root, process_runner, isolated_environment
    )
    example = namespace / "pki/inventory/services.yml.example"
    example.write_text("custom example\n")
    example.chmod(0o600)

    repeat = _run_init_differential(
        seed, tmp_path / "repeat-case", isolated_environment
    )
    repeat.assert_equivalent()

    force = _run_init_differential(
        seed, tmp_path / "force-case", isolated_environment, "--force"
    )
    force.assert_equivalent()


def test_bash_python_preflight_failure_is_equivalent(
    tmp_path, isolated_environment
) -> None:
    seed, containing_root = _differential_seed(tmp_path)
    pki = containing_root / "namespace/pki"
    pki.mkdir(mode=0o700, parents=True)
    (pki / "services").write_text("destination collision\n")

    result = _run_init_differential(
        seed, tmp_path / "preflight-case", isolated_environment
    )

    result.assert_equivalent()


def test_bash_python_failed_publication_cleans_stage_equivalently(
    tmp_path,
    process_runner,
    isolated_environment,
    executable_directory,
) -> None:
    seed, containing_root = _differential_seed(tmp_path)
    _initialize_seed(seed, containing_root, process_runner, isolated_environment)
    fake_bin = executable_directory / "differential-failing-bin"
    write_executable(fake_bin / "mv", "#!/usr/bin/env bash\nexit 1\n")

    result = _run_init_differential(
        seed,
        tmp_path / "failed-publication-case",
        isolated_environment,
        "--force",
        extra_environment={
            "PATH": f"{fake_bin}:{isolated_environment['PATH']}",
        },
    )

    result.assert_equivalent()
    assert all(
        not any(path.rglob(".platform-pki-init.*"))
        for path in (
            tmp_path / "failed-publication-case/bash/containing-root",
            tmp_path / "failed-publication-case/python/containing-root",
        )
    )


def test_bash_python_ineffective_successful_move_cleans_stage_equivalently(
    tmp_path,
    process_runner,
    isolated_environment,
    executable_directory,
) -> None:
    seed, containing_root = _differential_seed(tmp_path)
    namespace = _initialize_seed(
        seed, containing_root, process_runner, isolated_environment
    )
    example = namespace / "pki/inventory/services.yml.example"
    example.write_text("retained example\n")
    example.chmod(0o600)
    fake_bin = executable_directory / "differential-ineffective-bin"
    write_executable(fake_bin / "mv", "#!/usr/bin/env bash\nexit 0\n")

    result = _run_init_differential(
        seed,
        tmp_path / "ineffective-publication-case",
        isolated_environment,
        "--force",
        extra_environment={
            "PATH": f"{fake_bin}:{isolated_environment['PATH']}",
        },
    )

    result.assert_equivalent()
    for path in (
        tmp_path / "ineffective-publication-case/bash/containing-root",
        tmp_path / "ineffective-publication-case/python/containing-root",
    ):
        assert not any(path.rglob(".platform-pki-init.*"))
        assert (
            path / "namespace/pki/inventory/services.yml.example"
        ).read_text() == "retained example\n"


def test_bash_python_relative_pki_rejection_is_equivalent(
    tmp_path, isolated_environment
) -> None:
    seed, _ = _differential_seed(tmp_path)

    result = _run_init_differential(
        seed,
        tmp_path / "relative-pki-case",
        isolated_environment,
        "--pki-dir",
        "relative/pki",
    )

    result.assert_equivalent()


@pytest.mark.parametrize("case", ["symlink", "hardlink", "private-mode"])
def test_bash_python_unsafe_existing_tree_rejection_is_equivalent(
    tmp_path,
    process_runner,
    isolated_environment,
    case,
) -> None:
    seed, containing_root = _differential_seed(tmp_path)
    namespace = _initialize_seed(
        seed, containing_root, process_runner, isolated_environment
    )
    pki = namespace / "pki"
    private = pki / "services/custom/private"
    private.mkdir(mode=0o700, parents=True)
    (pki / "services/custom").chmod(0o700)

    if case == "symlink":
        (private / "linked").symlink_to(pki / "inventory", target_is_directory=True)
    elif case == "hardlink":
        source = private / "tls.key"
        source.write_text("key sentinel\n")
        source.chmod(0o600)
        os.link(source, pki / "inventory/linked-key")
    else:
        private.chmod(0o777)

    result = _run_init_differential(
        seed,
        tmp_path / f"unsafe-tree-{case}-case",
        isolated_environment,
    )

    result.assert_equivalent()


def test_bash_python_namespace_creation_race_is_equivalent(
    tmp_path,
    isolated_environment,
    executable_directory,
) -> None:
    seed, _ = _differential_seed(tmp_path)
    victim = tmp_path / "creation-race-victim"
    victim.mkdir(mode=0o700)
    fake_bin = executable_directory / "differential-creation-race-bin"
    write_executable(
        fake_bin / "mkdir",
        """#!/usr/bin/env bash
set -euo pipefail
target=${!#}
if [[ $target == */namespace ]]; then
  ln -s "$RACE_VICTIM" "$target"
  exit 1
fi
exec "$REAL_MKDIR" "$@"
""",
    )

    result = _run_init_differential(
        seed,
        tmp_path / "creation-race-case",
        isolated_environment,
        extra_environment={
            "PATH": f"{fake_bin}:{isolated_environment['PATH']}",
            "RACE_VICTIM": os.fspath(victim),
            "REAL_MKDIR": executable("mkdir"),
        },
    )

    result.assert_equivalent()


def test_bash_python_template_destination_race_is_equivalent(
    tmp_path,
    isolated_environment,
    executable_directory,
) -> None:
    seed, _ = _differential_seed(tmp_path)
    victim = tmp_path / "template-race-victim"
    victim.write_text("victim sentinel\n")
    fake_bin = executable_directory / "differential-template-race-bin"
    write_executable(
        fake_bin / "chmod",
        """#!/usr/bin/env bash
set -euo pipefail
target=${!#}
"$REAL_CHMOD" "$@"
if [[ $target == */inventory ]]; then
  ln -s "$RACE_VICTIM" "$target/services.yml.example"
fi
""",
    )

    result = _run_init_differential(
        seed,
        tmp_path / "template-destination-race-case",
        isolated_environment,
        "--force",
        extra_environment={
            "PATH": f"{fake_bin}:{isolated_environment['PATH']}",
            "RACE_VICTIM": os.fspath(victim),
            "REAL_CHMOD": executable("chmod"),
        },
    )

    result.assert_equivalent()
    assert victim.read_text() == "victim sentinel\n"


def test_bash_python_missing_template_rejection_is_equivalent(
    tmp_path, isolated_environment
) -> None:
    seed, _ = _differential_seed(tmp_path)
    template_root = tmp_path / "missing-template-root"
    (template_root / "pki").mkdir(mode=0o700, parents=True)

    result = _run_init_differential(
        seed,
        tmp_path / "missing-template-case",
        isolated_environment,
        extra_environment={
            "PLATFORM_TOOLS_TEMPLATE_DIR": os.fspath(template_root),
        },
    )

    result.assert_equivalent()
