import os
import sys
from pathlib import Path

import pytest

from . import migration_harness
from .migration_harness import (
    copy_private_case,
    managed_openssl_dir_normalizer,
    run_differential_case,
    snapshot_state,
    state_transitions,
)


pytestmark = pytest.mark.infrastructure


def _write_config(path: Path, directory: Path) -> None:
    path.parent.mkdir(parents=True)
    path.write_text(f"[ ca ]\ndir = {directory}\n", encoding="utf-8")


def test_private_copy_rebases_managed_configs_and_preserves_hardlinks(tmp_path: Path) -> None:
    source = tmp_path / "source"
    pki_relative = Path("namespace/pki")
    root_config = source / pki_relative / "authorities/roots/g1/openssl.cnf"
    intermediate_config = (
        source / pki_relative / "authorities/intermediates/g1-i1/openssl.cnf"
    )
    _write_config(root_config, root_config.parent)
    _write_config(intermediate_config, intermediate_config.parent)
    first = source / "linked-a"
    first.write_text("linked\n", encoding="utf-8")
    os.link(first, source / "linked-b")

    destination = tmp_path / "destination"
    copy_private_case(source, destination, pki_relative)

    assert f"dir = {destination / root_config.parent.relative_to(source)}\n" in (
        destination / root_config.relative_to(source)
    ).read_text(encoding="utf-8")
    assert f"dir = {destination / intermediate_config.parent.relative_to(source)}\n" in (
        destination / intermediate_config.relative_to(source)
    ).read_text(encoding="utf-8")
    copied = snapshot_state(
        destination,
        (managed_openssl_dir_normalizer(source, destination),),
    )
    linked = {entry.path: entry for entry in copied if entry.path.startswith("linked-")}
    assert linked["linked-a"].object_class == ("linked-a", "linked-b")
    assert linked["linked-b"].object_class == ("linked-a", "linked-b")


def test_semantic_snapshots_compare_private_copies_without_raw_identities(tmp_path: Path) -> None:
    source = tmp_path / "source"
    config = source / "pki/authorities/roots/g1/openssl.cnf"
    _write_config(config, config.parent)
    destination = tmp_path / "destination"
    copy_private_case(source, destination, Path("pki"))

    normalizer = managed_openssl_dir_normalizer(source, destination)
    source_snapshot = snapshot_state(source, (normalizer,))
    destination_snapshot = snapshot_state(
        destination,
        (normalizer,),
    )
    assert source_snapshot == destination_snapshot
    assert source_snapshot[0].identity != destination_snapshot[0].identity


def test_state_transitions_distinguish_modification_and_replacement(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    retained = state / "retained"
    replaced = state / "replaced"
    retained.write_text("before\n", encoding="utf-8")
    replaced.write_text("before\n", encoding="utf-8")
    before = snapshot_state(state)

    retained.write_text("after\n", encoding="utf-8")
    replacement = state / "replacement"
    replacement.write_text("after\n", encoding="utf-8")
    os.replace(replacement, replaced)
    after = snapshot_state(state)

    assert state_transitions(before, after) == {
        ".": "unchanged",
        "replaced": "replaced",
        "retained": "modified",
    }


def test_config_rebase_rejects_an_external_directory(tmp_path: Path) -> None:
    source = tmp_path / "source"
    config = source / "pki/authorities/roots/g1/openssl.cnf"
    _write_config(config, tmp_path / "outside")

    destination = tmp_path / "destination"
    try:
        copy_private_case(source, destination, Path("pki"))
    except ValueError as error:
        assert "escapes source workspace" in str(error)
    else:
        raise AssertionError("unsafe OpenSSL config was accepted")


@pytest.mark.parametrize("pki_relative", (Path("../outside"), Path("/outside"), Path()))
def test_private_copy_rejects_unsafe_pki_relative_path(
    tmp_path: Path, pki_relative: Path
) -> None:
    source = tmp_path / "source"
    (source / "pki").mkdir(parents=True)

    with pytest.raises(ValueError, match="nonempty relative path"):
        copy_private_case(source, tmp_path / "destination", pki_relative)


def test_config_rebase_rejects_lexical_traversal(tmp_path: Path) -> None:
    source = tmp_path / "source"
    config = source / "pki/authorities/roots/g1/openssl.cnf"
    _write_config(config, source / "../outside")

    with pytest.raises(ValueError, match="escapes source workspace"):
        copy_private_case(source, tmp_path / "destination", Path("pki"))


@pytest.mark.parametrize("unsafe_kind", ("symlink", "hardlink"))
def test_config_rebase_rejects_unsafe_config_object(
    tmp_path: Path, unsafe_kind: str
) -> None:
    source = tmp_path / "source"
    config = source / "pki/authorities/roots/g1/openssl.cnf"
    config.parent.mkdir(parents=True)
    other = source / "other.cnf"
    other.write_text(f"[ ca ]\ndir = {config.parent}\n", encoding="utf-8")
    if unsafe_kind == "symlink":
        config.symlink_to(other)
    else:
        os.link(other, config)

    with pytest.raises(ValueError, match="regular file|singly linked"):
        copy_private_case(source, tmp_path / "destination", Path("pki"))


def test_config_rebase_rejects_path_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    config = source / "pki/authorities/roots/g1/openssl.cnf"
    _write_config(config, config.parent)
    destination = tmp_path / "destination"
    copied_config = destination / config.relative_to(source)
    _write_config(copied_config, config.parent)
    attacker = destination / "attacker.cnf"
    attacker.write_text("attacker\n", encoding="utf-8")
    real_fstat = migration_harness.os.fstat
    replaced = False

    def replace_after_open(descriptor: int):
        nonlocal replaced
        opened_stat = real_fstat(descriptor)
        if not replaced:
            replaced = True
            os.replace(attacker, copied_config)
        return opened_stat

    monkeypatch.setattr(migration_harness.os, "fstat", replace_after_open)
    with pytest.raises(ValueError, match="changed while rebasing"):
        migration_harness.rebase_openssl_config(copied_config, source, destination)
    assert copied_config.read_text(encoding="utf-8") == "attacker\n"


def test_config_rebase_rejects_symlinked_authority_collection(tmp_path: Path) -> None:
    source = tmp_path / "source"
    pki = source / "pki"
    outside = source / "outside"
    outside.mkdir(parents=True)
    pki.mkdir()
    (pki / "authorities").mkdir()
    (pki / "authorities/roots").symlink_to(outside)

    with pytest.raises(ValueError, match="collection is not a real directory"):
        copy_private_case(source, tmp_path / "destination", Path("pki"))


def test_config_rebase_rejects_symlinked_authorities_ancestor(tmp_path: Path) -> None:
    source = tmp_path / "source"
    pki = source / "pki"
    outside = source / "outside"
    outside.mkdir(parents=True)
    pki.mkdir()
    (pki / "authorities").symlink_to(outside)

    with pytest.raises(ValueError, match="path component is not a real directory"):
        copy_private_case(source, tmp_path / "destination", Path("pki"))


def test_snapshot_rejects_symlink_root(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    root = tmp_path / "root"
    root.symlink_to(real)

    with pytest.raises(ValueError, match="Snapshot root is not a real directory"):
        snapshot_state(root)


def test_normalizer_ignores_signed_records_and_rejects_prefix_collisions(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    normalizer = managed_openssl_dir_normalizer(source)
    signed = f"schema=1\nrequest_path={source}/request\n".encode()
    assert normalizer("pki/state/csr/request", signed) == signed

    config = f"[ ca ]\ndir = {source}-other/pki\n".encode()
    with pytest.raises(ValueError, match="escapes known workspaces"):
        normalizer("pki/authorities/roots/g1/openssl.cnf", config)


def test_differential_runner_uses_private_state_and_environments(tmp_path: Path) -> None:
    seed = tmp_path / "seed"
    pki = seed / "namespace/pki"
    pki.mkdir(parents=True)
    config = pki / "authorities/roots/g1/openssl.cnf"
    _write_config(config, config.parent)
    script = tmp_path / "command.py"
    script.write_text(
        "import os\n"
        "import sys\n"
        "from pathlib import Path\n"
        "pki = Path(sys.argv[1])\n"
        "(pki / 'result').write_text('same\\n', encoding='utf-8')\n"
        "for name in ('HOME', 'TMPDIR', 'XDG_CACHE_HOME', 'XDG_CONFIG_HOME', "
        "'XDG_DATA_HOME', 'XDG_RUNTIME_DIR', 'XDG_STATE_HOME'):\n"
        "    print(f'{name}={os.environ[name]}')\n",
        encoding="utf-8",
    )

    def argv(root: Path) -> tuple[str | os.PathLike[str], ...]:
        return (sys.executable, script, root / "namespace/pki")

    def normalize_workspace(root: Path, output: str) -> str:
        return output.replace(os.fspath(root), "<WORKSPACE>")

    result = run_differential_case(
        seed,
        tmp_path / "case",
        Path("namespace/pki"),
        argv,
        argv,
        {
            "LC_ALL": "C",
            "PATH": os.environ["PATH"],
            "XDG_CACHE_HOME": "/shared/cache",
            "XDG_DATA_HOME": "/shared/data",
            "XDG_RUNTIME_DIR": "/shared/runtime",
            "XDG_STATE_HOME": "/shared/state",
        },
        output_normalizers=(normalize_workspace,),
    )

    result.assert_equivalent()
    assert result.bash.process.stdout == (
        "HOME=<WORKSPACE>/.differential-environment/home\n"
        "TMPDIR=<WORKSPACE>/.differential-environment/tmp\n"
        "XDG_CACHE_HOME=<WORKSPACE>/.differential-environment/cache\n"
        "XDG_CONFIG_HOME=<WORKSPACE>/.differential-environment/config\n"
        "XDG_DATA_HOME=<WORKSPACE>/.differential-environment/data\n"
        "XDG_RUNTIME_DIR=<WORKSPACE>/.differential-environment/runtime\n"
        "XDG_STATE_HOME=<WORKSPACE>/.differential-environment/state\n"
    )
    assert dict(result.bash.transitions)["result"] == "created"


def test_differential_runner_prepares_identity_bound_side_copies(
    tmp_path: Path,
) -> None:
    seed = tmp_path / "seed"
    pki = seed / "namespace/pki"
    pki.mkdir(parents=True)
    config = pki / "authorities/roots/g1/openssl.cnf"
    _write_config(config, config.parent)
    script = tmp_path / "recover.py"
    script.write_text(
        "import sys\n"
        "from pathlib import Path\n"
        "pki = Path(sys.argv[1])\n"
        "interrupted = pki / 'interrupted'\n"
        "expected = tuple(map(int, (interrupted / 'journal').read_text().split(':')))\n"
        "for name in ('source', 'alias'):\n"
        "    value = (interrupted / name).stat()\n"
        "    assert (value.st_dev, value.st_ino) == expected\n"
        "(pki / 'recovered').write_text('recovered\\n', encoding='utf-8')\n",
        encoding="utf-8",
    )
    prepared = []

    def prepare(side: str, root: Path, environment) -> None:
        assert root.name == side
        assert Path(environment["HOME"]) == root / ".differential-environment/home"
        assert Path(environment["HOME"]).is_dir()
        copied_config = root / config.relative_to(seed)
        assert f"dir = {copied_config.parent}\n" in copied_config.read_text(
            encoding="utf-8"
        )
        interrupted = root / "namespace/pki/interrupted"
        interrupted.mkdir()
        source = interrupted / "source"
        source.write_text("pending\n", encoding="utf-8")
        os.link(source, interrupted / "alias")
        source_stat = source.stat()
        (interrupted / "journal").write_text(
            f"{source_stat.st_dev}:{source_stat.st_ino}", encoding="utf-8"
        )
        prepared.append((side, root))

    def argv(root: Path) -> tuple[str | os.PathLike[str], ...]:
        return (sys.executable, script, root / "namespace/pki")

    def normalize_identity(relative: str, content: bytes) -> bytes:
        if relative == "interrupted/journal":
            return b"<IDENTITY>"
        return content

    result = run_differential_case(
        seed,
        tmp_path / "case",
        Path("namespace/pki"),
        argv,
        argv,
        {"LC_ALL": "C", "PATH": os.environ["PATH"]},
        content_normalizers=(normalize_identity,),
        bash_prepare=lambda root, environment: prepare("bash", root, environment),
        python_prepare=lambda root, environment: prepare("python", root, environment),
    )

    result.assert_equivalent()
    assert prepared == [
        ("bash", tmp_path / "case/bash"),
        ("python", tmp_path / "case/python"),
    ]
    before = {entry.path: entry for entry in result.bash.before}
    assert before["interrupted/source"].object_class == (
        "interrupted/alias",
        "interrupted/source",
    )
    assert before["interrupted/alias"].object_class == (
        "interrupted/alias",
        "interrupted/source",
    )
    assert dict(result.bash.transitions)["recovered"] == "created"


def test_differential_runner_revalidates_paths_after_preparation(
    tmp_path: Path,
) -> None:
    seed = tmp_path / "seed"
    (seed / "namespace/pki").mkdir(parents=True)

    def replace_namespace(root: Path, _environment) -> None:
        namespace = root / "namespace"
        retained = root / "retained-namespace"
        namespace.rename(retained)
        namespace.symlink_to(retained, target_is_directory=True)

    with pytest.raises(ValueError, match="path component is not a real directory"):
        run_differential_case(
            seed,
            tmp_path / "case",
            Path("namespace/pki"),
            lambda _root: (sys.executable, "-c", "pass"),
            lambda _root: (sys.executable, "-c", "pass"),
            {"LC_ALL": "C", "PATH": os.environ["PATH"]},
            bash_prepare=replace_namespace,
        )


def test_differential_runner_rejects_replaced_side_root(tmp_path: Path) -> None:
    seed = tmp_path / "seed"
    (seed / "namespace/pki").mkdir(parents=True)

    def replace_root(root: Path, _environment) -> None:
        retained = root.with_name(f"{root.name}-retained")
        root.rename(retained)
        root.symlink_to(retained, target_is_directory=True)

    with pytest.raises(ValueError, match="workspace changed during preparation"):
        run_differential_case(
            seed,
            tmp_path / "case",
            Path("namespace/pki"),
            lambda _root: (sys.executable, "-c", "pass"),
            lambda _root: (sys.executable, "-c", "pass"),
            {"LC_ALL": "C", "PATH": os.environ["PATH"]},
            bash_prepare=replace_root,
        )


def test_differential_runner_reports_process_divergence_without_output(tmp_path: Path) -> None:
    seed = tmp_path / "seed"
    (seed / "pki").mkdir(parents=True)

    def argv(status: int):
        return lambda _root: (sys.executable, "-c", f"raise SystemExit({status})")

    result = run_differential_case(
        seed,
        tmp_path / "case",
        Path("pki"),
        argv(0),
        argv(1),
        {"LC_ALL": "C", "PATH": os.environ["PATH"]},
    )

    with pytest.raises(AssertionError, match="process observations differ") as error:
        result.assert_equivalent()
    assert result.bash.process.status == 0
    assert result.python.process.status == 1
    assert str(error.value) == "differential process observations differ"


def test_differential_runner_uses_validated_nested_working_directory(
    tmp_path: Path,
) -> None:
    seed = tmp_path / "seed"
    (seed / "pki").mkdir(parents=True)
    (seed / "checkout/nested").mkdir(parents=True)

    def argv(_root: Path) -> tuple[str, ...]:
        return (sys.executable, "-c", "import os; print(os.getcwd())")

    def normalize(root: Path, output: str) -> str:
        return output.replace(os.fspath(root), "<CASE>")

    result = run_differential_case(
        seed,
        tmp_path / "case",
        Path("pki"),
        argv,
        argv,
        {"LC_ALL": "C", "PATH": os.environ["PATH"]},
        cwd_relative=Path("checkout/nested"),
        output_normalizers=(normalize,),
    )

    result.assert_equivalent()
    assert result.bash.process.stdout == "<CASE>/checkout/nested\n"


@pytest.mark.parametrize(
    "working_directory",
    [Path("/absolute"), Path("checkout/../outside")],
    ids=["absolute", "parent-traversal"],
)
def test_differential_runner_rejects_lexically_unsafe_working_directory(
    tmp_path: Path, working_directory: Path
) -> None:
    seed = tmp_path / "seed"
    (seed / "pki").mkdir(parents=True)

    with pytest.raises(ValueError, match="working directory must be relative"):
        run_differential_case(
            seed,
            tmp_path / "case",
            Path("pki"),
            lambda _root: (sys.executable, "-c", "pass"),
            lambda _root: (sys.executable, "-c", "pass"),
            {"LC_ALL": "C", "PATH": os.environ["PATH"]},
            cwd_relative=working_directory,
        )


@pytest.mark.parametrize("kind", ["symlink", "file", "missing"])
def test_differential_runner_rejects_unsafe_working_directory_components(
    tmp_path: Path, kind: str
) -> None:
    seed = tmp_path / "seed"
    (seed / "pki").mkdir(parents=True)
    external = tmp_path / "external"
    external.mkdir()
    working_directory = seed / "checkout"
    if kind == "symlink":
        working_directory.symlink_to(external, target_is_directory=True)
    elif kind == "file":
        working_directory.write_text("not a directory\n", encoding="utf-8")

    with pytest.raises(ValueError, match="working directory|path component"):
        run_differential_case(
            seed,
            tmp_path / "case",
            Path("pki"),
            lambda _root: (sys.executable, "-c", "pass"),
            lambda _root: (sys.executable, "-c", "pass"),
            {"LC_ALL": "C", "PATH": os.environ["PATH"]},
            cwd_relative=Path("checkout"),
        )
