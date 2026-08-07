from __future__ import annotations

import os
import subprocess
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from src.platform_pki.errors import render_error
from src.platform_pki.paths import (
    PathError,
    PkiPaths,
    absolutize_path,
    default_namespace,
    default_pki_dir,
    expand_home,
    is_same_or_descendant,
    resolve_pki_paths,
    trees_are_disjoint,
    validate_absolute_path,
)


ROOT = Path(__file__).resolve().parents[1]


def _bash_common(
    function: str,
    argument: str | None,
    *,
    home: str,
    xdg: str | None,
) -> str:
    command = f'source "$1"; {function}'
    arguments = [
        "/bin/bash",
        "--noprofile",
        "--norc",
        "-c",
        command,
        "bash",
        os.fspath(ROOT / "lib/platform-pki-common.sh"),
    ]
    if argument is not None:
        arguments.append(argument)
    environment = {"HOME": home, "LC_ALL": "C", "PATH": "/usr/bin:/bin"}
    if xdg is not None:
        environment["XDG_CONFIG_HOME"] = xdg
    result = subprocess.run(
        arguments,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    )
    return result.stdout.removesuffix(b"\n").decode()


def test_home_expansion_matches_the_narrow_bash_contract() -> None:
    assert expand_home("~", home="/home/operator") == "/home/operator"
    assert expand_home("~/state/pki", home="/home/operator") == (
        "/home/operator/state/pki"
    )
    assert expand_home("~other/state", home="/home/operator") == "~other/state"
    assert expand_home("prefix/~/state", home="/home/operator") == "prefix/~/state"
    assert expand_home("~", home="") == ""
    assert expand_home("~/state", home="") == "/state"


@pytest.mark.parametrize(
    ("path", "home"),
    (
        ("~", "/home/operator"),
        ("~/state/pki", "/home/operator"),
        ("~other/state", "/home/operator"),
        ("~", ""),
        ("~/state", ""),
    ),
)
def test_home_expansion_is_source_backed(path: str, home: str) -> None:
    assert expand_home(path, home=home) == _bash_common(
        "pki_expand_path \"$2\"", path, home=home, xdg=None
    )


def test_namespace_and_pki_defaults_match_bash_empty_value_fallbacks() -> None:
    assert default_namespace(home="/home/operator", xdg_config_home="/xdg") == (
        "/xdg/platform-infrastructure"
    )
    assert default_namespace(home="/home/operator", xdg_config_home=None) == (
        "/home/operator/.config/platform-infrastructure"
    )
    assert default_namespace(home="/home/operator", xdg_config_home="") == (
        "/home/operator/.config/platform-infrastructure"
    )
    assert default_namespace(home="", xdg_config_home="") == (
        "/.config/platform-infrastructure"
    )
    assert default_pki_dir("/config/platform-infrastructure") == (
        "/config/platform-infrastructure/pki"
    )


@pytest.mark.parametrize(
    ("home", "xdg"),
    (
        ("/home/operator", "/xdg"),
        ("/home/operator", None),
        ("/home/operator", ""),
        ("", ""),
    ),
)
def test_namespace_default_is_source_backed(home: str, xdg: str | None) -> None:
    assert default_namespace(home=home, xdg_config_home=xdg) == _bash_common(
        "pki_default_namespace", None, home=home, xdg=xdg
    )


def test_relative_paths_use_only_the_supplied_physical_cwd() -> None:
    assert resolve_pki_paths(
        namespace=None,
        pki_dir=None,
        home="/unused",
        xdg_config_home="relative-config",
        physical_cwd="/physical/work",
    ) == PkiPaths(
        "/physical/work/relative-config/platform-infrastructure",
        "/physical/work/relative-config/platform-infrastructure/pki",
    )
    assert resolve_pki_paths(
        namespace="namespace",
        pki_dir="pki-state",
        home="/unused",
        xdg_config_home=None,
        physical_cwd="/physical/work",
    ) == PkiPaths("/physical/work/namespace", "/physical/work/pki-state")
    assert absolutize_path("child", physical_cwd="/") == "/child"


def test_tilde_user_remains_a_literal_relative_component_during_resolution() -> None:
    resolved = resolve_pki_paths(
        namespace="~service/namespace",
        pki_dir="~service/pki",
        home="/home/operator",
        xdg_config_home=None,
        physical_cwd="/physical/work",
    )
    assert resolved == PkiPaths(
        "/physical/work/~service/namespace",
        "/physical/work/~service/pki",
    )


def test_resolution_is_lexical_and_does_not_resolve_symlinks(tmp_path: Path) -> None:
    physical = tmp_path / "physical"
    target = tmp_path / "target"
    physical.mkdir()
    target.mkdir()
    (physical / "link").symlink_to(target, target_is_directory=True)

    result = resolve_pki_paths(
        namespace="link/namespace",
        pki_dir="link/pki",
        home="/unused",
        xdg_config_home=None,
        physical_cwd=str(physical),
    )

    assert result.namespace == f"{physical}/link/namespace"
    assert result.pki_dir == f"{physical}/link/pki"
    assert str(target) not in result.namespace
    assert str(target) not in result.pki_dir


@pytest.mark.parametrize(
    "path",
    (
        "",
        "relative",
        "/",
        "/trailing/",
        "//double",
        "/double//component",
        "/dot/./component",
        "/dot/.",
        "/parent/../component",
        "/parent/..",
    ),
)
def test_validation_rejects_root_and_noncanonical_forms(path: str) -> None:
    with pytest.raises(PathError):
        validate_absolute_path(path)


@pytest.mark.parametrize(
    "character",
    (
        "\0",
        "\n",
        "\r",
        "\t",
        "\x1b",
        "\x7f",
        "\u0085",
        "\u200b",
        "\u2028",
        "\u2029",
        "\u202e",
        "\ufeff",
        "\ud800",
    ),
)
def test_absolute_path_validation_rejects_controls_and_unicode_formatting(
    character: str,
) -> None:
    with pytest.raises(PathError) as caught:
        validate_absolute_path(f"/safe/{character}DO_NOT_DISCLOSE")

    assert character not in str(caught.value)
    assert "DO_NOT_DISCLOSE" not in str(caught.value)
    assert "DO_NOT_DISCLOSE" not in repr(caught.value)
    assert "DO_NOT_DISCLOSE" not in render_error(caught.value)


def test_valid_paths_preserve_lexical_spelling() -> None:
    for path in (
        "/a",
        "/a-b/c_d",
        "/space component/caf\N{LATIN SMALL LETTER E WITH ACUTE}",
        "/looks-like-symlink/target",
    ):
        assert validate_absolute_path(path) == path


def test_resolution_rejects_invalid_expanded_and_relative_paths() -> None:
    with pytest.raises(PathError):
        resolve_pki_paths(
            namespace="~",
            pki_dir=None,
            home="",
            xdg_config_home=None,
            physical_cwd="/work",
        )
    with pytest.raises(PathError):
        absolutize_path("state/../pki", physical_cwd="/work")
    with pytest.raises(PathError):
        absolutize_path("state", physical_cwd="/logical/../physical")


@pytest.mark.parametrize(
    ("path", "parent", "expected"),
    (
        ("/tree", "/tree", True),
        ("/tree/child", "/tree", True),
        ("/tree/deep/child", "/tree", True),
        ("/treehouse", "/tree", False),
        ("/tree-archive/child", "/tree", False),
        ("/tree", "/tree/child", False),
    ),
)
def test_same_or_descendant_is_component_aware(
    path: str, parent: str, expected: bool
) -> None:
    assert is_same_or_descendant(path, parent) is expected


@pytest.mark.parametrize(
    ("first", "second", "expected"),
    (
        ("/one", "/two", True),
        ("/tree", "/treehouse", True),
        ("/tree/a", "/tree/b", True),
        ("/tree", "/tree", False),
        ("/tree", "/tree/child", False),
        ("/tree/child", "/tree", False),
    ),
)
def test_tree_disjointness_is_symmetric_and_prefix_safe(
    first: str, second: str, expected: bool
) -> None:
    assert trees_are_disjoint(first, second) is expected
    assert trees_are_disjoint(second, first) is expected


def test_results_and_errors_are_immutable() -> None:
    paths = PkiPaths("/namespace", "/namespace/pki")
    with pytest.raises(FrozenInstanceError):
        paths.namespace = "/changed"  # type: ignore[misc]

    with pytest.raises(PathError) as caught:
        validate_absolute_path("/unsafe\ntext")
    with pytest.raises(FrozenInstanceError):
        caught.value.message = "changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        caught.value.reason = caught.value.reason  # type: ignore[misc]


@pytest.mark.parametrize(
    ("function", "arguments"),
    (
        (validate_absolute_path, (b"/bytes",)),
        (default_pki_dir, (Path("/path"),)),
    ),
)
def test_path_primitives_reject_non_text_inputs(
    function: object, arguments: tuple[object, ...]
) -> None:
    with pytest.raises(TypeError):
        function(*arguments)  # type: ignore[operator]
