import stat
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "bin/platform-bastion-policy"
FIXTURES = ROOT / "tests/bastion-policy/fixtures"
VALID_POLICY = FIXTURES / "access-policy.valid.yaml"
EXPECTED_CONFIGMAP = (
    ROOT / "examples/bastion-policy/bastion-csr-policy.configmap.example.yaml"
)


def test_valid_policy_has_no_output(process_runner) -> None:
    result = process_runner([TOOL, "validate", "--input", VALID_POLICY])

    assert (result.status, result.stdout, result.stderr) == (0, "", "")


def test_render_host_preserves_policy_and_secures_output(
    tmp_path: Path, process_runner
) -> None:
    output = tmp_path / "access-policy.yaml"
    result = process_runner(
        [TOOL, "render-host", "--input", VALID_POLICY, "--output", output]
    )

    assert (result.status, result.stdout, result.stderr) == (0, "", "")
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert yaml.safe_load(output.read_text(encoding="utf-8")) == yaml.safe_load(
        VALID_POLICY.read_text(encoding="utf-8")
    )


def test_render_csr_configmap_matches_projection_and_secures_output(
    tmp_path: Path, process_runner
) -> None:
    output = tmp_path / "bastion-csr-policy.configmap.yaml"
    result = process_runner(
        [
            TOOL,
            "render-csr-configmap",
            "--input",
            VALID_POLICY,
            "--name",
            "bastion-csr-policy",
            "--namespace",
            "bastion-system",
            "--output",
            output,
        ]
    )

    assert (result.status, result.stdout, result.stderr) == (0, "", "")
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert output.read_bytes() == EXPECTED_CONFIGMAP.read_bytes()

    configmap = yaml.safe_load(output.read_text(encoding="utf-8"))
    policy = yaml.safe_load(configmap["data"]["policy.yaml"])
    assert not {"cluster", "daemon", "bootstrap"} & policy.keys()
    assert "renewal" not in policy["csr"]
    assert policy["apiVersion"] == "bastion.csr-policy/v1"
    assert policy["csr"]["signerName"] == "example.com/client"
    assert policy["csr"]["groupPrefix"] == "k8s-"
    assert policy["csr"]["ttl"] == {
        "minSeconds": 3600,
        "defaultSeconds": 28800,
        "maxSeconds": 86400,
    }
    assert policy["csr"]["cleanup"]["retentionSeconds"] == 1209600
    assert set(policy["groups"]) == {"k8s-admins", "k8s-viewers"}
    assert set(policy["users"]) == {"alice", "bob"}


@pytest.mark.parametrize(
    ("fixture", "message"),
    [
        ("access-policy.invalid-missing-user-group.yaml", "k8s-missing"),
        ("access-policy.invalid-newline-group.yaml", "group name"),
        ("access-policy.invalid-newline-user.yaml", "user name"),
        ("access-policy.invalid-embedded-newline-user.yaml", "user name"),
    ],
    ids=["missing-user-group", "newline-group", "newline-user", "embedded-newline-user"],
)
def test_invalid_policy_is_rejected(fixture: str, message: str, process_runner) -> None:
    result = process_runner(
        [TOOL, "validate", "--input", FIXTURES / fixture]
    )

    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr.startswith("error: invalid access policy:\n")
    assert message in result.stderr


def test_render_host_refuses_existing_output(tmp_path: Path, process_runner) -> None:
    output = tmp_path / "existing-output.yaml"
    output.write_text("keep\n", encoding="utf-8")

    result = process_runner(
        [TOOL, "render-host", "--input", VALID_POLICY, "--output", output]
    )

    assert (result.status, result.stdout) == (1, "")
    assert result.stderr == f"error: refusing to overwrite existing output {output}\n"
    assert output.read_bytes() == b"keep\n"


def test_render_host_does_not_follow_output_symlink(
    tmp_path: Path, process_runner
) -> None:
    output = tmp_path / "symlink-output.yaml"
    target = tmp_path / "symlink-target.yaml"
    output.symlink_to(target)

    result = process_runner(
        [TOOL, "render-host", "--input", VALID_POLICY, "--output", output]
    )

    assert (result.status, result.stdout) == (1, "")
    assert result.stderr == f"error: refusing to overwrite existing output {output}\n"
    assert output.is_symlink()
    assert not target.exists()
