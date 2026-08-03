from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[2]
TOOL = ROOT / "bin/platform-proxmox-vm-snapshot"
FAKES = ROOT / "tests/proxmox-vm-snapshot/fake-bin"
FIXTURES = ROOT / "tests/proxmox-vm-snapshot/fixtures"


@pytest.fixture
def snapshot_env(tmp_path, process_runner):
    state = tmp_path / "state"
    base_env = {**os.environ, "PATH": f"{FAKES}:{os.environ['PATH']}", "FAKE_PVE_STATE": os.fspath(state)}

    class SnapshotTool:
        def create_state(self):
            if state.exists():
                for path in sorted(state.rglob("*"), reverse=True):
                    path.unlink() if path.is_file() or path.is_symlink() else path.rmdir()
                state.rmdir()
            for name in ("configs", "status", "snapshots"):
                (state / name).mkdir(parents=True, exist_ok=True)
            copies = {
                "nodes.single.json": "nodes.json", "inventory.json": "inventory.json",
                "config-101.json": "configs/101.json", "config-102.json": "configs/102.json",
                "config-103.json": "configs/103.json", "config-9000.json": "configs/9000.json",
                "status-running.json": "status/101.json", "status-stopped.json": "status/102.json",
                "status-stopped.json#103": "status/103.json", "status-stopped.json#9000": "status/9000.json",
                "snapshots.current.json": "snapshots/101.json", "snapshots.current.json#102": "snapshots/102.json",
                "snapshots.current.json#103": "snapshots/103.json", "snapshots.current.json#9000": "snapshots/9000.json",
            }
            for source, destination in copies.items():
                (state / destination).write_bytes((FIXTURES / source.split("#")[0]).read_bytes())
            for name in ("pvesh.log", "qm.log", "qm-order.log", "ssh.log"):
                (state / name).touch()

        def run(self, *args: str, update=None, input=None, pty=False):
            return process_runner(
                (TOOL, *args), env={**base_env, **(update or {})}, input=input,
                pty_mode="canonical" if pty else None,
            )

        def log(self, name):
            return (state / f"{name}.log").read_text()

        def read_json(self, relative):
            return json.loads((state / relative).read_text())

        def write_json(self, relative, value):
            (state / relative).write_text(json.dumps(value) + "\n")

        def checkpoint(self, vmid=101):
            (state / f"snapshots/{vmid}.json").write_bytes((FIXTURES / "snapshots.checkpoint.json").read_bytes())

        def capture_manifest(self, path, *args):
            result = self.run("create", *args, "--internal-preflight")
            assert result.status == 0, result.stderr
            path.write_text(result.stdout)
            path.chmod(0o600)

    tool = SnapshotTool()
    tool.create_state()
    return tool, state, tmp_path


@pytest.mark.parametrize(
    ("args", "status", "message", "stderr_only"),
    [
        ((), 1, "platform-proxmox-vm-snapshot COMMAND", False),
        (("create", "--unknown"), 1, "invalid option: --unknown", True),
        (("create", "--vmid", "101", "--snapshot-name", "valid-name", "--start-after-rollback"), 1, "invalid option: --start-after-rollback", False),
        (("rollback", "--vmid", "101", "--snapshot-name", "valid-name", "--description", "invalid"), 1, "invalid option: --description", False),
        (("list",), 1, "Exactly one of --vmid, --vm-name, or --environment is required", False),
        (("list", "--vmid="), 1, "invalid option: --vmid=", False),
        (("create", "--vmid", "101", "--snapshot-name", "valid-name", "--dry-run=true"), 1, "invalid argument: true", False),
        (("create", "--vmid", "101", "--snapshot-name", "valid-name", "--dry-run="), 1, "invalid option: --dry-run=", False),
        (("create", "--vmid", "--help", "--snapshot-name", "valid-name"), 1, "--vmid must be an integer", False),
        (("create", "--vmid", "101", "--snapshot-name", "a"), 1, "2-40 characters", False),
        (("create", "--vmid"), 1, "--vmid requires an argument", False),
        (("create", "--vmid", "101", "--snapshot-name", "current"), 1, "Reserved snapshot name: current", False),
        (("create", "--vmid", "101", "--snapshot-name", "PENDING"), 1, "Reserved snapshot name: PENDING", False),
        (("list", "--environment", "managed-by-tofu"), 1, "Reserved environment selector", False),
        (("list", "--environment", "all"), 1, "Reserved environment selector: all", False),
        (("list", "--environment", "*"), 1, "valid exact Proxmox tag", False),
        (("list", "--vmid", "101", "--yes"), 1, "invalid option: --yes", False),
        (("create", "--vmid", "101", "--snapshot-name", "valid-name", "--yes", "--dry-run"), 1, "--yes cannot be combined", False),
    ],
)
def test_parser_and_validation_contract(snapshot_env, args, status, message, stderr_only):
    tool, *_ = snapshot_env
    result = tool.run(*args)
    assert result.status == status and message in result.stdout + result.stderr
    if stderr_only:
        assert result.stdout == ""
    assert tool.log("pvesh") == "" and tool.log("qm-order") == ""


def test_help_version_and_hidden_protocol(snapshot_env):
    tool, *_ = snapshot_env
    result = tool.run("--help")
    assert result.status == 0 and result.stderr == "" and "Commands:" in result.stdout
    assert "create" in result.stdout and "rollback" in result.stdout
    assert "--internal-preflight" not in result.stdout and "--expected-targets-file" not in result.stdout
    result = tool.run("create", "--help")
    assert "--include-memory" in result.stdout and "--start-after-rollback" not in result.stdout
    assert "--internal-action" not in result.stdout
    result = tool.run("--version")
    assert result.stdout.strip() == f"platform-proxmox-vm-snapshot {(ROOT / 'VERSION').read_text().strip()}" and result.stderr == ""


@pytest.mark.parametrize("selectors", [
    ("--vmid", "101", "--vm-name", "fixture-app"),
    ("--vmid", "101", "--environment", "dev"),
    ("--vm-name", "fixture-app", "--environment", "dev"),
])
def test_selector_pairs_rejected_before_discovery(snapshot_env, selectors):
    tool, *_ = snapshot_env
    result = tool.run("list", *selectors)
    assert result.status == 1 and "Exactly one" in result.stderr
    assert "CALL pvesh" not in tool.log("pvesh")


@pytest.mark.parametrize("option", [
    "--vmid", "--vm-name", "--environment", "--snapshot-name", "--description",
    "--ssh", "--identity-file", "--expected-targets-file",
])
def test_duplicate_scalar_options(snapshot_env, option):
    tool, *_ = snapshot_env
    result = tool.run("create", "--vmid", "101", "--snapshot-name", "valid-name", option, "first", option, "second")
    assert result.status == 1 and "may be specified only once" in result.stderr
    assert "CALL pvesh" not in tool.log("pvesh")


@pytest.mark.parametrize("option", ["--include-memory", "--dry-run", "--yes", "--internal-preflight", "--internal-action"])
def test_duplicate_boolean_options(snapshot_env, option):
    tool, *_ = snapshot_env
    result = tool.run("create", "--vmid", "101", "--snapshot-name", "valid-name", option, option)
    assert result.status == 1 and "may be specified only once" in result.stderr
    assert tool.log("pvesh") == "" and tool.log("qm-order") == ""


def test_duplicate_rollback_boolean_equals_and_help_precedence(snapshot_env):
    tool, *_ = snapshot_env
    result = tool.run("rollback", "--vmid", "101", "--snapshot-name", "valid-name", "--start-after-rollback", "--start-after-rollback")
    assert result.status == 1 and "may be specified only once" in result.stderr
    result = tool.run("list", "--vmid=101")
    assert result.status == 0 and "VMID 101" in result.stdout
    result = tool.run("create", "--vmid=101", "--vmid", "102", "--snapshot-name", "valid-name")
    assert result.status == 1 and "--vmid may be specified only once" in result.stderr
    result = tool.run("create", "--vmid", "101", "--snapshot-name", "valid-name", "--dry-run=true", "--dry-run")
    assert "invalid argument: true" in result.stderr and "specified only once" not in result.stderr
    result = tool.run("create", "--vmid", "101", "--help", "--unknown")
    assert result.status == 0 and "Create a temporary VM snapshot" in result.stdout
    for args, message in [
        (("create", "--unknown", "--help"), "invalid option"),
        (("create", "--vmid", "101", "--vmid", "102", "--help"), "specified only once"),
        (("create", "--vmid=", "--help"), "invalid option"),
    ]:
        result = tool.run(*args)
        assert result.status == 1 and message in result.stderr


def test_scalar_option_consumption_and_interspersed_help(snapshot_env):
    tool, *_ = snapshot_env
    result = tool.run("create", "--vmid", "101", "--snapshot-name", "option-value", "--description", "--include-memory", "--dry-run")
    assert result.status == 0 and "qm snapshot 101 option-value --description --include-memory" in result.stderr
    assert "--vmstate" not in result.stderr
    result = tool.run("create", "--description", "--yes", "--yes", "--help")
    assert result.status == 0 and "specified only once" not in result.stdout


@pytest.mark.parametrize("target", [
    "-oProxyCommand=touch-bad", "root@pve-a;touch bad", "root@$(touch bad)",
    "root@`touch bad`", "root@pve-a'quoted",
])
def test_hostile_ssh_rejected_before_execution(snapshot_env, target):
    tool, *_ = snapshot_env
    result = tool.run("create", "--ssh", target, "--vmid", "101", "--snapshot-name", "valid-name", "--yes")
    assert result.status == 1 and "--ssh must use user@host" in result.stderr and "CALL ssh" not in tool.log("ssh")


def test_identity_and_description_validation(snapshot_env, tmp_path):
    tool, *_ = snapshot_env
    result = tool.run("create", "--identity-file", os.fspath(tmp_path / "missing"), "--vmid", "101", "--snapshot-name", "valid-name", "--yes")
    assert result.status == 1 and "requires --ssh" in result.stderr
    result = tool.run("create", "--vmid", "101", "--snapshot-name", "valid-name", "--description", "one\ntwo", "--yes")
    assert result.status == 1 and "must not contain control characters" in result.stderr
    assert tool.log("pvesh") == "" and tool.log("qm-order") == ""


def test_list_selectors_order_and_template_exclusion(snapshot_env):
    tool, *_ = snapshot_env
    result = tool.run("list", "--vmid", "101")
    assert result.status == 0 and "VMID 101 (fixture-app) on pve-a" in result.stdout and "current state" in result.stdout
    assert tool.log("qm") == ""
    result = tool.run("list", "--vm-name", "fixture-db")
    assert result.status == 0 and "VMID 102" in result.stdout
    result = tool.run("list", "--vm-name", "fixture")
    assert result.status == 1 and "No VM has exact name" in result.stderr
    result = tool.run("list", "--environment", "dev")
    assert result.status == 0 and result.stdout.index("VMID 101") < result.stdout.index("VMID 102")
    assert "fixture-other" not in result.stdout and "fixture-template" not in result.stdout
    result = tool.run("list", "--environment", "Dev")
    assert result.status == 1 and "No non-template VMs" in result.stderr
    result = tool.run("list", "--vmid", "9000")
    assert result.status == 1 and "is a template" in result.stderr


@pytest.mark.parametrize("nodes", [[], [{"node": "pve-a"}, {"node": "pve-b"}], [{"node": "pve-a"}, {"node": "pve-a"}]])
def test_requires_exactly_one_node(snapshot_env, nodes):
    tool, state, *_ = snapshot_env
    tool.write_json("nodes.json", nodes)
    result = tool.run("list", "--vmid", "101")
    assert result.status == 1 and f"discovered: {len(nodes)}" in result.stderr


@pytest.mark.parametrize(
    ("relative", "contents", "args", "message"),
    [
        ("nodes.json", "{not-json\n", ("list", "--vmid", "101"), "Invalid JSON returned by pvesh node discovery"),
        ("inventory.json", "{not-json\n", ("list", "--vmid", "101"), "Invalid QEMU inventory JSON"),
        ("configs/101.json", "{not-json\n", ("list", "--vmid", "101"), "Invalid current config JSON"),
        ("status/101.json", "{}\n", ("create", "--vmid", "101", "--snapshot-name", "invalid-status", "--dry-run"), "Invalid current status JSON"),
        ("snapshots/101.json", "{not-json\n", ("list", "--vmid", "101"), "Invalid snapshot JSON"),
    ],
)
def test_invalid_discovery_json(snapshot_env, relative, contents, args, message):
    tool, state, *_ = snapshot_env
    (state / relative).write_text(contents)
    result = tool.run(*args)
    assert result.status == 1 and message in result.stderr and tool.log("qm") == ""


def test_duplicate_inventory_and_invalid_snapshot_shapes(snapshot_env):
    tool, state, *_ = snapshot_env
    inventory = tool.read_json("inventory.json")
    tool.write_json("inventory.json", inventory + [inventory[0]])
    result = tool.run("list", "--vmid", "101")
    assert result.status == 1 and "Invalid QEMU inventory JSON" in result.stderr
    for snapshots in [
        [{"description": "missing name"}, {"name": "current"}],
        [{"name": "duplicate"}, {"name": "duplicate"}, {"name": "current"}],
    ]:
        tool.create_state(); tool.write_json("snapshots/101.json", snapshots)
        result = tool.run("list", "--vmid", "101")
        assert result.status == 1 and "Invalid snapshot JSON" in result.stderr


def test_digest_lock_and_dry_run_preconditions(snapshot_env):
    tool, *_ = snapshot_env
    config = tool.read_json("configs/101.json"); config.pop("digest"); tool.write_json("configs/101.json", config)
    result = tool.run("create", "--vmid", "101", "--snapshot-name", "missing-digest", "--dry-run")
    assert result.status == 1 and "has no valid digest" in result.stderr and tool.log("qm") == ""
    for lock in ("snapshot", "backup"):
        tool.create_state(); config = tool.read_json("configs/101.json"); config["lock"] = lock; tool.write_json("configs/101.json", config)
        result = tool.run("create", "--vmid", "101", "--snapshot-name", "before-change", "--dry-run")
        assert result.status == 1 and f"has Proxmox lock '{lock}'" in result.stderr and tool.log("qm") == ""
    tool.create_state(); result = tool.run("create", "--vmid", "101", "--snapshot-name", "before-change", "--dry-run")
    assert result.status == 0 and "[PLAN] Would run:" in result.stderr and tool.log("qm") == ""


def test_create_interactive_memory_and_duplicate_preflight(snapshot_env):
    tool, *_ = snapshot_env
    result = tool.run("create", "--vmid", "101", "--snapshot-name", "before-change", "--yes")
    assert result.status == 0 and "succeeded" in result.stdout and "ARG=--vmstate" not in tool.log("qm")
    tool.create_state(); result = tool.run("create", "--vmid", "101", "--snapshot-name", "interactive-create", input="y\n", pty=True)
    assert result.status == 0 and "Create snapshot" in result.stdout
    tool.create_state(); result = tool.run("create", "--vmid", "101", "--snapshot-name", "memory-check", "--description", "Before app upgrade", "--include-memory", "--yes")
    assert result.status == 0 and "ARG=Before\\ app\\ upgrade" in tool.log("qm") and "ARG=--vmstate" in tool.log("qm")
    tool.create_state(); tool.checkpoint(102)
    result = tool.run("create", "--environment", "dev", "--snapshot-name", "before-change", "--yes")
    assert result.status == 1 and "already has snapshot" in result.stderr and tool.log("qm") == ""


def test_rollback_confirmations_postconditions_and_delete(snapshot_env):
    tool, *_ = snapshot_env
    tool.checkpoint(); result = tool.run("rollback", "--vmid", "101", "--snapshot-name", "before-change", "--start-after-rollback", "--yes")
    assert result.status == 0 and "ARG=--start" in tool.log("qm") and tool.read_json("status/101.json")["status"] == "running"
    tool.create_state(); tool.checkpoint(); result = tool.run("rollback", "--vmid", "101", "--snapshot-name", "before-change", input="101 before-change\n", pty=True)
    assert result.status == 0 and "ARG=--start" not in tool.log("qm") and tool.read_json("status/101.json")["status"] == "stopped"
    for command, confirmation, message in [("rollback", "wrong\n", "Confirmation did not match"), ("delete", "wrong\n", "Confirmation did not match; delete aborted")]:
        tool.create_state(); tool.checkpoint(); result = tool.run(command, "--vmid", "101", "--snapshot-name", "before-change", input=confirmation, pty=True)
        assert result.status == 1 and message in result.stdout + result.stderr and tool.log("qm") == ""
    for command in ("create", "rollback", "delete"):
        tool.create_state(); tool.checkpoint()
        name = "no-input" if command == "create" else "before-change"
        result = tool.run(command, "--vmid", "101", "--snapshot-name", name)
        assert result.status == 1 and "requires a TTY" in result.stderr and tool.log("qm") == ""
    tool.create_state(); tool.checkpoint(); result = tool.run("rollback", "--vmid", "101", "--snapshot-name", "before", "--yes")
    assert result.status == 1 and "does not have snapshot" in result.stderr and tool.log("qm-order") == ""
    for update, message in [({"FAKE_QM_SUPPRESS_STATUS_UPDATE": "1"}, "did not reach Proxmox state"), ({"FAKE_QM_NOOP_ROLLBACK": "1"}, "current snapshot parent is not")]:
        tool.create_state(); tool.checkpoint(); result = tool.run("rollback", "--vmid", "101", "--snapshot-name", "before-change", "--yes", update=update)
        assert result.status == 1 and message in result.stderr
        assert tool.log("qm-order") == "rollback:101\n"
    tool.create_state(); tool.checkpoint(); result = tool.run("delete", "--vmid", "101", "--snapshot-name", "before-change", "--yes")
    assert result.status == 0 and "ARG=delsnapshot" in tool.log("qm") and "ARG=--force" not in tool.log("qm")
    tool.create_state(); tool.checkpoint(); result = tool.run("delete", "--vmid", "101", "--snapshot-name", "before-change", input="101 before-change\n", pty=True)
    assert result.status == 0


def test_multi_target_preflight_partial_failure_and_order(snapshot_env):
    tool, *_ = snapshot_env
    tool.checkpoint(101)
    result = tool.run("rollback", "--environment", "dev", "--snapshot-name", "before-change", "--yes")
    assert result.status == 1 and "VMID 102 does not have snapshot" in result.stderr and tool.log("qm") == ""
    tool.create_state(); config = tool.read_json("configs/103.json"); config["tags"] = "managed-by-tofu;dev"; tool.write_json("configs/103.json", config)
    result = tool.run("create", "--environment", "dev", "--snapshot-name", "partial-check", "--yes", update={"FAKE_QM_FAIL_OPERATION": "snapshot", "FAKE_QM_FAIL_VMID": "102"})
    assert result.status == 1
    assert result.stdout.index("VMID 101 (fixture-app): succeeded") < result.stdout.index("VMID 102 (fixture-db): failed") < result.stdout.index("VMID 103 (fixture-other): not attempted")
    assert tool.log("qm-order") == "snapshot:101\nsnapshot:102\n"


@pytest.mark.parametrize("kind,message", [("rename-101", "Target set changed after preflight"), ("disk-101", "Config, status, lock, or snapshot state changed after preflight")])
def test_local_target_and_state_drift(snapshot_env, kind, message):
    tool, *_ = snapshot_env
    result = tool.run("create", "--vmid", "101", "--snapshot-name", "drift-check", "--yes", update={"FAKE_PVESH_DRIFT_AT": "2", "FAKE_PVESH_DRIFT_KIND": kind})
    assert result.status == 1 and message in result.stderr and tool.log("qm") == ""


def test_name_selector_must_be_unique(snapshot_env):
    tool, *_ = snapshot_env
    inventory = tool.read_json("inventory.json")
    next(item for item in inventory if item["vmid"] == 103)["name"] = "fixture-app"
    tool.write_json("inventory.json", inventory)
    config = tool.read_json("configs/103.json"); config["name"] = "fixture-app"; tool.write_json("configs/103.json", config)
    result = tool.run("list", "--vm-name", "fixture-app")
    assert result.status == 1 and "matching VMIDs: 101, 103" in result.stderr


def test_manifest_metadata_consumption_and_collision(snapshot_env):
    tool, _state, tmp_path = snapshot_env
    manifest = tmp_path / "expected-targets.json"
    for path in (tmp_path / "missing", tmp_path / "directory"):
        if path.name == "directory": path.mkdir()
        result = tool.run("create", "--vmid", "101", "--snapshot-name", "internal-check", "--yes", "--internal-action", "--expected-targets-file", os.fspath(path))
        assert result.status == 1 and "regular non-symlink file" in result.stderr
    manifest.write_text("{}\n"); manifest.chmod(0o600)
    link = tmp_path / "link"; link.symlink_to(manifest)
    result = tool.run("create", "--vmid", "101", "--snapshot-name", "internal-check", "--yes", "--internal-action", "--expected-targets-file", os.fspath(link))
    assert result.status == 1 and "regular non-symlink file" in result.stderr
    hardlink = tmp_path / "hardlink"; hardlink.hardlink_to(manifest)
    result = tool.run("create", "--vmid", "101", "--snapshot-name", "internal-check", "--yes", "--internal-action", "--expected-targets-file", os.fspath(manifest))
    assert result.status == 1 and "exactly one hard link" in result.stderr; hardlink.unlink()
    result = tool.run("create", "--vmid", "101", "--snapshot-name", "internal-check", "--yes", "--internal-action", "--expected-targets-file", os.fspath(manifest), update={"FAKE_STAT_TARGET": os.fspath(manifest), "FAKE_STAT_OWNER": str(os.geteuid() + 1)})
    assert result.status == 1 and "owned by the current user" in result.stderr
    for mode in (0o640, 0o604):
        manifest.chmod(mode); result = tool.run("create", "--vmid", "101", "--snapshot-name", "internal-check", "--yes", "--internal-action", "--expected-targets-file", os.fspath(manifest))
        assert result.status == 1 and "exact mode 600" in result.stderr
    manifest.chmod(0o600)
    consumed_dir = tmp_path / ".platform-proxmox-vm-snapshot-manifest"; consumed_dir.mkdir(mode=0o750)
    result = tool.run("create", "--vmid", "101", "--snapshot-name", "internal-check", "--yes", "--internal-action", "--expected-targets-file", os.fspath(manifest))
    assert result.status == 1 and "exact mode 700" in result.stderr and manifest.exists(); consumed_dir.rmdir()
    assert tool.log("qm") == "" and tool.log("qm-order") == ""
    for kind in ("file", "symlink"):
        result = tool.run("create", "--vmid", "101", "--snapshot-name", "internal-check", "--yes", "--internal-action", "--expected-targets-file", os.fspath(manifest), update={"FAKE_MV_SWAP_SOURCE": os.fspath(manifest), "FAKE_MV_SWAP_KIND": kind})
        assert result.status == 1 and "Could not inspect consumed" in result.stderr and manifest.is_file() and not manifest.is_symlink()
        assert tool.log("qm") == "" and tool.log("qm-order") == ""
    consumed_dir.mkdir(mode=0o700); collision = consumed_dir / "expected-targets.consumed"; collision.write_text("foreign collision\n")
    result = tool.run("create", "--vmid", "101", "--snapshot-name", "internal-check", "--yes", "--internal-action", "--expected-targets-file", os.fspath(manifest))
    assert result.status == 1 and "consumed-state path already exists" in result.stderr and collision.read_text() == "foreign collision\n"
    assert tool.log("qm") == "" and tool.log("qm-order") == ""


def test_manifest_requires_yes_malformed_is_consumed_and_signal_cleans(snapshot_env):
    tool, _state, tmp_path = snapshot_env
    manifest = tmp_path / "expected-targets.json"; manifest.write_text("{}\n"); manifest.chmod(0o600)
    result = tool.run("create", "--vmid", "101", "--snapshot-name", "internal-check", "--internal-action", "--expected-targets-file", os.fspath(manifest))
    assert result.status == 1 and "Internal action requires --yes" in result.stderr and manifest.exists()
    result = tool.run("create", "--vmid", "101", "--snapshot-name", "internal-check", "--yes", "--internal-action", "--expected-targets-file", os.fspath(manifest))
    assert result.status == 1 and "Invalid expected operation-state manifest" in result.stderr and not manifest.exists()
    tool.create_state(); tool.capture_manifest(manifest, "--vmid", "101", "--snapshot-name", "signal-cleanup")
    result = tool.run("create", "--vmid", "101", "--snapshot-name", "signal-cleanup", "--yes", "--internal-action", "--expected-targets-file", os.fspath(manifest), update={"FAKE_STAT_SIGNAL_DESCRIPTOR": "1"})
    assert result.status == 1 and not manifest.exists() and not (tmp_path / ".platform-proxmox-vm-snapshot-manifest").exists()
    assert tool.log("qm") == ""


@pytest.mark.parametrize(
    ("selector", "mutate", "message"),
    [
        (("--environment", "dev"), "add-target", "Target set changed after remote preflight"),
        (("--vmid", "101"), "rename", "Target set changed after remote preflight"),
        (("--vmid", "101"), "status", "Config, status, lock, or snapshot state changed after remote preflight"),
        (("--vmid", "101"), "config", "Config, status, lock, or snapshot state changed after remote preflight"),
        (("--vmid", "101"), "snapshot", "Config, status, lock, or snapshot state changed after remote preflight"),
    ],
)
def test_manifest_target_and_state_drift(snapshot_env, selector, mutate, message):
    tool, _state, tmp_path = snapshot_env
    manifest = tmp_path / "expected-targets.json"
    tool.capture_manifest(manifest, *selector, "--snapshot-name", "drift")
    if mutate == "add-target":
        config = tool.read_json("configs/103.json"); config["tags"] = "managed-by-tofu;dev"; tool.write_json("configs/103.json", config)
    elif mutate == "rename":
        config = tool.read_json("configs/101.json"); config["name"] = "fixture-app-renamed"; tool.write_json("configs/101.json", config)
    elif mutate == "status":
        status = tool.read_json("status/101.json"); status.update(status="stopped", qmpstatus="stopped"); tool.write_json("status/101.json", status)
    elif mutate == "config":
        config = tool.read_json("configs/101.json"); config.update(scsi0="fixture-storage:changed", digest="4" * 40); tool.write_json("configs/101.json", config)
    else:
        tool.checkpoint()
    result = tool.run("create", *selector, "--snapshot-name", "drift", "--yes", "--internal-action", "--expected-targets-file", os.fspath(manifest))
    assert result.status == 1 and message in result.stderr and tool.log("qm") == ""


def test_manifest_replay_fd_closure_and_serial_drift(snapshot_env):
    tool, _state, tmp_path = snapshot_env
    manifest = tmp_path / "expected-targets.json"
    tool.capture_manifest(manifest, "--vmid", "101", "--snapshot-name", "replay-check")
    args = ("create", "--vmid", "101", "--snapshot-name", "replay-check", "--yes", "--internal-action", "--expected-targets-file", os.fspath(manifest))
    result = tool.run(*args, update={"FAKE_FORBID_CONSUMED_MANIFEST_FD": "1"})
    assert result.status == 0 and not manifest.exists()
    result = tool.run(*args)
    assert result.status == 1 and "regular non-symlink file" in result.stderr and tool.log("qm-order") == "snapshot:101\n"
    for kind, message in [("rename-102", "target set changed before mutation"), ("lock-102", "operation state changed before mutation")]:
        tool.create_state(); result = tool.run("create", "--environment", "dev", "--snapshot-name", "serial-drift", "--yes", update={"FAKE_PVESH_DRIFT_AT": "4", "FAKE_PVESH_DRIFT_KIND": kind})
        assert result.status == 1 and "VMID 101 (fixture-app): succeeded" in result.stdout and message in result.stdout
        assert tool.log("qm-order") == "snapshot:101\n"


def test_self_streamed_ssh_remote_drift_list_and_large_transport(snapshot_env):
    tool, state, tmp_path = snapshot_env
    identity = tmp_path / "id_ed25519"; identity.write_text("synthetic identity\n"); identity.chmod(0o600)
    result = tool.run("create", "--ssh", "root@pve-a", "--identity-file", os.fspath(identity), "--vmid", "101", "--snapshot-name", "remote-check", "--description", "Remote description; still one argument", "--yes")
    assert result.status == 0 and "succeeded" in result.stdout
    assert "ARG=-i" in tool.log("ssh") and "ARG=IdentitiesOnly=yes" in tool.log("ssh")
    assert "fixture-storage" not in tool.log("ssh") and "ARG=Remote\\ description\\;\\ still\\ one\\ argument" in tool.log("qm")
    assert tool.log("qm-order") == "snapshot:101\n"
    tool.create_state(); result = tool.run("create", "--ssh", "root@pve-a", "--vmid", "101", "--snapshot-name", "remote-drift", "--yes", update={"FAKE_PVESH_DRIFT_AT": "2", "FAKE_PVESH_DRIFT_KIND": "rename-101"})
    assert result.status == 1 and "Target set changed after remote preflight" in result.stderr and tool.log("qm") == ""
    tool.create_state(); result = tool.run("list", "--ssh", "root@pve-a", "--environment", "dev")
    assert result.status == 0 and "VMID 101" in result.stdout and "VMID 102" in result.stdout
    tool.create_state(); tool.write_json("snapshots/101.json", [{"name": "history", "description": "x" * 140000, "snaptime": 1700004000, "vmstate": 0}, {"name": "current", "parent": "history"}])
    result = tool.run("create", "--ssh", "root@pve-a", "--vmid", "101", "--snapshot-name", "large-transport", "--yes", update={"FAKE_FORBID_CONSUMED_MANIFEST_FD": "1"})
    assert result.status == 0 and "succeeded" in result.stdout and "x" * 32 not in tool.log("ssh")
    assert tool.log("qm-order") == "snapshot:101\n"
