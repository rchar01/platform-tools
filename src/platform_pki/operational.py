"""Shared operational-state checks for read-oriented PKI commands."""

from __future__ import annotations

import errno
import os
import re
import shutil
import sys
from collections.abc import Mapping
from pathlib import Path

from .errors import ApplicationError
from .filesystem import (
    ABSENT,
    DirectoryPolicy,
    FilePolicy,
    FilesystemError,
    OpenedDirectory,
    OpenedFile,
)
from .inventory import Inventory, InventoryError, parse_inventory
from .paths import PkiPaths, resolve_pki_paths
from .records import RecordError, RecordSpec
from .subprocesses import ProcessResult, run_process


_SERVICE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*", re.ASCII)
_ROOT_GENERATION = re.compile(r"g[1-9][0-9]*", re.ASCII)
_INTERMEDIATE_GENERATION = re.compile(r"g[1-9][0-9]*-i[1-9][0-9]*", re.ASCII)
_PAIR_SPEC = RecordSpec(("root", "intermediate"))
_PROCESS_TIMEOUT = 30.0
_PROCESS_GRACE = 1.0
_PROCESS_STDOUT_LIMIT = 4 * 1024 * 1024
_PROCESS_STDERR_LIMIT = 1024 * 1024


def require_pilot_common_library(environment: Mapping[str, str]) -> None:
    """Preserve the pilot commands' operational installed-asset boundary."""

    explicit = environment.get("PLATFORM_TOOLS_LIB_DIR", "")
    if explicit:
        candidate = Path(explicit) / "platform-pki-common.sh"
    else:
        invocation = Path(sys.argv[0])
        try:
            adjacent = invocation.parent.resolve(strict=True).parent / "lib/platform-pki-common.sh"
        except OSError:
            adjacent = invocation.parent / "../lib/platform-pki-common.sh"
        if os.access(adjacent, os.R_OK):
            candidate = adjacent
        else:
            share = environment.get("PLATFORM_TOOLS_SHARE_DIR", "")
            if not share:
                data_home = environment.get("XDG_DATA_HOME", "")
                if not data_home:
                    home = environment.get("HOME", "")
                    data_home = f"{home}/.local/share"
                share = f"{data_home}/platform-tools"
            candidate = Path(share) / "lib/platform-pki-common.sh"
    try:
        with OpenedFile(candidate, policy=FilePolicy(links=1)):
            pass
    except FilesystemError:
        raise ApplicationError("platform-pki-common.sh not found")


def validate_service_name(service: str) -> None:
    if _SERVICE_NAME.fullmatch(service) is None:
        raise ApplicationError(f"Invalid service name: {service}")


def resolve_paths(values: Mapping[str, object], environment: Mapping[str, str]) -> PkiPaths:
    try:
        physical_cwd = os.getcwd()
    except OSError:
        raise ApplicationError("Current directory could not be resolved") from None
    home = environment.get("HOME")
    if home is None:
        raise ApplicationError("HOME is required")
    return resolve_pki_paths(
        namespace=values.get("--namespace"),
        pki_dir=values.get("--pki-dir"),
        home=home,
        xdg_config_home=environment.get("XDG_CONFIG_HOME"),
        physical_cwd=physical_cwd,
    )


def require_program(name: str, environment: Mapping[str, str]) -> None:
    if shutil.which(name, path=environment.get("PATH")) is None:
        raise ApplicationError(f"{name} is required")


def _ensure_private_child(parent: OpenedDirectory, name: str) -> OpenedDirectory:
    identity = parent.identity_at(name)
    if identity is ABSENT:
        created = False
        try:
            os.mkdir(name, 0o700, dir_fd=parent.fileno())
            created = True
        except OSError as error:
            if error.errno != errno.EEXIST:
                raise ApplicationError("PKI control directory could not be prepared") from None
        child = parent.open_directory(name)
        try:
            if created:
                os.fchmod(child.fileno(), 0o700)
            DirectoryPolicy(owner=os.geteuid(), mode=0o700).validate(child.recheck())
        except BaseException:
            child.close()
            raise
        return child
    return parent.open_directory(
        name,
        policy=DirectoryPolicy(owner=os.geteuid(), mode=0o700),
    )


def prepare_control_state(pki_dir: str) -> None:
    """Create only the Bash-compatible private control directories."""

    try:
        pki = OpenedDirectory(
            pki_dir, policy=DirectoryPolicy(owner=os.geteuid(), mode=0o700)
        )
        try:
            for name in ("locks", "state"):
                child = _ensure_private_child(pki, name)
                child.close()
            state = pki.open_directory(
                "state", policy=DirectoryPolicy(owner=os.geteuid(), mode=0o700)
            )
            try:
                for name in ("rollover", "rollovers", "generation-reservations"):
                    child = _ensure_private_child(state, name)
                    child.close()
            finally:
                state.close()
        finally:
            pki.close()
    except FilesystemError:
        raise ApplicationError("PKI directory does not satisfy its private path policy") from None


def require_pki_directory(pki_dir: str) -> None:
    if not os.path.isdir(pki_dir):
        raise ApplicationError(
            f"PKI directory does not exist; run platform-pki-init first: {pki_dir}"
        )


def require_inventory_readable(pki_dir: str) -> str:
    path = f"{pki_dir}/inventory/services.yml"
    if not os.access(path, os.R_OK):
        raise ApplicationError(
            f"Service inventory is missing or unreadable: {path}; "
            "run platform-pki-inventory-install"
        )
    return path


def _read_pair(path: str) -> tuple[str, str]:
    record = None
    try:
        with OpenedFile(
            path,
            policy=FilePolicy(owner=os.geteuid(), mode=0o600, links=1, max_size=4096),
        ) as opened:
            record = _PAIR_SPEC.parse(opened.read(opened.identity.size))
    except (FilesystemError, RecordError):
        raise ApplicationError("PKI issuer state is invalid") from None
    assert record is not None
    root = record["root"]
    intermediate = record["intermediate"]
    if (
        _ROOT_GENERATION.fullmatch(root) is None
        or _INTERMEDIATE_GENERATION.fullmatch(intermediate) is None
        or not intermediate.startswith(f"{root}-i")
    ):
        raise ApplicationError("PKI issuer state is invalid")
    return root, intermediate


def _directory_entries(path: str) -> tuple[str, ...]:
    try:
        with os.scandir(path) as entries:
            return tuple(entry.name for entry in entries)
    except FileNotFoundError:
        return ()
    except OSError:
        raise ApplicationError("PKI authority layout could not be inspected") from None


def require_generation_layout(pki_dir: str) -> None:
    active = f"{pki_dir}/state/active-issuer"
    bootstrap = f"{pki_dir}/state/bootstrap-root"
    roots = f"{pki_dir}/authorities/roots"
    intermediates = f"{pki_dir}/authorities/intermediates"
    legacy_root = f"{pki_dir}/root-ca"
    legacy_intermediate = f"{pki_dir}/intermediate-ca"

    legacy = os.path.isdir(legacy_root) and not os.path.islink(legacy_root)
    legacy = legacy and os.path.isdir(legacy_intermediate) and not os.path.islink(
        legacy_intermediate
    )
    indicators = (
        os.path.lexists(active)
        or os.path.lexists(bootstrap)
        or bool(_directory_entries(roots))
        or bool(_directory_entries(intermediates))
    )
    generation = False
    if os.path.isfile(active) and not os.path.islink(active):
        try:
            root, intermediate = _read_pair(active)
        except ApplicationError:
            root = intermediate = ""
        generation = bool(root) and all(
            os.path.isdir(path) and not os.path.islink(path)
            for path in (
                f"{roots}/{root}",
                f"{intermediates}/{intermediate}",
            )
        )

    if generation and not os.path.lexists(legacy_root) and not os.path.lexists(
        legacy_intermediate
    ):
        return
    if legacy and not indicators:
        raise ApplicationError(
            "Legacy PKI state requires migration; create a fresh backup and follow "
            "platform-pki-ca-rollover status/migrate"
        )
    if not legacy and not indicators and not os.path.lexists(legacy_root) and not os.path.lexists(
        legacy_intermediate
    ):
        raise ApplicationError(
            "Generation-aware PKI state does not exist; create the root and "
            "intermediate authorities first"
        )
    raise ApplicationError(
        "PKI state is incomplete or ambiguous; run platform-pki-ca-rollover status"
    )


def _read_state_map(path: str, label: str) -> dict[str, str]:
    data = b""
    try:
        with OpenedFile(
            path,
            policy=FilePolicy(owner=os.geteuid(), mode=0o600, links=1, max_size=1024 * 1024),
        ) as opened:
            data = opened.read(opened.identity.size)
    except FilesystemError:
        raise ApplicationError(f"{label} is unsafe: {path}") from None
    values: dict[str, str] = {}
    lines = data.split(b"\n")
    if lines[-1] == b"":
        lines.pop()
    for raw_line in lines:
        if b"=" not in raw_line:
            raise ApplicationError(f"{label} has invalid content")
        raw_key, raw_value = raw_line.split(b"=", 1)
        if any(byte < 32 or byte == 127 for byte in raw_value):
            raise ApplicationError(f"{label} has invalid content")
        try:
            key = raw_key.decode("ascii")
            value = raw_value.decode("ascii")
        except UnicodeDecodeError:
            raise ApplicationError(f"{label} has invalid content") from None
        if not re.fullmatch(r"[a-z0-9_]+", key, re.ASCII):
            raise ApplicationError(f"{label} has invalid content")
        if key in values:
            raise ApplicationError(f"{label} contains duplicate field: {key}")
        values[key] = value
    return values


def require_no_unresolved_state(pki_dir: str) -> None:
    finalization = f"{pki_dir}/state/csr/finalization-recovery-journal"
    signing = f"{pki_dir}/state/csr/recovery-journal"
    marker = f"{pki_dir}/state/rollover/recovery-required"
    journal = f"{pki_dir}/state/rollover/journal"
    if os.path.lexists(finalization):
        state = _read_state_map(
            finalization, "CSR candidate finalization recovery journal"
        )
        if state.get("operation") != "csr-finalize":
            raise ApplicationError(
                "Unsupported CSR finalization recovery state blocks this command: "
                f"{finalization}"
            )
        raise ApplicationError(
            "CSR candidate finalization recovery is required before this command "
            f"can continue: {finalization}"
        )
    if os.path.lexists(signing):
        state = _read_state_map(signing, "Authenticated CSR signing recovery journal")
        if state.get("operation") == "csr-sign":
            raise ApplicationError(
                "Authenticated CSR signing recovery is required before this command "
                f"can continue: {signing}"
            )
        raise ApplicationError(
            f"Unsupported CSR recovery state blocks this command: {signing}"
        )
    if os.path.lexists(marker):
        try:
            with OpenedFile(
                marker,
                policy=FilePolicy(owner=os.geteuid(), mode=0o600, links=1),
            ):
                pass
        except FilesystemError:
            raise ApplicationError(f"PKI recovery marker is unsafe: {marker}") from None
        raise ApplicationError(
            f"PKI recovery is required before this command can continue: {marker}"
        )
    if os.path.lexists(journal):
        state = _read_state_map(journal, "PKI recovery journal")
        if (
            state.get("operation") == "rollover-prepare"
            or state.get("committed") != "true"
        ):
            raise ApplicationError(
                f"PKI recovery is required before this command can continue: {journal}"
            )


def run_external(argv: tuple[str, ...], environment: Mapping[str, str]) -> ProcessResult:
    result = run_process(
        argv,
        env=environment,
        timeout=_PROCESS_TIMEOUT,
        term_grace=_PROCESS_GRACE,
        stdout_limit=_PROCESS_STDOUT_LIMIT,
        stderr_limit=_PROCESS_STDERR_LIMIT,
    )
    assert isinstance(result, ProcessResult)
    return result


def load_active_issuer(pki_dir: str, environment: Mapping[str, str]) -> tuple[str, str]:
    require_no_unresolved_state(pki_dir)
    root, intermediate = _read_pair(f"{pki_dir}/state/active-issuer")
    for path in (
        f"{pki_dir}/authorities/roots/{root}",
        f"{pki_dir}/authorities/intermediates/{intermediate}",
    ):
        try:
            with OpenedDirectory(
                path, policy=DirectoryPolicy(owner=os.geteuid(), mode=0o700)
            ):
                pass
        except FilesystemError:
            raise ApplicationError("PKI active authority state is invalid") from None
    result = run_external(
        (
            "openssl",
            "verify",
            "-CAfile",
            f"{pki_dir}/authorities/roots/{root}/certs/root-ca.crt",
            f"{pki_dir}/authorities/intermediates/{intermediate}/certs/intermediate-ca.crt",
        ),
        environment,
    )
    sys.stderr.buffer.write(result.stderr)
    sys.stderr.buffer.flush()
    if result.status:
        raise ApplicationError("Active intermediate does not verify against its recorded root")
    return root, intermediate


def load_inventory(path: str) -> Inventory:
    data = b""
    try:
        with OpenedFile(
            path,
            policy=FilePolicy(
                owner=os.geteuid(), forbidden_bits=0o022, links=1
            ),
        ) as opened:
            data = opened.read(opened.identity.size)
        return parse_inventory(data)
    except InventoryError as error:
        raise ApplicationError(str(error)) from None
    except FilesystemError:
        raise ApplicationError("Service inventory could not be read safely") from None


def require_service(inventory: Inventory, service: str, inventory_path: str) -> None:
    if not any(entry.name == service for entry in inventory.services):
        raise ApplicationError(
            f"Service is not defined in {inventory_path}: {service}"
        )
