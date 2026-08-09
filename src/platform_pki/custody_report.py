"""Read-only PKI custody and backup-policy reporting."""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import sys
from dataclasses import asdict, dataclass
from typing import Literal, Mapping

from .errors import ApplicationError
from .filesystem import (
    DirectoryPolicy,
    FileIdentity,
    FilePolicy,
    FilesystemError,
    FilesystemIdentityError,
    FilesystemReadLimitError,
    FilesystemTraversalError,
    MetadataEntry,
    OpenedDirectory,
    OpenedFile,
    open_descendant_file,
    walk_metadata,
)
from .operational import (
    acquire_operational_locks,
    detect_layout,
    prepare_control_state,
    require_no_unresolved_state,
    require_pilot_common_library,
    require_pki_directory,
    resolve_paths,
)
from .parser import ParseResult
from .subprocesses import ProcessResult, run_process


_ROOT_GENERATION = re.compile(r"g[1-9][0-9]*", re.ASCII)
_INTERMEDIATE_GENERATION = re.compile(r"g[1-9][0-9]*-i[1-9][0-9]*", re.ASCII)
_SERVICE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*", re.ASCII)
_BACKUP_NAME = re.compile(
    r"platform-pki-([0-9]{8}-[0-9]{6})(-[0-9]+)?\.tar\.gz(\.age)?",
    re.ASCII,
)
_RECORD_LINE = re.compile(rb"([a-z0-9_]+)=([^\x00-\x1f\x7f]*)")
_LOWER_HEX_32 = re.compile(rb"[0-9a-f]{32}")
_LOWER_HEX_64 = re.compile(rb"[0-9a-f]{64}")
_DECIMAL = re.compile(rb"[0-9]+")
_OCTAL = re.compile(rb"[0-7]+")
_TIMESTAMP = re.compile(rb"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_RECEIPT_FIELDS = (
    b"schema",
    b"layout",
    b"session",
    b"backup_path",
    b"backup_device",
    b"backup_inode",
    b"backup_size",
    b"backup_mode",
    b"backup_owner",
    b"archive_sha256",
    b"created_at",
    b"created_epoch",
    b"state_manifest_sha256",
    b"private_metadata_sha256",
)
_OPERATIONAL_CHECKS = (
    "ca_key_cryptographic_validation",
    "backup_decryption_validation",
    "backup_archive_digest_validation",
    "offline_ca_custody",
    "backup_recipient_separation",
    "offsite_backup_copy",
    "isolated_restore_rehearsal",
    "target_host_leaf_custody",
)
_UID = os.geteuid()
_PRIVATE_DIRECTORY = DirectoryPolicy(owner=_UID, mode=0o700)
_PRIVATE_FILE = FilePolicy(owner=_UID, forbidden_bits=0o077, links=1)
_RECEIPT_FILE = FilePolicy(owner=_UID, mode=0o600, links=1)


@dataclass(frozen=True, slots=True)
class Material:
    id: str
    role: str
    encryption_evidence: str
    recommended_custody: str
    backup_policy: str
    status: str


@dataclass(frozen=True, slots=True)
class Finding:
    severity: str
    code: str
    material: str
    action: str


class Report:
    def __init__(self, pki_dir: str, root: OpenedDirectory) -> None:
        self.pki_dir = pki_dir
        self.root = root
        self.materials: list[Material] = []
        self.findings: list[Finding] = []
        self.expected_keys: set[tuple[str, ...]] = set()

    def add_material(
        self,
        material_id: str,
        role: str,
        encryption: str,
        custody: str,
        backup: str,
        status: str,
    ) -> None:
        self.materials.append(Material(material_id, role, encryption, custody, backup, status))

    def add_finding(self, severity: str, code: str, material: str, action: str) -> None:
        self.findings.append(Finding(severity, code, material, action))


def _path(pki_dir: str, components: tuple[str, ...]) -> str:
    return os.path.join(pki_dir, *components)


def _lexists(path: str) -> bool:
    return os.path.lexists(path)


def _private_ancestry_is_safe(pki_dir: str, components: tuple[str, ...]) -> bool:
    current = pki_dir
    try:
        root = os.lstat(current)
        if not stat.S_ISDIR(root.st_mode) or stat.S_ISLNK(root.st_mode):
            return False
        if root.st_uid != _UID or stat.S_IMODE(root.st_mode) != 0o700:
            return False
        for component in components[:-1]:
            current = os.path.join(current, component)
            result = os.lstat(current)
            if not stat.S_ISDIR(result.st_mode) or stat.S_ISLNK(result.st_mode):
                return False
            if result.st_uid != _UID or stat.S_IMODE(result.st_mode) != 0o700:
                return False
    except OSError:
        return False
    return True


def _safe_regular_metadata(pki_dir: str, components: tuple[str, ...], *, receipt: bool = False) -> bool:
    if not _private_ancestry_is_safe(pki_dir, components):
        return False
    try:
        result = os.lstat(_path(pki_dir, components))
    except OSError:
        return False
    permissions = stat.S_IMODE(result.st_mode)
    return (
        stat.S_ISREG(result.st_mode)
        and not stat.S_ISLNK(result.st_mode)
        and result.st_uid == _UID
        and result.st_nlink == 1
        and (permissions == 0o600 if receipt else permissions & 0o077 == 0)
    )


def _open_private_file(
    report: Report,
    components: tuple[str, ...],
    label: str,
    *,
    receipt: bool = False,
    expected: FileIdentity | None = None,
) -> OpenedFile:
    try:
        return open_descendant_file(
            report.root,
            components,
            directory_policy=_PRIVATE_DIRECTORY,
            file_policy=_RECEIPT_FILE if receipt else _PRIVATE_FILE,
            expected_identity=expected,
        )
    except FilesystemIdentityError:
        raise ApplicationError(f"{label} identity changed while opening") from None
    except FilesystemError:
        raise ApplicationError(f"Cannot inspect {label}") from None


def _classify_first_line(opened: OpenedFile, kind: Literal["key", "age"], label: str) -> str:
    try:
        prefix = opened.read_prefix(257)
    except FilesystemIdentityError:
        raise ApplicationError(f"{label} changed while reading its first line") from None
    except FilesystemError:
        raise ApplicationError(f"Cannot perform bounded {label} header inspection") from None

    line = bytearray()
    for byte in prefix:
        if byte == 10:
            break
        if byte == 0:
            return "nul-header"
        line.append(byte)
    if len(line) > 256:
        return "overlong-header"
    value = bytes(line)
    if kind == "key" and value == b"-----BEGIN ENCRYPTED " b"PRIVATE KEY-----":
        return "encrypted-pkcs8-header"
    if kind == "key" and value == b"-----BEGIN " b"PRIVATE KEY-----":
        return "plaintext-pkcs8-header"
    if kind == "age" and value == b"age-encryption.org/v1":
        return "age-v1-header"
    return "unknown" if value else "unreadable"


def _inspect_key(
    report: Report,
    material_id: str,
    role: str,
    components: tuple[str, ...],
    custody: str,
    backup: str,
    presence_severity: str = "",
    presence_code: str = "",
    presence_action: str = "",
) -> None:
    report.expected_keys.add(components)
    path = _path(report.pki_dir, components)
    if not _lexists(path):
        report.add_material(material_id, role, "absent", custody, backup, "missing")
        if role in ("root-authority", "intermediate-authority"):
            report.add_finding("high", "missing-ca-key", material_id, "restore-or-repair-authority")
        return

    encryption = "unknown"
    status = "review"
    if not _safe_regular_metadata(report.pki_dir, components):
        status = "finding"
        report.add_finding(
            "high", "unsafe-private-key", material_id, "repair-owner-mode-type-and-links"
        )
    else:
        with _open_private_file(report, components, "private key") as opened:
            encryption = _classify_first_line(opened, "key", "private key")
        if encryption == "overlong-header":
            status = "finding"
            report.add_finding(
                "high", "oversized-private-key-header", material_id, "quarantine-and-review-key-file"
            )
        elif encryption == "nul-header":
            status = "finding"
            report.add_finding(
                "high", "binary-private-key-header", material_id, "quarantine-and-review-key-file"
            )

    if role in ("root-authority", "intermediate-authority"):
        if encryption != "encrypted-pkcs8-header":
            status = "finding"
            report.add_finding(
                "high",
                "ca-key-encryption-header-missing",
                material_id,
                "review-key-envelope-and-approved-remediation",
            )
    elif role in ("controller-leaf-key", "ansible-export-key"):
        status = "finding"
        report.add_finding(presence_severity, presence_code, material_id, presence_action)
    report.add_material(material_id, role, encryption, custody, backup, status)


def _parse_receipt(data: bytes) -> dict[bytes, bytes] | None:
    if any(byte < 32 and byte != 10 or byte == 127 for byte in data):
        return None
    values: dict[bytes, bytes] = {}
    text = data.rstrip(b"\n")
    for line in text.split(b"\n"):
        match = _RECORD_LINE.fullmatch(line)
        if match is None or match.group(1) in values:
            return None
        values[match.group(1)] = match.group(2)
    if len(values) != 14 or set(values) != set(_RECEIPT_FIELDS):
        return None
    if any(not values[key] for key in _RECEIPT_FIELDS):
        return None
    return values


def _receipt_matches_archive(
    report: Report,
    receipt_components: tuple[str, ...],
    archive_components: tuple[str, ...],
    archive_identity: FileIdentity,
) -> bool:
    data = b""
    try:
        with _open_private_file(
            report, archive_components, "backup archive", expected=archive_identity
        ):
            pass
        with _open_private_file(report, receipt_components, "backup receipt", receipt=True) as receipt:
            try:
                data = receipt.read(65536)
            except FilesystemReadLimitError:
                return False
            except FilesystemIdentityError:
                raise ApplicationError("backup receipt changed while reading") from None
            except FilesystemError:
                return False
        values = _parse_receipt(data)
        if values is None:
            return False
        if values[b"schema"] != b"2" or values[b"layout"] not in (b"legacy", b"generation"):
            return False
        if _LOWER_HEX_32.fullmatch(values[b"session"]) is None:
            return False
        if values[b"backup_path"] != os.fsencode(_path(report.pki_dir, archive_components)):
            return False
        for key in (b"backup_device", b"backup_inode", b"backup_size", b"backup_owner", b"created_epoch"):
            if _DECIMAL.fullmatch(values[key]) is None:
                return False
        if _OCTAL.fullmatch(values[b"backup_mode"]) is None:
            return False
        for key in (b"archive_sha256", b"state_manifest_sha256", b"private_metadata_sha256"):
            if _LOWER_HEX_64.fullmatch(values[key]) is None:
                return False
        if _TIMESTAMP.fullmatch(values[b"created_at"]) is None:
            return False
        identity = b":".join(
            (
                str(archive_identity.dev).encode(),
                str(archive_identity.ino).encode(),
                str(archive_identity.size).encode(),
                f"{archive_identity.permissions:o}".encode(),
                str(archive_identity.uid).encode(),
            )
        )
        recorded = b":".join(
            values[key]
            for key in (b"backup_device", b"backup_inode", b"backup_size", b"backup_mode", b"backup_owner")
        )
        if recorded != identity:
            return False
        with _open_private_file(
            report, archive_components, "backup archive", expected=archive_identity
        ):
            pass
        return True
    except ApplicationError as error:
        if (
            "identity changed" in error.message
            or error.message == "backup receipt changed while reading"
        ):
            raise
        return False


def _backup_entries(path: str) -> tuple[str, ...]:
    try:
        names = os.listdir(path)
    except OSError:
        raise ApplicationError(f"PKI backup directory must be a non-symlink directory: {path}") from None
    visible = sorted((name for name in names if not name.startswith(".")), key=os.fsencode)
    one_dot = sorted(
        (name for name in names if name.startswith(".") and not name.startswith("..")),
        key=os.fsencode,
    )
    two_dot = sorted((name for name in names if name.startswith("..")), key=os.fsencode)
    return tuple((*visible, *one_dot, *two_dot))


def _inspect_backups(report: Report) -> None:
    backup_components = ("backups",)
    backup_dir = _path(report.pki_dir, backup_components)
    if not _lexists(backup_dir):
        return
    try:
        result = os.lstat(backup_dir)
    except OSError:
        raise ApplicationError(f"PKI backup directory must be a non-symlink directory: {backup_dir}") from None
    if not stat.S_ISDIR(result.st_mode) or stat.S_ISLNK(result.st_mode):
        raise ApplicationError(f"PKI backup directory must be a non-symlink directory: {backup_dir}")

    entries = _backup_entries(backup_dir)
    expected_receipts: set[str] = set()
    counter = 0
    for name in entries:
        if name.endswith(".receipt"):
            continue
        counter += 1
        components = (*backup_components, name)
        match = _BACKUP_NAME.fullmatch(name)
        if match is None:
            material_id = f"backup:unknown-{counter}"
        else:
            kind = "age" if match.group(3) else "plain"
            material_id = f"backup:{match.group(1)}{match.group(2) or ''}:{kind}"

        encryption = "unknown"
        status = "finding"
        archive_identity: FileIdentity | None = None
        if not _safe_regular_metadata(report.pki_dir, components):
            report.add_finding(
                "high", "unsafe-backup", material_id, "repair-owner-mode-type-and-links"
            )
        elif name.endswith(".tar.gz.age"):
            with _open_private_file(report, components, "age backup") as opened:
                encryption = _classify_first_line(opened, "age", "age backup")
                archive_identity = opened.identity
            if encryption == "age-v1-header":
                status = "review"
            elif encryption == "overlong-header":
                report.add_finding(
                    "high", "oversized-backup-header", material_id, "quarantine-and-review-backup"
                )
            elif encryption == "nul-header":
                report.add_finding(
                    "high", "binary-backup-header", material_id, "quarantine-and-review-backup"
                )
            else:
                report.add_finding(
                    "high", "invalid-age-backup", material_id, "replace-with-verified-age-backup"
                )
        else:
            with _open_private_file(report, components, "backup archive") as opened:
                archive_identity = opened.identity
            if name.endswith(".tar.gz"):
                encryption = "plaintext-archive-name"
                report.add_finding(
                    "high", "plaintext-backup", material_id, "replace-with-age-encrypted-backup"
                )
            else:
                report.add_finding(
                    "high",
                    "unknown-backup-format",
                    material_id,
                    "review-and-quarantine-unknown-backup",
                )
        report.add_material(
            material_id,
            "pki-backup",
            encryption,
            "offline-offsite",
            "encrypted-and-restore-tested",
            status,
        )

        receipt_name = f"{name}.receipt"
        expected_receipts.add(receipt_name)
        receipt_components = (*backup_components, receipt_name)
        receipt_path = _path(report.pki_dir, receipt_components)
        if not _lexists(receipt_path):
            report.add_finding(
                "medium", "missing-backup-receipt", material_id, "create-a-fresh-receipt-bound-backup"
            )
        elif not _safe_regular_metadata(report.pki_dir, receipt_components, receipt=True):
            report.add_finding(
                "high", "unsafe-backup-receipt", material_id, "repair-or-replace-receipt-bound-backup"
            )
        elif archive_identity is None or not _receipt_matches_archive(
            report, receipt_components, components, archive_identity
        ):
            report.add_finding(
                "high", "invalid-backup-receipt", material_id, "create-a-fresh-receipt-bound-backup"
            )

    orphan_count = sum(
        name.endswith(".receipt") and name not in expected_receipts for name in entries
    )
    if orphan_count:
        report.add_finding(
            "medium",
            f"orphan-backup-receipt-count:{orphan_count}",
            "backups",
            "review-or-remove-orphan-receipts",
        )


def _unsafe_metadata(entry: MetadataEntry) -> bool:
    if entry.uid != _UID:
        return True
    if entry.kind == "directory":
        return entry.permissions != 0o700
    if entry.kind == "regular":
        return entry.links != 1 or bool(entry.permissions & 0o022)
    return True


def _scan_managed_metadata(report: Report) -> None:
    try:
        count = sum(_unsafe_metadata(entry) for entry in walk_metadata(report.root, xdev=True))
    except FilesystemTraversalError:
        raise ApplicationError("Cannot enumerate complete managed PKI metadata") from None
    if count:
        report.add_material(
            "unsafe-managed-paths",
            "filesystem-metadata",
            "unknown",
            "repair-in-place",
            "no-independent-backup",
            "finding",
        )
        report.add_finding(
            "high",
            f"unsafe-managed-path-count:{count}",
            "unsafe-managed-paths",
            "inspect-owner-mode-type-and-links",
        )


def _scan_unexpected_keys(report: Report) -> None:
    try:
        count = sum(
            entry.kind in ("regular", "symlink")
            and bool(entry.relative)
            and entry.relative[-1].endswith(".key")
            and entry.relative not in report.expected_keys
            for entry in walk_metadata(report.root, xdev=True)
        )
    except FilesystemTraversalError:
        raise ApplicationError("Cannot enumerate complete managed private-key paths") from None
    if count:
        report.add_material(
            "unexpected-keys",
            "unclassified-private-key",
            "unknown",
            "restricted-quarantine",
            "review-before-retention",
            "finding",
        )
        report.add_finding(
            "high",
            f"unexpected-private-key-count:{count}",
            "unexpected-keys",
            "inspect-without-copying-or-printing-content",
        )


def _visible_entries(path: str) -> tuple[str, ...]:
    try:
        return tuple(sorted((name for name in os.listdir(path) if not name.startswith(".")), key=os.fsencode))
    except OSError:
        return ()


def _real_directory(path: str) -> bool:
    try:
        result = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISDIR(result.st_mode) and not stat.S_ISLNK(result.st_mode)


def _require_private_directory(path: str, label: str) -> None:
    try:
        result = os.lstat(path)
    except OSError:
        raise ApplicationError(f"{label} must be a non-symlink directory: {path}") from None
    if not stat.S_ISDIR(result.st_mode) or stat.S_ISLNK(result.st_mode):
        raise ApplicationError(f"{label} must be a non-symlink directory: {path}")
    if result.st_uid != _UID or stat.S_IMODE(result.st_mode) != 0o700:
        raise ApplicationError(f"{label} must be current-user-owned with mode 700: {path}")


def _detect_storage_encryption(pki_dir: str, environment: Mapping[str, str]) -> str:
    path = environment.get("PATH")
    if shutil.which("findmnt", path=path) is None or shutil.which("lsblk", path=path) is None:
        return "unknown"
    options = {
        "env": environment,
        "timeout": 5.0,
        "term_grace": 0.5,
        "stdout_limit": 65536,
        "stderr_limit": 65536,
    }
    try:
        mounted = run_process(
            ("findmnt", "--noheadings", "--output", "SOURCE", "--target", pki_dir),
            **options,
        )
        assert isinstance(mounted, ProcessResult)
        if mounted.status:
            return "unknown"
        source_bytes = mounted.stdout.rstrip(b"\n").split(b"[", 1)[0]
        if b"\0" in source_bytes:
            return "unknown"
        source = os.fsdecode(source_bytes)
        ancestry = run_process(
            ("lsblk", "--inverse", "--noheadings", "--output", "FSTYPE", source),
            **options,
        )
        assert isinstance(ancestry, ProcessResult)
        if ancestry.status:
            return "unknown"
    except (ApplicationError, ValueError):
        return "unknown"
    saw_ancestry = False
    for filesystem in ancestry.stdout.rstrip(b"\n").split(b"\n"):
        if not filesystem:
            continue
        saw_ancestry = True
        if filesystem == b"crypto_LUKS":
            return "luks-ancestor"
    return "no-luks-ancestor" if saw_ancestry else "unknown"


def _text_report(report: Report, layout: str, storage: str) -> str:
    material_width = max((len(item.id) for item in report.materials), default=0, )
    material_width = max(8, material_width)
    role_width = max((4, *(len(item.role) for item in report.materials)))
    evidence_width = max((19, *(len(item.encryption_evidence) for item in report.materials)))
    custody_width = max((19, *(len(item.recommended_custody) for item in report.materials)))
    backup_width = max((13, *(len(item.backup_policy) for item in report.materials)))
    severity_width = max((8, *(len(item.severity) for item in report.findings)))
    code_width = max((4, *(len(item.code) for item in report.findings)))
    finding_material_width = max((8, *(len(item.material) for item in report.findings)))
    status = "findings" if report.findings else "ok"
    lines = [
        f"status={status}",
        f"layout={layout}",
        f"storage_encryption_evidence={storage}",
        f"materials={len(report.materials)}",
        f"findings={len(report.findings)}",
        "",
        f"{'MATERIAL':<{material_width}}  {'ROLE':<{role_width}}  {'ENCRYPTION_EVIDENCE':<{evidence_width}}  {'RECOMMENDED_CUSTODY':<{custody_width}}  {'BACKUP_POLICY':<{backup_width}}  STATUS",
    ]
    lines.extend(
        f"{item.id:<{material_width}}  {item.role:<{role_width}}  {item.encryption_evidence:<{evidence_width}}  {item.recommended_custody:<{custody_width}}  {item.backup_policy:<{backup_width}}  {item.status}"
        for item in report.materials
    )
    lines.extend(("", "FINDINGS"))
    if not report.findings:
        lines.append("none")
    else:
        lines.append(
            f"{'SEVERITY':<{severity_width}}  {'CODE':<{code_width}}  {'MATERIAL':<{finding_material_width}}  ACTION"
        )
        lines.extend(
            f"{item.severity:<{severity_width}}  {item.code:<{code_width}}  {item.material:<{finding_material_width}}  {item.action}"
            for item in report.findings
        )
    lines.extend(("", "OPERATIONAL_CHECKS"))
    lines.extend(f"{name}=unknown" for name in _OPERATIONAL_CHECKS)
    return "\n".join(lines) + "\n"


def _json_report(report: Report, layout: str, storage: str) -> str:
    value = {
        "schema": 1,
        "status": "findings" if report.findings else "ok",
        "layout": layout,
        "storage_encryption_evidence": storage,
        "materials": [asdict(item) for item in report.materials],
        "findings": [asdict(item) for item in report.findings],
        "operational_checks": {name: "unknown" for name in _OPERATIONAL_CHECKS},
    }
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False) + "\n"


def custody_report(parsed: ParseResult) -> int:
    environment = dict(os.environ)
    require_pilot_common_library(environment)
    paths = resolve_paths(parsed.values, environment)
    require_pki_directory(paths.pki_dir)
    prepare_control_state(paths.pki_dir)
    os.umask(0o077)

    with acquire_operational_locks(paths.pki_dir, "export"):
        require_no_unresolved_state(paths.pki_dir)
        try:
            root = OpenedDirectory(paths.pki_dir, policy=_PRIVATE_DIRECTORY)
        except FilesystemError:
            raise ApplicationError("PKI directory does not satisfy its private path policy") from None
        with root:
            report = Report(paths.pki_dir, root)
            layout = detect_layout(paths.pki_dir)
            _scan_managed_metadata(report)
            if layout == "generation":
                roots = f"{paths.pki_dir}/authorities/roots"
                for generation in _visible_entries(roots):
                    authority = f"{roots}/{generation}"
                    if not _real_directory(authority):
                        raise ApplicationError(f"Root authority path is unsafe: {authority}")
                    if _ROOT_GENERATION.fullmatch(generation) is None:
                        raise ApplicationError(f"Invalid root generation ID: {generation}")
                    _inspect_key(
                        report,
                        f"root:{generation}",
                        "root-authority",
                        ("authorities", "roots", generation, "private", "root-ca.key"),
                        "offline-detached",
                        "two-encrypted-separated",
                    )
                intermediates = f"{paths.pki_dir}/authorities/intermediates"
                for generation in _visible_entries(intermediates):
                    authority = f"{intermediates}/{generation}"
                    if not _real_directory(authority):
                        raise ApplicationError(f"Intermediate authority path is unsafe: {authority}")
                    if _INTERMEDIATE_GENERATION.fullmatch(generation) is None:
                        raise ApplicationError(f"Invalid intermediate generation ID: {generation}")
                    _inspect_key(
                        report,
                        f"intermediate:{generation}",
                        "intermediate-authority",
                        ("authorities", "intermediates", generation, "private", "intermediate-ca.key"),
                        "offline-signer",
                        "encrypted-after-each-ca-mutation",
                    )
            elif layout == "legacy":
                _inspect_key(
                    report,
                    "legacy-root",
                    "root-authority",
                    ("root-ca", "private", "root-ca.key"),
                    "offline-detached",
                    "two-encrypted-separated",
                )
                _inspect_key(
                    report,
                    "legacy-intermediate",
                    "intermediate-authority",
                    ("intermediate-ca", "private", "intermediate-ca.key"),
                    "offline-signer",
                    "encrypted-after-each-ca-mutation",
                )
            else:
                raise ApplicationError(
                    "PKI custody report requires a complete legacy or generation layout; "
                    f"detected: {layout}"
                )

            services = f"{paths.pki_dir}/services"
            if _lexists(services):
                if not _real_directory(services):
                    raise ApplicationError(f"Service state must be a non-symlink directory: {services}")
                for service in _visible_entries(services):
                    service_dir = f"{services}/{service}"
                    if not _real_directory(service_dir):
                        raise ApplicationError(f"Service state path is unsafe: {service_dir}")
                    if _SERVICE_NAME.fullmatch(service) is None:
                        raise ApplicationError(f"Invalid service name: {service}")
                    _inspect_key(
                        report,
                        f"service:{service}",
                        "controller-leaf-key",
                        ("services", service, "private", "tls.key"),
                        "target-host-only",
                        "reissue-with-fresh-key",
                        "medium",
                        "controller-leaf-key",
                        "migrate-to-host-local-key",
                    )

            csr = f"{paths.pki_dir}/state/csr"
            if _lexists(csr):
                _require_private_directory(csr, "Host-local CSR protocol state")
                report.add_material(
                    "host-local-csr-state",
                    "certificate-only-candidates-and-protocol-evidence",
                    "not-required",
                    "controlled-protocol-state",
                    "encrypted-state-backup",
                    "review",
                )

            export_services = f"{paths.pki_dir}/export/ansible/services"
            if _lexists(export_services):
                if not _real_directory(export_services):
                    raise ApplicationError(
                        f"Ansible service export must be a non-symlink directory: {export_services}"
                    )
                for service in _visible_entries(export_services):
                    service_dir = f"{export_services}/{service}"
                    if not _real_directory(service_dir):
                        raise ApplicationError(f"Ansible service export path is unsafe: {service_dir}")
                    if _SERVICE_NAME.fullmatch(service) is None:
                        raise ApplicationError(f"Invalid service name: {service}")
                    key = f"{service_dir}/tls.key"
                    if _lexists(key):
                        _inspect_key(
                            report,
                            f"export:{service}",
                            "ansible-export-key",
                            ("export", "ansible", "services", service, "tls.key"),
                            "migration-only",
                            "do-not-retain",
                            "high",
                            "duplicate-export-key",
                            "remove-after-validated-host-local-migration",
                        )

            _inspect_backups(report)
            report.add_material(
                "inventory",
                "private-infrastructure-metadata",
                "storage-volume",
                "local-private",
                "encrypted-state-backup",
                "review",
            )
            report.add_material(
                "ca-databases",
                "integrity-critical-ca-state",
                "storage-volume",
                "offline-signer",
                "encrypted-after-each-ca-mutation",
                "review",
            )
            if _lexists(f"{paths.pki_dir}/legacy"):
                report.add_material(
                    "legacy",
                    "migration-quarantine",
                    "storage-volume",
                    "restricted-quarantine",
                    "encrypted-until-reviewed-retention",
                    "review",
                )
            report.add_material(
                "public-artifacts",
                "certificates-chains-and-csrs",
                "not-required",
                "controlled-public-artifact",
                "reconstructable",
                "ok",
            )
            _scan_unexpected_keys(report)
            storage = _detect_storage_encryption(paths.pki_dir, environment)
            output = (
                _json_report(report, layout, storage)
                if parsed["--format"] == "json"
                else _text_report(report, layout, storage)
            )
            sys.stdout.write(output)
            return 2 if report.findings else 0
    raise AssertionError("custody report lock context exited without a result")
