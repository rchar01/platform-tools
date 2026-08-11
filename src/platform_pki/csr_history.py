"""Authentication of retained host-local CSR deployment history."""

from __future__ import annotations

import datetime
import hashlib
import os
import re
from dataclasses import dataclass
from typing import Callable, Mapping

from .csr_protocol import (
    CsrOperation,
    CsrProtocolError,
    parse_csr_approval,
    parse_csr_candidate,
    parse_csr_replay_nonce,
    parse_csr_replay_request,
    parse_csr_request,
    parse_csr_response,
    parse_csr_terminal,
    validate_request_approval_binding,
)
from .filesystem import (
    DirectoryIdentity,
    DirectoryPolicy,
    FileIdentity,
    FilePolicy,
    FilesystemError,
    OpenedDirectory,
    OpenedFile,
)
from .inventory import InventoryService
from .records import OrderedRecord, RecordError, RecordSpec
from .subprocesses import ProcessResult, run_process


CSR_ARTIFACT_FIELDS = tuple(
    """schema kind service request_id operation target source_kind
source_response_sha256 source_response_signature_sha256 certificate_sha256
certificate_spki_sha256 chain_sha256 fullchain_sha256 issuer_root
issuer_intermediate serial not_before_epoch not_after_epoch candidate_state
deployment_state response_principal created_epoch""".split()
)
CSR_DEPLOYMENT_FIELDS = tuple(
    """schema request_id nonce operation service target request_sha256 response_sha256
response_signature_sha256 candidate_sha256 artifact_request_id
artifact_manifest_sha256 certificate_sha256 certificate_spki_sha256
chain_sha256 fullchain_sha256 action result local_certificate_sha256
local_key_spki_sha256 local_key_certificate_match served_certificate_sha256
served_intermediate_sha256 validation_boundary_sha256 validation_result
activation_epoch validation_epoch rollback_state rollback_hold_until_epoch
deployment_principal created_epoch expires_epoch""".split()
)
CSR_ACTIVE_FIELDS = tuple(
    """schema service target request_id operation certificate_sha256
certificate_spki_sha256 response_sha256 artifact_manifest_sha256
deployment_sha256 decision_sha256 activation_epoch rollback_hold_until_epoch
updated_epoch""".split()
)
CSR_DECISION_FIELDS = tuple(
    """schema action state service target request_id operation request_sha256
response_sha256 response_signature_sha256 candidate_sha256
artifact_manifest_sha256 certificate_sha256 certificate_spki_sha256
chain_sha256 fullchain_sha256 deployment_sha256 deployment_signature_sha256
deployers_sha256 predecessor_kind predecessor_request_id
predecessor_certificate_sha256 predecessor_certificate_spki_sha256
predecessor_intermediate_sha256 predecessor_response_sha256
predecessor_artifact_manifest_sha256 predecessor_deployment_sha256
predecessor_decision_sha256 resulting_active_request_id created_epoch""".split()
)

_ARTIFACT_SPEC = RecordSpec(CSR_ARTIFACT_FIELDS, schema="1")
_DEPLOYMENT_SPEC = RecordSpec(CSR_DEPLOYMENT_FIELDS, schema="1")
_ACTIVE_SPEC = RecordSpec(CSR_ACTIVE_FIELDS, schema="1")
_DECISION_SPEC = RecordSpec(CSR_DECISION_FIELDS, schema="1")
_ISSUER_SPEC = RecordSpec(("root", "intermediate"))
_DIGEST = re.compile(r"[0-9a-f]{64}", re.ASCII)
_REQUEST_ID = re.compile(r"[0-9a-f]{32}", re.ASCII)
_EPOCH = re.compile(r"0|[1-9][0-9]*", re.ASCII)
_PRINCIPAL = re.compile(r"[a-z0-9][a-z0-9.-]*", re.ASCII)
_OWNER = os.geteuid()
_FILE = FilePolicy(owner=_OWNER, mode=0o600, links=1, max_size=64 * 1024 * 1024)
_DIRECTORY = DirectoryPolicy(owner=_OWNER, mode=0o700)
_MAX_HISTORY_DEPTH = 256
_SCHEMA2_TRUST_FILES = frozenset(
    (
        "policy",
        "requesters.allowed_signers",
        "approvers.allowed_signers",
        "responses.allowed_signers",
        "deployers.allowed_signers",
    )
)
_SCHEMA2_POLICY_PREFIX = (
    "schema=2",
    "request_namespace=platform-pki-csr-request-v1",
    "approval_namespace=platform-pki-csr-approval-v1",
    "response_namespace=platform-pki-csr-response-v1",
    "deployment_namespace=platform-pki-csr-deployment-v1",
    "request_max_age_seconds=604800",
    "sole_operator_min_delay_seconds=86400",
    "approval_max_age_seconds=86400",
    "deployment_max_age_seconds=86400",
    "clock_skew_seconds=300",
)


class CsrHistoryError(ValueError):
    """Retained CSR history is not completely authenticated."""


@dataclass(frozen=True, slots=True)
class CsrHistoryAuthentication:
    """Authenticated history summary plus its exact source recheck."""

    request_ids: frozenset[str]
    root_request_id: str
    root_action: str
    root_state: str
    resulting_active_request_id: str
    _recheck: Callable[[], None]

    def __call__(self) -> None:
        self._recheck()


@dataclass(frozen=True, slots=True)
class _File:
    path: str
    identity: FileIdentity
    data: bytes

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.data).hexdigest()


@dataclass(frozen=True, slots=True)
class _Directory:
    path: str
    identity: DirectoryIdentity
    files: Mapping[str, _File]


@dataclass(frozen=True, slots=True)
class _Outcome:
    request_id: str
    operation: CsrOperation
    certificate_sha256: str
    certificate_spki_sha256: str
    intermediate_sha256: str
    response_sha256: str
    artifact_sha256: str
    deployment_sha256: str
    decision_sha256: str
    activation_epoch: str
    rollback_hold_until_epoch: str
    updated_epoch: str
    action: str
    state: str
    resulting_active_request_id: str


class _Evidence:
    def __init__(self) -> None:
        self.files: list[_File] = []
        self.directories: list[_Directory] = []

    def file(self, path: str, label: str, *, public: bool = False) -> _File:
        data = b""
        identity: FileIdentity | None = None
        policy = (
            FilePolicy(
                owner=_OWNER,
                forbidden_bits=0o022,
                links=1,
                max_size=_FILE.max_size,
            )
            if public
            else _FILE
        )
        try:
            with OpenedFile(path, policy=policy) as opened:
                data = opened.read(policy.max_size or 0)
                identity = opened.recheck()
        except FilesystemError:
            raise CsrHistoryError(f"{label} is unsafe") from None
        assert identity is not None
        result = _File(path, identity, data)
        self.files.append(result)
        return result

    def tree(self, path: str, names: frozenset[str], label: str) -> _Directory:
        files: dict[str, _File] = {}
        identity: DirectoryIdentity | None = None
        try:
            with OpenedDirectory(path, policy=_DIRECTORY) as directory:
                if frozenset(os.listdir(directory.fileno())) != names:
                    raise CsrHistoryError(f"{label} has unexpected entries")
                for name in sorted(names):
                    with directory.open_file(name, policy=_FILE) as opened:
                        data = opened.read(_FILE.max_size or 0)
                        files[name] = _File(
                            f"{path}/{name}", opened.recheck(), data
                        )
                identity = directory.recheck().directory
        except FilesystemError:
            raise CsrHistoryError(f"{label} is unsafe") from None
        assert identity is not None
        result = _Directory(path, identity, files)
        self.directories.append(result)
        self.files.extend(files.values())
        return result

    def recheck(self) -> None:
        try:
            for item in self.files:
                with OpenedFile(
                    item.path,
                    policy=FilePolicy(
                        owner=_OWNER,
                        mode=item.identity.permissions,
                        links=1,
                        max_size=_FILE.max_size,
                    ),
                    expected_identity=item.identity,
                ) as opened:
                    if opened.read(_FILE.max_size or 0) != item.data:
                        raise CsrHistoryError("CSR historical evidence changed during validation")
                    opened.recheck()
            for item in self.directories:
                with OpenedDirectory(
                    item.path,
                    policy=_DIRECTORY,
                    expected_identity=item.identity,
                ) as directory:
                    if frozenset(os.listdir(directory.fileno())) != frozenset(item.files):
                        raise CsrHistoryError("CSR historical evidence changed during validation")
                    directory.recheck()
        except FilesystemError:
            raise CsrHistoryError("CSR historical evidence changed during validation") from None


def _record(item: _File, spec: RecordSpec, label: str) -> OrderedRecord:
    try:
        return spec.parse(item.data)
    except RecordError as error:
        raise CsrHistoryError(f"{label} is invalid: {error}") from None


def _require_digest(value: str, label: str, *, allow_none: bool = False) -> None:
    if allow_none and value == "none":
        return
    if _DIGEST.fullmatch(value) is None:
        raise CsrHistoryError(f"{label} is not a lowercase SHA-256 digest")


def _epoch(value: str, label: str) -> int:
    if _EPOCH.fullmatch(value) is None:
        raise CsrHistoryError(f"{label} is not a canonical epoch")
    return int(value, 10)


def _allowed_signers(
    item: _File, principal: str, label: str, *, sole: bool = False
) -> Mapping[str, str]:
    try:
        lines = item.data.decode("ascii").splitlines()
    except UnicodeDecodeError:
        raise CsrHistoryError(f"{label} is invalid") from None
    keys: dict[str, str] = {}
    for line in lines:
        fields = line.split(" ")
        if (
            len(fields) != 3
            or _PRINCIPAL.fullmatch(fields[0]) is None
            or fields[1] != "ssh-ed25519"
            or re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", fields[2], re.ASCII) is None
            or fields[0] in keys
        ):
            raise CsrHistoryError(f"{label} is not canonical")
        keys[fields[0]] = fields[2]
    if principal not in keys:
        raise CsrHistoryError(f"{label} does not authorize {principal}")
    if sole and len(keys) != 1:
        raise CsrHistoryError(f"{label} does not contain one pinned signer")
    return keys


def _schema2_trust(evidence: _Evidence, pki_dir: str) -> tuple[_Directory, str, str]:
    trust = evidence.tree(
        f"{pki_dir}/inventory/csr-trust",
        _SCHEMA2_TRUST_FILES,
        "Installed schema-2 CSR trust",
    )
    try:
        lines = trust.files["policy"].data.decode("ascii").splitlines()
    except UnicodeDecodeError:
        raise CsrHistoryError("Installed schema-2 CSR trust policy is invalid") from None
    if tuple(lines[:10]) != _SCHEMA2_POLICY_PREFIX or len(lines) != 12:
        raise CsrHistoryError("Installed schema-2 CSR trust policy is invalid")
    approver = re.fullmatch(
        r"approver_principal=([a-z0-9][a-z0-9.-]*)", lines[10], re.ASCII
    )
    response = re.fullmatch(
        r"response_principal=([a-z0-9][a-z0-9.-]*)", lines[11], re.ASCII
    )
    if approver is None or response is None:
        raise CsrHistoryError("Installed schema-2 CSR trust policy is invalid")
    return trust, approver.group(1), response.group(1)


def _require_trust_root(retained: _File, installed: _File, label: str) -> None:
    if retained.data != installed.data:
        raise CsrHistoryError(
            f"{label} does not match installed schema-2 CSR trust"
        )


def _verify_signature(
    trust: _File,
    signature: _File,
    content: _File,
    principal: str,
    namespace: str,
    environment: Mapping[str, str],
    label: str,
    *,
    sole: bool = False,
) -> None:
    _allowed_signers(trust, principal, label, sole=sole)
    try:
        with OpenedFile(
            trust.path, policy=_FILE, expected_identity=trust.identity
        ) as allowed, OpenedFile(
            signature.path, policy=_FILE, expected_identity=signature.identity
        ) as detached:
            result = run_process(
                (
                    "ssh-keygen",
                    "-Y",
                    "verify",
                    "-f",
                    f"/proc/self/fd/{allowed.fileno()}",
                    "-I",
                    principal,
                    "-n",
                    namespace,
                    "-s",
                    f"/proc/self/fd/{detached.fileno()}",
                ),
                env=environment,
                input=content.data,
                pass_fds=(allowed.fileno(), detached.fileno()),
                timeout=30.0,
                term_grace=1.0,
                stdout_limit=1024 * 1024,
                stderr_limit=1024 * 1024,
            )
            if not isinstance(result, ProcessResult) or result.status:
                raise CsrHistoryError(f"{label} signature verification failed")
            allowed.recheck()
            detached.recheck()
    except FilesystemError:
        raise CsrHistoryError(f"{label} signature verification failed") from None


def _spki(
    item: _File, environment: Mapping[str, str], *, certificate: bool = True
) -> str:
    first: ProcessResult | None = None
    try:
        with OpenedFile(
            item.path,
            policy=FilePolicy(
                owner=_OWNER,
                mode=item.identity.permissions,
                links=1,
                max_size=_FILE.max_size,
            ),
            expected_identity=item.identity,
        ) as opened:
            first = run_process(
                (
                    "openssl",
                    "x509" if certificate else "req",
                    "-in",
                    f"/proc/self/fd/{opened.fileno()}",
                    "-pubkey",
                    "-noout",
                ),
                env=environment,
                pass_fds=(opened.fileno(),),
                timeout=30.0,
                term_grace=1.0,
                stdout_limit=1024 * 1024,
                stderr_limit=1024 * 1024,
            )
            opened.recheck()
    except FilesystemError:
        raise CsrHistoryError("Cannot extract historical certificate public key") from None
    if not isinstance(first, ProcessResult) or first.status:
        raise CsrHistoryError("Cannot extract historical certificate public key")
    second = run_process(
        ("openssl", "pkey", "-pubin", "-outform", "DER"),
        env=environment,
        input=first.stdout,
        timeout=30.0,
        term_grace=1.0,
        stdout_limit=1024 * 1024,
        stderr_limit=1024 * 1024,
    )
    if not isinstance(second, ProcessResult) or second.status:
        raise CsrHistoryError("Cannot encode historical certificate public key")
    return hashlib.sha256(second.stdout).hexdigest()


def _certificate_binding(
    item: _File,
    serial: str,
    not_before: int,
    not_after: int,
    environment: Mapping[str, str],
) -> None:
    result: ProcessResult | None = None
    try:
        with OpenedFile(
            item.path,
            policy=FilePolicy(
                owner=_OWNER,
                mode=item.identity.permissions,
                links=1,
                max_size=_FILE.max_size,
            ),
            expected_identity=item.identity,
        ) as opened:
            result = run_process(
                (
                    "openssl",
                    "x509",
                    "-in",
                    f"/proc/self/fd/{opened.fileno()}",
                    "-noout",
                    "-serial",
                    "-dates",
                ),
                env=environment,
                pass_fds=(opened.fileno(),),
                timeout=30.0,
                term_grace=1.0,
                stdout_limit=1024 * 1024,
                stderr_limit=1024 * 1024,
            )
            opened.recheck()
    except FilesystemError:
        raise CsrHistoryError("Cannot inspect historical certificate metadata") from None
    if not isinstance(result, ProcessResult) or result.status:
        raise CsrHistoryError("Cannot inspect historical certificate metadata")
    try:
        lines = result.stdout.decode("ascii").splitlines()
        actual_serial = lines[0].removeprefix("serial=").upper()
        epochs = tuple(
            int(
                datetime.datetime.strptime(
                    line.split("=", 1)[1], "%b %d %H:%M:%S %Y %Z"
                )
                .replace(tzinfo=datetime.UTC)
                .timestamp()
            )
            for line in lines[1:]
        )
    except (IndexError, UnicodeDecodeError, ValueError):
        raise CsrHistoryError("Historical certificate metadata is invalid") from None
    if (
        len(lines) != 3
        or actual_serial != serial
        or epochs != (not_before, not_after)
    ):
        raise CsrHistoryError("Historical certificate metadata binding failed")


def _verify_certificate_chain(
    certificate: _File,
    intermediate: _File,
    root: _File,
    environment: Mapping[str, str],
) -> None:
    result: ProcessResult | None = None
    try:
        with OpenedFile(
            certificate.path,
            policy=FilePolicy(
                owner=_OWNER,
                mode=certificate.identity.permissions,
                links=1,
                max_size=_FILE.max_size,
            ),
            expected_identity=certificate.identity,
        ) as certificate_file, OpenedFile(
            intermediate.path,
            policy=FilePolicy(
                owner=_OWNER,
                mode=intermediate.identity.permissions,
                links=1,
                max_size=_FILE.max_size,
            ),
            expected_identity=intermediate.identity,
        ) as intermediate_file, OpenedFile(
            root.path,
            policy=FilePolicy(
                owner=_OWNER,
                mode=root.identity.permissions,
                links=1,
                max_size=_FILE.max_size,
            ),
            expected_identity=root.identity,
        ) as root_file:
            descriptors = (
                certificate_file.fileno(),
                intermediate_file.fileno(),
                root_file.fileno(),
            )
            result = run_process(
                (
                    "openssl",
                    "verify",
                    "-CAfile",
                    f"/proc/self/fd/{root_file.fileno()}",
                    "-untrusted",
                    f"/proc/self/fd/{intermediate_file.fileno()}",
                    f"/proc/self/fd/{certificate_file.fileno()}",
                ),
                env=environment,
                pass_fds=descriptors,
                timeout=30.0,
                term_grace=1.0,
                stdout_limit=1024 * 1024,
                stderr_limit=1024 * 1024,
            )
            certificate_file.recheck()
            intermediate_file.recheck()
            root_file.recheck()
    except FilesystemError:
        raise CsrHistoryError("Historical certificate chain verification failed") from None
    if not isinstance(result, ProcessResult) or result.status:
        raise CsrHistoryError("Historical certificate chain verification failed")


def _x509_output(
    item: _File,
    arguments: tuple[str, ...],
    environment: Mapping[str, str],
    label: str,
) -> bytes:
    result: ProcessResult | None = None
    try:
        with OpenedFile(
            item.path,
            policy=FilePolicy(
                owner=_OWNER,
                mode=item.identity.permissions,
                links=1,
                max_size=_FILE.max_size,
            ),
            expected_identity=item.identity,
        ) as opened:
            result = run_process(
                (
                    "openssl",
                    "x509",
                    "-in",
                    f"/proc/self/fd/{opened.fileno()}",
                    *arguments,
                ),
                env=environment,
                pass_fds=(opened.fileno(),),
                timeout=30.0,
                term_grace=1.0,
                stdout_limit=1024 * 1024,
                stderr_limit=1024 * 1024,
            )
            opened.recheck()
    except FilesystemError:
        raise CsrHistoryError(f"Cannot inspect {label}") from None
    if not isinstance(result, ProcessResult) or result.status:
        raise CsrHistoryError(f"Cannot inspect {label}")
    return result.stdout


def _x509_extension(
    item: _File,
    name: str,
    environment: Mapping[str, str],
) -> tuple[bool, str]:
    try:
        lines = _x509_output(
            item,
            ("-noout", "-ext", name),
            environment,
            "historical certificate extension",
        ).decode("ascii").splitlines()
    except UnicodeDecodeError:
        raise CsrHistoryError("Historical certificate extension is invalid") from None
    if not lines or not lines[0].startswith("X509v3 ") or ":" not in lines[0]:
        raise CsrHistoryError("Historical certificate extension is invalid")
    header = lines[0].split(":", 1)[1].strip()
    value = " ".join(line.strip() for line in lines[1:] if line.strip())
    if header not in {"", "critical"} or not value:
        raise CsrHistoryError("Historical certificate extension is invalid")
    return header == "critical", value


def _current_certificate_profile(
    certificate: _File,
    intermediate: _File,
    service: InventoryService,
    environment: Mapping[str, str],
) -> None:
    try:
        metadata = _x509_output(
            certificate,
            ("-noout", "-subject", "-issuer", "-nameopt", "RFC2253"),
            environment,
            "current historical certificate metadata",
        ).decode("ascii").splitlines()
        issuer_metadata = _x509_output(
            intermediate,
            ("-noout", "-subject", "-nameopt", "RFC2253"),
            environment,
            "historical intermediate metadata",
        ).decode("ascii").splitlines()
        text = _x509_output(
            certificate,
            ("-noout", "-text", "-nameopt", "RFC2253"),
            environment,
            "current historical certificate profile",
        ).decode("ascii")
    except UnicodeDecodeError:
        raise CsrHistoryError("Current historical certificate profile is invalid") from None
    if len(issuer_metadata) != 1 or metadata != [
        f"subject=CN={service.common_name}",
        issuer_metadata[0].replace("subject=", "issuer=", 1),
    ]:
        raise CsrHistoryError("Current historical certificate identity does not match inventory")
    signatures = set(
        re.findall(r"^\s*Signature Algorithm: ([^\r\n]+)$", text, re.MULTILINE)
    )
    extension_names = tuple(
        re.findall(r"^\s{12}X509v3 ([^:\r\n]+):", text, re.MULTILINE)
    )
    required_extensions = {
        "Basic Constraints",
        "Key Usage",
        "Extended Key Usage",
        "Subject Alternative Name",
        "Subject Key Identifier",
        "Authority Key Identifier",
    }
    if (
        "Version: 3 (0x2)" not in text
        or "Public Key Algorithm: id-ecPublicKey" not in text
        or "Public-Key: (384 bit)" not in text
        or "ASN1 OID: secp384r1" not in text
        or signatures != {"ecdsa-with-SHA384"}
        or len(extension_names) != len(set(extension_names))
        or set(extension_names) != required_extensions
    ):
        raise CsrHistoryError("Current historical certificate profile is invalid")
    basic_critical, basic = _x509_extension(
        certificate, "basicConstraints", environment
    )
    usage_critical, usage = _x509_extension(certificate, "keyUsage", environment)
    eku_critical, eku = _x509_extension(
        certificate, "extendedKeyUsage", environment
    )
    san_critical, sans = _x509_extension(certificate, "subjectAltName", environment)
    ski_critical, ski = _x509_extension(
        certificate, "subjectKeyIdentifier", environment
    )
    aki_critical, aki = _x509_extension(
        certificate, "authorityKeyIdentifier", environment
    )
    issuer_ski_critical, issuer_ski = _x509_extension(
        intermediate, "subjectKeyIdentifier", environment
    )
    expected_sans = {f"DNS:{value}" for value in service.dns}
    expected_sans.update(f"IP Address:{value}" for value in service.ips)
    actual_sans = tuple(value.strip() for value in sans.split(","))
    key_identifier = re.compile(r"(?:[0-9A-F]{2}:){19}[0-9A-F]{2}", re.ASCII)
    if (
        not basic_critical
        or basic != "CA:FALSE"
        or not usage_critical
        or usage != "Digital Signature"
        or eku_critical
        or eku != "TLS Web Server Authentication"
        or san_critical
        or not actual_sans
        or any(not value for value in actual_sans)
        or len(actual_sans) != len(set(actual_sans))
        or set(actual_sans) != expected_sans
        or ski_critical
        or key_identifier.fullmatch(ski) is None
        or issuer_ski_critical
        or key_identifier.fullmatch(issuer_ski) is None
        or aki_critical
        or aki != issuer_ski
    ):
        raise CsrHistoryError("Current historical certificate profile does not match inventory")


def _same(files: tuple[_File, ...], label: str) -> None:
    if any(item.data != files[0].data for item in files[1:]):
        raise CsrHistoryError(f"{label} differs across immutable CSR artifacts")


def _validate_deployment(
    deployment: OrderedRecord,
    response_operation: CsrOperation,
    action: str,
    certificate_sha256: str,
    certificate_spki_sha256: str,
    intermediate_sha256: str,
    validation_boundary_sha256: str,
    rollback_hold_seconds: int,
    predecessor_kind: str,
    predecessor_certificate_sha256: str,
    predecessor_intermediate_sha256: str,
) -> None:
    for field in (
        "request_sha256",
        "response_sha256",
        "response_signature_sha256",
        "candidate_sha256",
        "artifact_manifest_sha256",
        "certificate_sha256",
        "certificate_spki_sha256",
        "chain_sha256",
        "fullchain_sha256",
        "local_certificate_sha256",
        "local_key_spki_sha256",
        "validation_boundary_sha256",
    ):
        _require_digest(deployment[field], f"Deployment {field}")
    for field in ("served_certificate_sha256", "served_intermediate_sha256"):
        _require_digest(deployment[field], f"Deployment {field}", allow_none=True)
    created = _epoch(deployment["created_epoch"], "Deployment created_epoch")
    expires = _epoch(deployment["expires_epoch"], "Deployment expires_epoch")
    if expires <= created or expires - created > 86400:
        raise CsrHistoryError("Deployment validity interval is invalid")
    if (
        deployment["action"] != action
        or deployment["local_certificate_sha256"] != certificate_sha256
        or deployment["local_key_spki_sha256"] != certificate_spki_sha256
        or deployment["local_key_certificate_match"] != "true"
        or deployment["validation_boundary_sha256"] != validation_boundary_sha256
    ):
        raise CsrHistoryError("Deployment does not bind the exact candidate and inventory")
    if action == "finalize":
        activation = _epoch(
            deployment["activation_epoch"], "Deployment activation_epoch"
        )
        validation = _epoch(
            deployment["validation_epoch"], "Deployment validation_epoch"
        )
        if (
            deployment["result"] != "activated"
            or deployment["served_certificate_sha256"] != certificate_sha256
            or deployment["served_intermediate_sha256"] != intermediate_sha256
            or deployment["validation_result"] != "passed"
            or not activation <= validation <= created + 300
        ):
            raise CsrHistoryError("Deployment does not prove the exact activated candidate")
        if response_operation is CsrOperation.ISSUE:
            if (
                deployment["rollback_state"] != "none"
                or deployment["rollback_hold_until_epoch"] != "none"
            ):
                raise CsrHistoryError("Issue deployment has unexpected rollback evidence")
        else:
            hold = _epoch(
                deployment["rollback_hold_until_epoch"],
                "Deployment rollback_hold_until_epoch",
            )
            if (
                deployment["rollback_state"] != "retained"
                or hold < created + rollback_hold_seconds
            ):
                raise CsrHistoryError("Deployment rollback hold is insufficient")
        return
    if action != "abandon":
        raise CsrHistoryError("Deployment action is invalid")
    if deployment["result"] == "not-activated":
        if (
            deployment["served_certificate_sha256"] != "none"
            or deployment["served_intermediate_sha256"] != "none"
            or deployment["validation_result"] != "not-run"
            or deployment["activation_epoch"] != "none"
            or deployment["validation_epoch"] != "none"
            or deployment["rollback_state"] != "none"
            or deployment["rollback_hold_until_epoch"] != "none"
        ):
            raise CsrHistoryError("Not-activated abandonment evidence is inconsistent")
        return
    if deployment["result"] != "rolled-back" or predecessor_kind == "none":
        raise CsrHistoryError("Abandonment result is invalid")
    activation = _epoch(deployment["activation_epoch"], "Deployment activation_epoch")
    validation = _epoch(deployment["validation_epoch"], "Deployment validation_epoch")
    hold = _epoch(
        deployment["rollback_hold_until_epoch"],
        "Deployment rollback_hold_until_epoch",
    )
    if (
        deployment["served_certificate_sha256"] != predecessor_certificate_sha256
        or deployment["served_intermediate_sha256"]
        != predecessor_intermediate_sha256
        or deployment["validation_result"] != "passed"
        or deployment["rollback_state"] != "restored"
        or not activation <= validation <= created + 300
        or hold < created + rollback_hold_seconds
    ):
        raise CsrHistoryError("Rolled-back abandonment evidence is inconsistent")


def _authenticate_history(
    pki_dir: str,
    service: InventoryService,
    environment: Mapping[str, str],
    *,
    root_request_id: str | None = None,
    request_current_certificate_sha256: str | None = None,
    current_certificate_path: str | None = None,
) -> CsrHistoryAuthentication:
    if service.target is None or service.validation_boundary_sha256 is None or service.rollback_hold_seconds is None:
        raise CsrHistoryError("Host-local inventory lacks deployment trust scalars")
    target = service.target
    validation_boundary_sha256 = service.validation_boundary_sha256
    rollback_hold_seconds = int(service.rollback_hold_seconds, 10)
    evidence = _Evidence()
    trust, approver_principal, response_principal = _schema2_trust(evidence, pki_dir)
    active: OrderedRecord | None = None
    if root_request_id is None:
        if (request_current_certificate_sha256 is None) != (
            current_certificate_path is None
        ):
            raise ValueError(
                "active history authentication requires both current certificate arguments"
            )
        active_file = evidence.file(
            f"{pki_dir}/state/csr/active/{service.name}",
            "Host-local active accepted-evidence pointer",
        )
        active = _record(
            active_file, _ACTIVE_SPEC, "Host-local active accepted-evidence pointer"
        )
        if (
            active["service"] != service.name
            or active["target"] != target
            or _REQUEST_ID.fullmatch(active["request_id"]) is None
        ):
            raise CsrHistoryError("Host-local active accepted-evidence pointer is invalid")
        for field in (
            "certificate_sha256",
            "certificate_spki_sha256",
            "response_sha256",
            "artifact_manifest_sha256",
            "deployment_sha256",
            "decision_sha256",
        ):
            _require_digest(active[field], f"Active pointer {field}")
        if request_current_certificate_sha256 is not None:
            assert current_certificate_path is not None
            if active["certificate_sha256"] != request_current_certificate_sha256:
                raise CsrHistoryError(
                    "Host-local renewal request does not match the authenticated active accepted evidence"
                )
            current = evidence.file(
                current_certificate_path, "Current host-local certificate"
            )
            if current.digest != request_current_certificate_sha256:
                raise CsrHistoryError("Renewal request does not bind the current certificate")
        root_request_id = active["request_id"]
    elif (
        request_current_certificate_sha256 is not None
        or current_certificate_path is not None
        or _REQUEST_ID.fullmatch(root_request_id) is None
    ):
        raise ValueError("terminal history authentication arguments are invalid")

    stack: set[str] = set()
    authenticated: dict[str, _Outcome] = {}

    def historical(request_id: str) -> _Outcome:
        if _REQUEST_ID.fullmatch(request_id) is None:
            raise CsrHistoryError("Historical CSR outcome request ID is invalid")
        existing = authenticated.get(request_id)
        if existing is not None:
            return existing
        if request_id in stack:
            raise CsrHistoryError("Historical CSR outcome predecessor chain contains a cycle")
        if len(stack) >= _MAX_HISTORY_DEPTH:
            raise CsrHistoryError("Historical CSR outcome predecessor chain is too deep")
        stack.add(request_id)
        try:
            candidate = evidence.tree(
                f"{pki_dir}/state/csr/candidates/{service.name}/{request_id}",
                frozenset(("candidate", "tls.crt", "ca-chain.crt", "fullchain.crt", "response", "response.sig")),
                "CSR candidate",
            )
            response_tree = evidence.tree(
                f"{pki_dir}/state/csr/responses/{service.name}/{request_id}",
                frozenset(("tls.crt", "ca-chain.crt", "fullchain.crt", "response", "response.sig")),
                "CSR response",
            )
            artifact = evidence.tree(
                f"{pki_dir}/export/certificates/v1/artifacts/{service.name}/{request_id}",
                frozenset(("artifact", "tls.crt", "ca-chain.crt", "fullchain.crt", "response", "response.sig")),
                "Certificate export artifact",
            )
            outcome = evidence.tree(
                f"{pki_dir}/state/csr/outcomes/{service.name}/{request_id}",
                frozenset(("deployment", "deployment.sig", "deployers.allowed_signers", "decision")),
                "CSR outcome",
            )
            for name in ("tls.crt", "ca-chain.crt", "fullchain.crt", "response", "response.sig"):
                _same(
                    (candidate.files[name], response_tree.files[name], artifact.files[name]),
                    name,
                )
            try:
                response = parse_csr_response(response_tree.files["response"].data)
                candidate_record = parse_csr_candidate(candidate.files["candidate"].data)
            except CsrProtocolError as error:
                raise CsrHistoryError(str(error)) from None
            response_record = response.record
            candidate_values = candidate_record.record
            artifact_record = _record(artifact.files["artifact"], _ARTIFACT_SPEC, "Certificate export manifest")
            deployment = _record(outcome.files["deployment"], _DEPLOYMENT_SPEC, "Deployment evidence")
            decision = _record(outcome.files["decision"], _DECISION_SPEC, "CSR decision")
            if (
                response_record["request_id"] != request_id
                or response_record["service"] != service.name
                or response_record["target"] != target
                or candidate_values["state"] != "pending"
                or artifact_record["kind"] != "certificate-export"
                or artifact_record["service"] != service.name
                or artifact_record["request_id"] != request_id
                or artifact_record["source_kind"] != "csr-response"
                or artifact_record["candidate_state"] != "pending"
                or artifact_record["deployment_state"] != "unfinalized"
            ):
                raise CsrHistoryError("CSR historical source identity binding failed")
            response_sha = response_tree.files["response"].digest
            signature_sha = response_tree.files["response.sig"].digest
            candidate_sha = candidate.files["candidate"].digest
            artifact_sha = artifact.files["artifact"].digest
            certificate_sha = response_tree.files["tls.crt"].digest
            chain_sha = response_tree.files["ca-chain.crt"].digest
            fullchain_sha = response_tree.files["fullchain.crt"].digest
            certificate_spki = _spki(response_tree.files["tls.crt"], environment)
            for field in (
                "request_id", "nonce", "operation", "service", "target",
                "request_sha256", "approval_sha256", "inventory_sha256", "csr_sha256",
                "csr_spki_sha256", "certificate_sha256", "chain_sha256", "issuer_root",
                "issuer_intermediate", "serial", "created_epoch",
            ):
                if candidate_values[field] != response_record[field]:
                    raise CsrHistoryError(f"CSR candidate does not bind response field: {field}")
            if (
                candidate_values["response_sha256"] != response_sha
                or candidate_values["response_signature_sha256"] != signature_sha
                or response_record["certificate_sha256"] != certificate_sha
                or response_record["certificate_spki_sha256"] != certificate_spki
                or response_record["csr_spki_sha256"] != certificate_spki
                or response_record["chain_sha256"] != chain_sha
                or artifact_record["source_response_sha256"] != response_sha
                or artifact_record["source_response_signature_sha256"] != signature_sha
                or artifact_record["certificate_sha256"] != certificate_sha
                or artifact_record["certificate_spki_sha256"] != certificate_spki
                or artifact_record["chain_sha256"] != chain_sha
                or artifact_record["fullchain_sha256"] != fullchain_sha
            ):
                raise CsrHistoryError("CSR historical source digest binding failed")
            for field in (
                "operation", "target", "issuer_root", "issuer_intermediate", "serial",
                "not_before_epoch", "not_after_epoch", "response_principal", "created_epoch",
            ):
                if artifact_record[field] != response_record[field]:
                    raise CsrHistoryError(f"Certificate export does not bind response field: {field}")

            transaction_path = f"{pki_dir}/state/csr/transactions/csr-{request_id}"
            retained_request = evidence.file(f"{transaction_path}/request", "Retained CSR request")
            retained_request_signature = evidence.file(
                f"{transaction_path}/request.sig", "Retained CSR request signature"
            )
            retained_approval = evidence.file(f"{transaction_path}/approval", "Retained CSR approval")
            retained_approval_signature = evidence.file(
                f"{transaction_path}/approval.sig", "Retained CSR approval signature"
            )
            retained_csr = evidence.file(f"{transaction_path}/tls.csr", "Retained CSR")
            response_trust = evidence.file(
                f"{transaction_path}/responses.allowed_signers", "Retained CSR response trust"
            )
            replay_request = evidence.file(
                f"{pki_dir}/state/csr/replay/requests/{request_id}", "CSR request replay record"
            )
            replay_nonce_path = f"{pki_dir}/state/csr/replay/nonces/{response_record['nonce']}"
            replay_nonce = evidence.file(replay_nonce_path, "CSR nonce replay record")
            terminal = evidence.file(f"{transaction_path}/terminal", "CSR signing terminal record")
            try:
                request = parse_csr_request(retained_request.data)
                approval = parse_csr_approval(retained_approval.data)
                request_replay = parse_csr_replay_request(replay_request.data)
                nonce_replay = parse_csr_replay_nonce(replay_nonce.data)
                terminal_record = parse_csr_terminal(terminal.data)
            except CsrProtocolError as error:
                raise CsrHistoryError(str(error)) from None
            if (
                retained_request.digest != response_record["request_sha256"]
                or retained_approval.digest != response_record["approval_sha256"]
                or retained_csr.digest != response_record["csr_sha256"]
                or request_replay.record["request_id"] != request_id
                or request_replay.record["nonce"] != response_record["nonce"]
                or request_replay.record["operation"] != response_record["operation"]
                or request_replay.record["service"] != service.name
                or request_replay.record["target"] != target
                or request_replay.record["request_sha256"] != retained_request.digest
                or request_replay.record["approval_sha256"] != retained_approval.digest
                or request_replay.record["outcome"] != "reserved"
                or nonce_replay.record["nonce"] != response_record["nonce"]
                or nonce_replay.record["request_id"] != request_id
                or nonce_replay.record["request_sha256"] != retained_request.digest
                or nonce_replay.record["outcome"] != "reserved"
                or terminal_record.record["outcome"] != "published"
                or not terminal_record.committed
            ):
                raise CsrHistoryError("Retained CSR transaction binding failed")
            for field in (
                "request_id",
                "nonce",
                "operation",
                "service",
                "target",
                "inventory_sha256",
                "csr_sha256",
                "csr_spki_sha256",
            ):
                if request.record[field] != response_record[field]:
                    raise CsrHistoryError(
                        f"Retained CSR request does not bind response field: {field}"
                    )
            if (
                request.record["response_principal"]
                != response_record["response_principal"]
                or terminal_record.record["transaction"] != f"csr-{request_id}"
                or terminal_record.record["request_id"] != request_id
                or terminal_record.record["operation"]
                != response_record["operation"]
                or terminal_record.record["service"] != service.name
                or _spki(retained_csr, environment, certificate=False)
                != response_record["csr_spki_sha256"]
            ):
                raise CsrHistoryError(
                    "Retained CSR transaction identity binding failed"
                )
            if (
                approval.record["approver_principal"] != approver_principal
                or response_record["response_principal"] != response_principal
            ):
                raise CsrHistoryError(
                    "Retained CSR signer principals do not match installed schema-2 trust policy"
                )
            requester_keys = _allowed_signers(
                trust.files["requesters.allowed_signers"],
                request.record["requester_principal"],
                "Installed CSR requester trust",
            )
            approver_keys = _allowed_signers(
                trust.files["approvers.allowed_signers"],
                approval.record["approver_principal"],
                "Installed CSR approver trust",
                sole=True,
            )
            try:
                validate_request_approval_binding(
                    request,
                    approval,
                    signer_keys_match=(
                        requester_keys[request.record["requester_principal"]]
                        == approver_keys[approval.record["approver_principal"]]
                    ),
                )
            except CsrProtocolError as error:
                raise CsrHistoryError(str(error)) from None
            _verify_signature(
                trust.files["requesters.allowed_signers"],
                retained_request_signature,
                retained_request,
                request.record["requester_principal"],
                "platform-pki-csr-request-v1",
                environment,
                "Retained CSR request",
            )
            _verify_signature(
                trust.files["approvers.allowed_signers"],
                retained_approval_signature,
                retained_approval,
                approval.record["approver_principal"],
                "platform-pki-csr-approval-v1",
                environment,
                "Retained CSR approval",
                sole=True,
            )
            _require_trust_root(
                response_trust,
                trust.files["responses.allowed_signers"],
                "Retained CSR response trust",
            )
            _verify_signature(
                response_trust,
                response_tree.files["response.sig"],
                response_tree.files["response"],
                response_record["response_principal"],
                "platform-pki-csr-response-v1",
                environment,
                "CSR response",
                sole=True,
            )

            issuer_root = response_record["issuer_root"]
            issuer_intermediate = response_record["issuer_intermediate"]
            if (
                re.fullmatch(r"g[1-9][0-9]*", issuer_root, re.ASCII) is None
                or re.fullmatch(
                    r"g[1-9][0-9]*-i[1-9][0-9]*",
                    issuer_intermediate,
                    re.ASCII,
                )
                is None
                or not issuer_intermediate.startswith(f"{issuer_root}-i")
            ):
                raise CsrHistoryError("CSR historical issuer generation is invalid")
            root_certificate = evidence.file(
                f"{pki_dir}/authorities/roots/{issuer_root}/certs/root-ca.crt",
                "Historical root certificate",
                public=True,
            )
            intermediate_certificate = evidence.file(
                f"{pki_dir}/authorities/intermediates/{issuer_intermediate}/certs/intermediate-ca.crt",
                "Historical intermediate certificate",
                public=True,
            )
            _verify_certificate_chain(
                response_tree.files["tls.crt"],
                intermediate_certificate,
                root_certificate,
                environment,
            )
            _certificate_binding(
                response_tree.files["tls.crt"],
                response_record["serial"],
                response.not_before_epoch,
                response.not_after_epoch,
                environment,
            )
            if response_tree.files["ca-chain.crt"].data != intermediate_certificate.data + root_certificate.data:
                raise CsrHistoryError("Historical certificate chain does not match its issuer")
            if response_tree.files["fullchain.crt"].data != response_tree.files["tls.crt"].data + intermediate_certificate.data:
                raise CsrHistoryError("Historical certificate full chain is invalid")
            if active is not None and request_id == root_request_id:
                _current_certificate_profile(
                    response_tree.files["tls.crt"],
                    intermediate_certificate,
                    service,
                    environment,
                )

            deployment_sha = outcome.files["deployment"].digest
            deployment_signature_sha = outcome.files["deployment.sig"].digest
            deployers_sha = outcome.files["deployers.allowed_signers"].digest
            _require_trust_root(
                outcome.files["deployers.allowed_signers"],
                trust.files["deployers.allowed_signers"],
                "Retained CSR deployer trust",
            )
            _verify_signature(
                outcome.files["deployers.allowed_signers"],
                outcome.files["deployment.sig"],
                outcome.files["deployment"],
                target,
                "platform-pki-csr-deployment-v1",
                environment,
                "Deployment evidence",
            )
            if (
                deployment["request_id"] != request_id
                or deployment["artifact_request_id"] != request_id
                or deployment["service"] != service.name
                or deployment["target"] != target
                or deployment["deployment_principal"] != target
                or deployment["nonce"] != response_record["nonce"]
                or deployment["operation"] != response_record["operation"]
                or deployment["request_sha256"] != response_record["request_sha256"]
                or deployment["response_sha256"] != response_sha
                or deployment["response_signature_sha256"] != signature_sha
                or deployment["candidate_sha256"] != candidate_sha
                or deployment["artifact_manifest_sha256"] != artifact_sha
                or deployment["certificate_sha256"] != certificate_sha
                or deployment["certificate_spki_sha256"] != certificate_spki
                or deployment["chain_sha256"] != chain_sha
                or deployment["fullchain_sha256"] != fullchain_sha
            ):
                raise CsrHistoryError("Deployment evidence source binding failed")
            predecessor = {
                "kind": "none",
                "request_id": "none",
                "certificate_sha256": "none",
                "certificate_spki_sha256": "none",
                "intermediate_sha256": "none",
                "response_sha256": "none",
                "artifact_manifest_sha256": "none",
                "deployment_sha256": "none",
                "decision_sha256": "none",
            }
            if response.operation is CsrOperation.RENEW:
                predecessor_outcome = historical(decision["predecessor_request_id"])
                if (
                    predecessor_outcome.action != "finalize"
                    or predecessor_outcome.state != "finalized"
                    or predecessor_outcome.resulting_active_request_id
                    != predecessor_outcome.request_id
                ):
                    raise CsrHistoryError("Renewal predecessor outcome is not finalized")
                if request.record["current_cert_sha256"] != predecessor_outcome.certificate_sha256:
                    raise CsrHistoryError("Recorded renewal request does not bind its authenticated predecessor")
                predecessor.update(
                    kind="host-local",
                    request_id=predecessor_outcome.request_id,
                    certificate_sha256=predecessor_outcome.certificate_sha256,
                    certificate_spki_sha256=predecessor_outcome.certificate_spki_sha256,
                    intermediate_sha256=predecessor_outcome.intermediate_sha256,
                    response_sha256=predecessor_outcome.response_sha256,
                    artifact_manifest_sha256=predecessor_outcome.artifact_sha256,
                    deployment_sha256=predecessor_outcome.deployment_sha256,
                    decision_sha256=predecessor_outcome.decision_sha256,
                )
            elif response.operation is CsrOperation.MIGRATE:
                managed_certificate = evidence.file(
                    f"{pki_dir}/services/{service.name}/certs/tls.crt",
                    "Managed migration predecessor certificate",
                    public=True,
                )
                managed_chain = evidence.file(
                    f"{pki_dir}/services/{service.name}/chain/ca-chain.crt",
                    "Managed migration predecessor chain",
                    public=True,
                )
                managed_issuer = evidence.file(
                    f"{pki_dir}/services/{service.name}/issuer",
                    "Managed migration predecessor issuer",
                )
                issuer = _record(
                    managed_issuer,
                    _ISSUER_SPEC,
                    "Managed migration predecessor issuer",
                )
                if (
                    re.fullmatch(r"g[1-9][0-9]*", issuer["root"], re.ASCII)
                    is None
                    or re.fullmatch(
                        r"g[1-9][0-9]*-i[1-9][0-9]*",
                        issuer["intermediate"],
                        re.ASCII,
                    )
                    is None
                    or not issuer["intermediate"].startswith(
                        f"{issuer['root']}-i"
                    )
                ):
                    raise CsrHistoryError(
                        "Managed migration predecessor issuer is invalid"
                    )
                managed_root = evidence.file(
                    f"{pki_dir}/authorities/roots/{issuer['root']}/certs/root-ca.crt",
                    "Managed migration predecessor root",
                    public=True,
                )
                managed_intermediate = evidence.file(
                    f"{pki_dir}/authorities/intermediates/{issuer['intermediate']}/certs/intermediate-ca.crt",
                    "Managed migration predecessor intermediate",
                    public=True,
                )
                if request.record["current_cert_sha256"] != managed_certificate.digest:
                    raise CsrHistoryError("Recorded migration request does not bind its managed predecessor")
                if managed_chain.data != managed_intermediate.data + managed_root.data:
                    raise CsrHistoryError(
                        "Managed migration predecessor chain does not match its issuer"
                    )
                _verify_certificate_chain(
                    managed_certificate,
                    managed_intermediate,
                    managed_root,
                    environment,
                )
                predecessor.update(
                    kind="managed",
                    certificate_sha256=managed_certificate.digest,
                    certificate_spki_sha256=_spki(managed_certificate, environment),
                    intermediate_sha256=managed_intermediate.digest,
                )
            elif request.record["current_cert_sha256"] != "none":
                raise CsrHistoryError("Recorded issue request unexpectedly binds a predecessor")

            action = decision["action"]
            state = decision["state"]
            if (action, state) not in {
                ("finalize", "finalized"),
                ("abandon", "abandoned"),
            }:
                raise CsrHistoryError("CSR decision action and state are inconsistent")
            _validate_deployment(
                deployment,
                response.operation,
                action,
                certificate_sha,
                certificate_spki,
                intermediate_certificate.digest,
                validation_boundary_sha256,
                rollback_hold_seconds,
                predecessor["kind"],
                predecessor["certificate_sha256"],
                predecessor["intermediate_sha256"],
            )
            resulting = (
                request_id
                if action == "finalize"
                else predecessor["request_id"]
                if predecessor["kind"] == "host-local"
                else "none"
            )

            expected = {
                "schema": "1",
                "action": action,
                "state": state,
                "service": service.name,
                "target": target,
                "request_id": request_id,
                "operation": response_record["operation"],
                "request_sha256": response_record["request_sha256"],
                "response_sha256": response_sha,
                "response_signature_sha256": signature_sha,
                "candidate_sha256": candidate_sha,
                "artifact_manifest_sha256": artifact_sha,
                "certificate_sha256": certificate_sha,
                "certificate_spki_sha256": certificate_spki,
                "chain_sha256": chain_sha,
                "fullchain_sha256": fullchain_sha,
                "deployment_sha256": deployment_sha,
                "deployment_signature_sha256": deployment_signature_sha,
                "deployers_sha256": deployers_sha,
                "predecessor_kind": predecessor["kind"],
                "predecessor_request_id": predecessor["request_id"],
                "predecessor_certificate_sha256": predecessor["certificate_sha256"],
                "predecessor_certificate_spki_sha256": predecessor["certificate_spki_sha256"],
                "predecessor_intermediate_sha256": predecessor["intermediate_sha256"],
                "predecessor_response_sha256": predecessor["response_sha256"],
                "predecessor_artifact_manifest_sha256": predecessor["artifact_manifest_sha256"],
                "predecessor_deployment_sha256": predecessor["deployment_sha256"],
                "predecessor_decision_sha256": predecessor["decision_sha256"],
                "resulting_active_request_id": resulting,
                "created_epoch": deployment["created_epoch"],
            }
            if any(decision[field] != expected[field] for field in CSR_DECISION_FIELDS):
                raise CsrHistoryError("CSR decision does not exactly bind authenticated history")
            result = _Outcome(
                request_id,
                response.operation,
                certificate_sha,
                certificate_spki,
                intermediate_certificate.digest,
                response_sha,
                artifact_sha,
                deployment_sha,
                outcome.files["decision"].digest,
                deployment["activation_epoch"],
                deployment["rollback_hold_until_epoch"],
                deployment["created_epoch"],
                action,
                state,
                resulting,
            )
            authenticated[request_id] = result
            return result
        finally:
            stack.remove(request_id)

    assert root_request_id is not None
    accepted = historical(root_request_id)
    if active is None:
        evidence.recheck()
        return CsrHistoryAuthentication(
            frozenset(authenticated),
            accepted.request_id,
            accepted.action,
            accepted.state,
            accepted.resulting_active_request_id,
            evidence.recheck,
        )
    if accepted.action != "finalize" or accepted.state != "finalized":
        raise CsrHistoryError("Active pointer references a non-finalized CSR outcome")
    expected_active = {
        "schema": "1",
        "service": service.name,
        "target": target,
        "request_id": accepted.request_id,
        "operation": accepted.operation.value,
        "certificate_sha256": accepted.certificate_sha256,
        "certificate_spki_sha256": accepted.certificate_spki_sha256,
        "response_sha256": accepted.response_sha256,
        "artifact_manifest_sha256": accepted.artifact_sha256,
        "deployment_sha256": accepted.deployment_sha256,
        "decision_sha256": accepted.decision_sha256,
        "activation_epoch": accepted.activation_epoch,
        "rollback_hold_until_epoch": accepted.rollback_hold_until_epoch,
        "updated_epoch": accepted.updated_epoch,
    }
    if any(active[field] != expected_active[field] for field in CSR_ACTIVE_FIELDS):
        raise CsrHistoryError("Active pointer does not bind authenticated CSR history")
    evidence.recheck()
    return CsrHistoryAuthentication(
        frozenset(authenticated),
        accepted.request_id,
        accepted.action,
        accepted.state,
        accepted.resulting_active_request_id,
        evidence.recheck,
    )


def authenticate_active_predecessor(
    pki_dir: str,
    service: InventoryService,
    request_current_certificate_sha256: str,
    current_certificate_path: str,
    environment: Mapping[str, str],
) -> CsrHistoryAuthentication:
    """Authenticate the exact active finalized history and return its recheck."""

    return _authenticate_history(
        pki_dir,
        service,
        environment,
        request_current_certificate_sha256=request_current_certificate_sha256,
        current_certificate_path=current_certificate_path,
    )


def authenticate_current_history(
    pki_dir: str,
    service: InventoryService,
    environment: Mapping[str, str],
) -> CsrHistoryAuthentication:
    """Authenticate the current finalized history without an external certificate."""

    return _authenticate_history(pki_dir, service, environment)


def authenticate_terminal_outcome(
    pki_dir: str,
    service: InventoryService,
    request_id: str,
    environment: Mapping[str, str],
) -> CsrHistoryAuthentication:
    """Authenticate one exact immutable finalized or abandoned outcome."""

    return _authenticate_history(
        pki_dir,
        service,
        environment,
        root_request_id=request_id,
    )
