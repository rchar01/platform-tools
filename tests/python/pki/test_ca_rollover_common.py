import os
from collections.abc import Callable, Mapping
from hashlib import sha256
from pathlib import Path

import pytest

from ..harness import ProcessResult


pytestmark = pytest.mark.pki


def test_file_identity_detects_same_size_same_second_rewrite(
    tmp_path: Path,
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    common_library = (
        Path(__file__).resolve().parents[3] / "lib/platform-pki-common.sh"
    )
    rewritten = tmp_path / "key"
    rewritten.write_bytes(b"first")
    rewritten.chmod(0o600)

    second = rewritten.stat().st_mtime_ns // 1_000_000_000
    first_timestamp = second * 1_000_000_000 + 100_000_000
    second_timestamp = second * 1_000_000_000 + 200_000_000
    os.utime(rewritten, ns=(first_timestamp, first_timestamp))

    command = [
        "bash",
        "-c",
        'source "$1"; pki_file_identity "$2"',
        "_",
        common_library,
        rewritten,
    ]
    before = process_runner(command, env=isolated_environment, timeout=10)
    metadata_before = rewritten.stat()

    rewritten.write_bytes(b"other")
    os.utime(rewritten, ns=(second_timestamp, second_timestamp))
    after = process_runner(command, env=isolated_environment, timeout=10)
    metadata_after = rewritten.stat()

    assert before.status == after.status == 0
    assert before.stderr == after.stderr == ""
    assert before.stdout.strip()
    assert before.stdout != after.stdout
    assert metadata_before.st_dev == metadata_after.st_dev
    assert metadata_before.st_ino == metadata_after.st_ino
    assert metadata_before.st_mode == metadata_after.st_mode
    assert metadata_before.st_size == metadata_after.st_size == 5
    assert metadata_before.st_mtime_ns // 1_000_000_000 == (
        metadata_after.st_mtime_ns // 1_000_000_000
    )


def test_state_record_preserves_nanosecond_file_identity(
    tmp_path: Path,
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    common_library = (
        Path(__file__).resolve().parents[3] / "lib/platform-pki-common.sh"
    )
    source = tmp_path / "key"
    source.write_bytes(b"state-identity")
    source.chmod(0o600)
    second = source.stat().st_mtime_ns // 1_000_000_000
    timestamp = second * 1_000_000_000 + 123_456_789
    os.utime(source, ns=(timestamp, timestamp))

    identity_result = process_runner(
        [
            "bash",
            "-c",
            'source "$1"; pki_file_identity "$2"',
            "_",
            common_library,
            source,
        ],
        env=isolated_environment,
        timeout=10,
    )
    assert identity_result.status == 0
    assert identity_result.stderr == ""
    identity = identity_result.stdout.strip()
    assert ".123456789 " in identity

    state_directory = tmp_path / "state"
    state_directory.mkdir(mode=0o700)
    state = state_directory / "identity"
    result = process_runner(
        [
            "bash",
            "-c",
            'source "$1"; pki_atomic_write "$2" "identity=$3\n"; '
            'pki_read_state_record "$2" Identity; '
            'printf "%s\n" "${PKI_RECORD[identity]}"',
            "_",
            common_library,
            state,
            identity,
        ],
        env=isolated_environment,
        timeout=10,
    )

    assert result.status == 0
    assert result.stderr == ""
    assert result.stdout == f"{identity}\n"
    assert state.read_text() == f"identity={identity}\n"
    assert state.stat().st_mode & 0o777 == 0o600
    assert not state.is_symlink()


def test_manifested_tree_rejects_same_inode_member_rewrite(
    tmp_path: Path,
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    common_library = (
        Path(__file__).resolve().parents[3] / "lib/platform-pki-common.sh"
    )
    case = tmp_path / "manifest-removal"
    tree = case / "tree"
    tree.mkdir(mode=0o700, parents=True)
    member = tree / "key"
    member.write_bytes(b"first")
    member.chmod(0o600)

    second = member.stat().st_mtime_ns // 1_000_000_000
    first_timestamp = second * 1_000_000_000 + 300_000_000
    second_timestamp = second * 1_000_000_000 + 400_000_000
    os.utime(member, ns=(first_timestamp, first_timestamp))

    manifest_result = process_runner(
        [
            "bash",
            "-c",
            'source "$1"; pki_tree_manifest "$2"',
            "_",
            common_library,
            tree,
        ],
        env=isolated_environment,
        timeout=10,
    )
    assert manifest_result.status == 0
    assert manifest_result.stderr == ""
    manifest_lines = manifest_result.stdout.splitlines()
    assert len(manifest_lines) == 1
    member_type, relative, member_identity, member_digest = manifest_lines[0].split(
        "|", 3
    )
    assert member_type == "regular file"
    assert relative == "key"
    assert member_identity
    assert member_digest == sha256(member.read_bytes()).hexdigest()
    manifest = case / "manifest"
    manifest.write_text(manifest_result.stdout)
    manifest.chmod(0o600)

    identities = process_runner(
        [
            "bash",
            "-c",
            'source "$1"; pki_file_identity "$2"; pki_dir_identity "$3"; '
            'pki_file_identity "$4"',
            "_",
            common_library,
            manifest,
            tree,
            member,
        ],
        env=isolated_environment,
        timeout=10,
    )
    assert identities.status == 0
    assert identities.stderr == ""
    manifest_identity, tree_identity, direct_member_identity = (
        identities.stdout.splitlines()
    )
    assert member_identity == direct_member_identity
    manifest_digest = sha256(manifest.read_bytes()).hexdigest()
    manifest_before = manifest.read_bytes()
    member_before = member.stat()

    member.write_bytes(b"other")
    os.utime(member, ns=(second_timestamp, second_timestamp))
    member_after = member.stat()
    result = process_runner(
        [
            "bash",
            "-c",
            'source "$1"; pki_remove_manifested_tree '
            '"$2" "$3" "$4" "$5" "$6" "$7"',
            "_",
            common_library,
            tree,
            tree_identity,
            case,
            manifest,
            manifest_identity,
            manifest_digest,
        ],
        env=isolated_environment,
        timeout=10,
    )

    assert result.status == 1
    assert result.stdout == result.stderr == ""
    assert member.read_bytes() == b"other"
    assert manifest.read_bytes() == manifest_before
    assert tree.is_dir() and not tree.is_symlink()
    assert member_before.st_dev == member_after.st_dev
    assert member_before.st_ino == member_after.st_ino
    assert member_before.st_mode == member_after.st_mode
    assert member_before.st_size == member_after.st_size == 5
    assert member_before.st_mtime_ns // 1_000_000_000 == (
        member_after.st_mtime_ns // 1_000_000_000
    )


def test_committed_prepare_journal_requires_recovery(
    tmp_path: Path,
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    common_library = (
        Path(__file__).resolve().parents[3] / "lib/platform-pki-common.sh"
    )
    pki = tmp_path / "pki"
    rollover_state = pki / "state/rollover"
    rollover_state.mkdir(mode=0o700, parents=True)
    pki.chmod(0o700)
    (pki / "state").chmod(0o700)
    journal = rollover_state / "journal"
    journal.write_text("operation=rollover-prepare\ncommitted=true\n")
    journal.chmod(0o600)
    content_before = journal.read_bytes()
    metadata_before = journal.stat()

    result = process_runner(
        [
            "bash",
            "-c",
            'source "$1"; PKI_DIR=$2; pki_require_no_unresolved_journal',
            "_",
            common_library,
            pki,
        ],
        env=isolated_environment,
        timeout=10,
    )

    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == (
        "[ERROR] PKI recovery is required before this command can continue: "
        f"{journal}\n"
    )
    metadata_after = journal.stat()
    assert journal.read_bytes() == content_before
    assert metadata_after.st_dev == metadata_before.st_dev
    assert metadata_after.st_ino == metadata_before.st_ino
    assert metadata_after.st_mode == metadata_before.st_mode
    assert metadata_after.st_size == metadata_before.st_size
    assert metadata_after.st_mtime_ns == metadata_before.st_mtime_ns


def test_committed_migration_journal_remains_operational(
    tmp_path: Path,
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    common_library = (
        Path(__file__).resolve().parents[3] / "lib/platform-pki-common.sh"
    )
    pki = tmp_path / "pki"
    rollover_state = pki / "state/rollover"
    rollover_state.mkdir(mode=0o700, parents=True)
    pki.chmod(0o700)
    (pki / "state").chmod(0o700)
    journal = rollover_state / "journal"
    journal.write_text("operation=legacy-migrate\ncommitted=true\n")
    journal.chmod(0o600)
    content_before = journal.read_bytes()
    metadata_before = journal.stat()

    result = process_runner(
        [
            "bash",
            "-c",
            'source "$1"; PKI_DIR=$2; pki_require_no_unresolved_journal',
            "_",
            common_library,
            pki,
        ],
        env=isolated_environment,
        timeout=10,
    )

    assert result.status == 0
    assert result.stdout == result.stderr == ""
    metadata_after = journal.stat()
    assert journal.read_bytes() == content_before
    assert metadata_after.st_dev == metadata_before.st_dev
    assert metadata_after.st_ino == metadata_before.st_ino
    assert metadata_after.st_mode == metadata_before.st_mode
    assert metadata_after.st_size == metadata_before.st_size
    assert metadata_after.st_mtime_ns == metadata_before.st_mtime_ns


def test_ca_profile_rejects_noncritical_basic_constraints(
    tmp_path: Path,
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    common_library = (
        Path(__file__).resolve().parents[3] / "lib/platform-pki-common.sh"
    )
    private_key = tmp_path / "basic.key"
    certificate = tmp_path / "basic.crt"
    generated = process_runner(
        [
            "openssl",
            "req",
            "-new",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=bad-basic",
            "-days",
            "1",
            "-keyout",
            private_key,
            "-out",
            certificate,
            "-addext",
            "basicConstraints=CA:true,pathlen:1",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ],
        env=isolated_environment,
        timeout=30,
    )
    assert generated.status == 0
    assert certificate.is_file() and not certificate.is_symlink()
    assert private_key.is_file() and not private_key.is_symlink()

    profile = process_runner(
        [
            "openssl",
            "x509",
            "-in",
            certificate,
            "-noout",
            "-ext",
            "basicConstraints",
        ],
        env=isolated_environment,
        timeout=10,
    )
    assert profile.status == 0
    assert profile.stderr == ""
    assert profile.stdout == (
        "X509v3 Basic Constraints: \n"
        "    CA:TRUE, pathlen:1\n"
    )

    result = process_runner(
        [
            "bash",
            "-c",
            'source "$1"; pki_require_ca_certificate_profile "$2" 1 Test',
            "_",
            common_library,
            certificate,
        ],
        env=isolated_environment,
        timeout=10,
    )

    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == (
        "[ERROR] Test must have critical CA:TRUE Basic Constraints "
        "with pathlen:1\n"
    )


def test_ca_profile_rejects_extra_key_usage(
    tmp_path: Path,
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    common_library = (
        Path(__file__).resolve().parents[3] / "lib/platform-pki-common.sh"
    )
    private_key = tmp_path / "usage.key"
    certificate = tmp_path / "usage.crt"
    generated = process_runner(
        [
            "openssl",
            "req",
            "-new",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=bad-usage",
            "-days",
            "1",
            "-keyout",
            private_key,
            "-out",
            certificate,
            "-addext",
            "basicConstraints=critical,CA:true,pathlen:1",
            "-addext",
            "keyUsage=critical,digitalSignature,keyCertSign,cRLSign",
        ],
        env=isolated_environment,
        timeout=30,
    )
    assert generated.status == 0
    assert certificate.is_file() and not certificate.is_symlink()
    assert private_key.is_file() and not private_key.is_symlink()

    constraints = process_runner(
        [
            "openssl",
            "x509",
            "-in",
            certificate,
            "-noout",
            "-ext",
            "basicConstraints",
        ],
        env=isolated_environment,
        timeout=10,
    )
    assert constraints.status == 0
    assert constraints.stderr == ""
    assert constraints.stdout == (
        "X509v3 Basic Constraints: critical\n"
        "    CA:TRUE, pathlen:1\n"
    )

    usage = process_runner(
        [
            "openssl",
            "x509",
            "-in",
            certificate,
            "-noout",
            "-ext",
            "keyUsage",
        ],
        env=isolated_environment,
        timeout=10,
    )
    assert usage.status == 0
    assert usage.stderr == ""
    assert usage.stdout == (
        "X509v3 Key Usage: critical\n"
        "    Digital Signature, Certificate Sign, CRL Sign\n"
    )

    result = process_runner(
        [
            "bash",
            "-c",
            'source "$1"; pki_require_ca_certificate_profile "$2" 1 Test',
            "_",
            common_library,
            certificate,
        ],
        env=isolated_environment,
        timeout=10,
    )

    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == (
        "[ERROR] Test must have critical Certificate Sign and CRL Sign "
        "Key Usage only\n"
    )
