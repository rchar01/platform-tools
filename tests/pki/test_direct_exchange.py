from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
from typing import cast

import pytest

from src.platform_pki import direct_exchange as client
from src.platform_pki.errors import ApplicationError
from src.platform_pki.parser import ParseResult, RouteSpec


pytestmark = pytest.mark.pki
REQUEST_ID = "0123456789abcdef0123456789abcdef"


def private_dir(path: Path) -> Path:
    path.mkdir(parents=True)
    path.chmod(0o700)
    return path


def private_file(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    path.chmod(0o600)
    return path


def record(**values: str) -> bytes:
    return "".join(f"{key}={value}\n" for key, value in values.items()).encode("ascii")


def parsed(action: str, **values: str) -> ParseResult:
    spec = RouteSpec(("direct-exchange", action), (), (), ())
    return ParseResult(spec, MappingProxyType(values), frozenset(values))


def response_files() -> tuple[dict[str, bytes], str]:
    artifact = record(
        schema="1",
        service="registry-test",
        target="target.test",
        request_id=REQUEST_ID,
    )
    files = {
        "artifact": artifact,
        "tls.crt": b"certificate\n",
        "ca-chain.crt": b"chain\n",
        "fullchain.crt": b"fullchain\n",
        "response": record(
            schema="1",
            request_id=REQUEST_ID,
            service="registry-test",
            target="target.test",
        ),
        "response.sig": b"signature\n",
    }
    assert tuple(files) == client.RESPONSE_NAMES
    return files, client.sha256(artifact)


def endpoint_fixture(
    root: Path, *, expected: str | None = None
) -> tuple[Path, client.Endpoint]:
    identity = private_file(root / "identity", b"private identity\n")
    algorithm = b"ssh-ed25519"
    public = b"k" * 32
    blob = (
        len(algorithm).to_bytes(4, "big")
        + algorithm
        + len(public).to_bytes(4, "big")
        + public
    )
    encoded = base64.b64encode(blob).decode("ascii")
    digest = (
        "SHA256:"
        + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    )
    known_hosts = private_file(
        root / "known_hosts",
        f"target.test ssh-ed25519 {encoded}\n".encode("ascii"),
    )
    value = {
        "expected_host_key_sha256": expected or digest,
        "host": "target.test",
        "identity_path": os.fspath(identity),
        "known_hosts_path": os.fspath(known_hosts),
        "port": 22,
        "remote_helper_path": "/usr/local/libexec/platform-pki-host-local-exchange",
        "schema": 1,
        "user": "admin",
    }
    endpoint_path = private_file(
        root / "endpoint.json", client.canonical_json(value) + b"\n"
    )
    return endpoint_path, client.load_endpoint(os.fspath(endpoint_path))


def test_allowlists_are_exact_and_exclude_private_key_name() -> None:
    assert client.NAMES_BY_KIND == {
        "request": ("tls.csr", "request", "request.sig"),
        "response": (
            "artifact",
            "tls.crt",
            "ca-chain.crt",
            "fullchain.crt",
            "response",
            "response.sig",
        ),
        "evidence": (
            "deployment",
            "deployment.sig",
            "validation-boundary",
            "validation-result",
            "validation-result.sig",
        ),
        "outcome": (
            "outcome",
            "outcome.sig",
            "deployment",
            "deployment.sig",
            "deployers.allowed_signers",
            "decision",
        ),
    }
    assert all("tls" + ".key" not in names for names in client.NAMES_BY_KIND.values())
    assert "tls" + ".key" not in Path(client.__file__).read_text(encoding="utf-8")


def test_pinned_ssh_argv_and_no_shell_use(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    endpoint_path, endpoint = endpoint_fixture(tmp_path)
    known_host_blob = base64.b64decode(endpoint.known_hosts_data.decode("ascii").split()[2])
    assert endpoint.transport_host_key_sha256 == hashlib.sha256(
        known_host_blob
    ).hexdigest()
    observed: dict[str, object] = {}

    def fake_run(
        argv: list[str], input_data: bytes | None
    ) -> tuple[int, bytes, bytes]:
        observed["argv"] = argv
        observed["input_data"] = input_data
        identity_path = Path(argv[argv.index("-i") + 1])
        known_hosts_option = next(
            value for value in argv if value.startswith("UserKnownHostsFile=")
        )
        known_hosts_path = Path(known_hosts_option.split("=", 1)[1])
        observed["identity_path"] = identity_path
        observed["known_hosts_path"] = known_hosts_path
        assert identity_path.read_bytes() == endpoint.identity_data
        assert known_hosts_path.read_bytes() == endpoint.known_hosts_data
        return 0, b"frame", b""

    monkeypatch.setattr(client, "run_bounded", fake_run)
    assert client.invoke(endpoint, "export-request", [REQUEST_ID], None) == b"frame"
    argv = observed["argv"]
    assert isinstance(argv, list)
    required = {
        "BatchMode=yes",
        "IdentitiesOnly=yes",
        "StrictHostKeyChecking=yes",
        "GlobalKnownHostsFile=/dev/null",
        "UpdateHostKeys=no",
        "VerifyHostKeyDNS=no",
        "ForwardAgent=no",
        "ForwardX11=no",
        "ClearAllForwardings=yes",
        "PermitLocalCommand=no",
        "ProxyCommand=none",
        "ProxyJump=none",
        "CanonicalizeHostname=no",
    }
    assert required.issubset(set(argv))
    assert endpoint.identity_path not in argv
    assert f"UserKnownHostsFile={endpoint.known_hosts_path}" not in argv
    proc_prefix = f"/proc/{os.getpid()}/fd/"
    assert os.fspath(cast(Path, observed["identity_path"])).startswith(proc_prefix)
    assert os.fspath(cast(Path, observed["known_hosts_path"])).startswith(proc_prefix)
    assert argv[-6:] == [
        "sudo",
        "-n",
        "--",
        endpoint.remote_helper_path,
        "export-request",
        REQUEST_ID,
    ]
    assert observed["input_data"] is None
    assert os.fspath(endpoint_path) not in argv
    assert not cast(Path, observed["identity_path"]).exists()
    assert not cast(Path, observed["known_hosts_path"]).exists()


def test_rejects_openssh_path_tokens(tmp_path: Path) -> None:
    endpoint_path, _endpoint = endpoint_fixture(tmp_path)
    value = json.loads(endpoint_path.read_bytes())
    value["known_hosts_path"] = "/outside-git/ssh/%h.known_hosts"
    private_file(endpoint_path, client.canonical_json(value) + b"\n")

    with pytest.raises(client.DirectExchangeError, match="canonical non-root path"):
        client.load_endpoint(os.fspath(endpoint_path))


def test_ssh_uses_validated_bytes_after_source_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _endpoint_path, endpoint = endpoint_fixture(tmp_path)
    private_file(Path(endpoint.identity_path), b"replacement identity\n")
    private_file(Path(endpoint.known_hosts_path), b"replacement known hosts\n")

    def fake_run(
        argv: list[str], _input_data: bytes | None
    ) -> tuple[int, bytes, bytes]:
        identity_path = Path(argv[argv.index("-i") + 1])
        known_hosts_option = next(
            value for value in argv if value.startswith("UserKnownHostsFile=")
        )
        known_hosts_path = Path(known_hosts_option.split("=", 1)[1])
        assert identity_path.read_bytes() == endpoint.identity_data
        assert known_hosts_path.read_bytes() == endpoint.known_hosts_data
        return 0, b"frame", b""

    monkeypatch.setattr(client, "run_bounded", fake_run)
    assert client.invoke(endpoint, "export-request", [REQUEST_ID], None) == b"frame"


@pytest.mark.parametrize(
    ("stream", "limit", "message"),
    (("stdout", "MAX_FRAME", "output"), ("stderr", "HEADER_LIMIT", "diagnostics")),
)
def test_bounds_ssh_process_output(stream: str, limit: str, message: str) -> None:
    size = getattr(client, limit) + 1
    script = f"import sys; sys.{stream}.buffer.write(b'x' * {size})"

    with pytest.raises(client.DirectExchangeError, match=f"{message} exceeded"):
        client.run_bounded([sys.executable, "-c", script], None)


def test_bounded_process_times_out_under_stdin_backpressure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(client, "SSH_TIMEOUT_SECONDS", 0.1)

    with pytest.raises(subprocess.TimeoutExpired):
        client.run_bounded(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            b"x" * client.MAX_FRAME,
        )


def test_openssh_loads_parent_memfd_identity(tmp_path: Path) -> None:
    identity = tmp_path / "probe-identity"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", identity],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    identity_data = identity.read_bytes()
    identity.unlink()
    identity.with_suffix(".pub").unlink()
    descriptor = client.sealed_memfd("platform-pki-probe", identity_data)
    identity_path = f"/proc/{os.getpid()}/fd/{descriptor}"
    try:
        result = subprocess.run(
            [
                "ssh",
                "-vvv",
                "-F",
                "/dev/null",
                "-T",
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "ProxyCommand=/bin/false",
                "-o",
                "CanonicalizeHostname=no",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-i",
                identity_path,
                "probe.invalid",
                "true",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
    finally:
        os.close(descriptor)

    assert result.returncode == 255
    diagnostics = result.stderr.decode("utf-8")
    assert re.search(
        rf"identity file {re.escape(identity_path)} type [0-9]+", diagnostics
    )
    assert f"Identity file {identity_path} not accessible" not in diagnostics


def test_request_pull_reports_receipt_compatible_host_key_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    endpoint_path, endpoint = endpoint_fixture(tmp_path)
    output_dir = tmp_path / "request-output"
    files = {
        "tls.csr": b"csr\n",
        "request": b"request\n",
        "request.sig": b"signature\n",
    }
    values = {"request_id": REQUEST_ID}
    frame = client.encode_frame(
        "request", files, values, "registry-test", "target.test"
    )
    output = io.BytesIO()
    monkeypatch.setattr(client, "load_endpoint", lambda _path: endpoint)
    monkeypatch.setattr(client, "invoke", lambda *_args: frame)
    monkeypatch.setattr(client.sys, "stdout", SimpleNamespace(buffer=output))

    status = client.direct_exchange(
        parsed(
            "request-pull",
            endpoint=os.fspath(endpoint_path),
            request_id=REQUEST_ID,
            output_dir=os.fspath(output_dir),
        )
    )

    assert status == 0
    result = json.loads(output.getvalue())
    assert result["transport_host_key_sha256"] == endpoint.transport_host_key_sha256
    assert set(result) == {
        "request_id",
        "service",
        "status",
        "target",
        "transport_host_key_sha256",
    }
    assert set(path.name for path in output_dir.iterdir()) == set(client.REQUEST_NAMES)
    assert "tls" + ".key" not in set(path.name for path in output_dir.iterdir())


def test_response_push_runs_leaf_operation_and_emits_canonical_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    endpoint_path, endpoint = endpoint_fixture(tmp_path)
    input_dir = private_dir(tmp_path / "response-input")
    files, artifact_sha = response_files()
    for name, data in files.items():
        private_file(input_dir / name, data)
    expected = {
        "artifact_sha256": artifact_sha,
        "request_id": REQUEST_ID,
        "status": "staged",
    }
    observed: dict[str, object] = {}

    def fake_invoke(
        actual_endpoint: client.Endpoint,
        remote_command: str,
        coordinates: tuple[str, ...],
        input_data: bytes | None,
    ) -> bytes:
        observed.update(
            endpoint=actual_endpoint,
            remote_command=remote_command,
            coordinates=coordinates,
            input_data=input_data,
        )
        return client.canonical_json(expected) + b"\n"

    output = io.BytesIO()
    monkeypatch.setattr(client, "load_endpoint", lambda _path: endpoint)
    monkeypatch.setattr(client, "invoke", fake_invoke)
    monkeypatch.setattr(client.sys, "stdout", SimpleNamespace(buffer=output))

    assert client.direct_exchange(
        parsed(
            "response-push",
            endpoint=os.fspath(endpoint_path),
            request_id=REQUEST_ID,
            artifact_sha256=artifact_sha,
            input_dir=os.fspath(input_dir),
        )
    ) == 0

    assert output.getvalue() == client.canonical_json(expected) + b"\n"
    assert observed["endpoint"] == endpoint
    assert observed["remote_command"] == "stage-response"
    assert observed["coordinates"] == (REQUEST_ID, artifact_sha)
    frame = cast(bytes, observed["input_data"])
    decoded, service, target = client.decode_frame(
        frame,
        "response",
        {"request_id": REQUEST_ID, "artifact_sha256": artifact_sha},
    )
    assert decoded == files
    assert (service, target) == ("registry-test", "target.test")


def test_wrong_known_host_digest_is_rejected_before_ssh(tmp_path: Path) -> None:
    endpoint_path, _endpoint = endpoint_fixture(tmp_path)
    value = json.loads(endpoint_path.read_bytes())
    value["expected_host_key_sha256"] = "SHA256:" + "A" * 43
    private_file(endpoint_path, client.canonical_json(value) + b"\n")
    with pytest.raises(client.DirectExchangeError, match="digest differs"):
        client.load_endpoint(os.fspath(endpoint_path))


def test_rejects_unsafe_local_file_metadata(tmp_path: Path) -> None:
    path = private_file(tmp_path / "unsafe", b"data\n")
    path.chmod(0o644)
    with pytest.raises(client.DirectExchangeError, match="unsafe metadata"):
        client.protected_file(os.fspath(path), "unsafe file", maximum=32)


@pytest.mark.parametrize(
    "error",
    (
        client.DirectExchangeError("direct failure"),
        OSError("operating system failure"),
        ValueError("value failure"),
    ),
)
def test_handler_sets_umask_and_converts_public_errors(
    error: Exception, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed: list[int] = []
    monkeypatch.setattr(client.os, "umask", lambda value: observed.append(value) or 0o022)
    monkeypatch.setattr(
        client,
        "_run_direct_exchange",
        lambda _parsed: (_ for _ in ()).throw(error),
    )

    with pytest.raises(ApplicationError, match=re.escape(str(error))):
        client.direct_exchange(parsed("request-pull"))
    assert observed == [0o077]
