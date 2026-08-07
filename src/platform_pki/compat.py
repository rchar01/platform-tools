from pathlib import Path


COMMANDS = {
    "init": (),
    "inventory-install": (),
    "csr-trust-install": (),
    "csr-recover": (),
    "certificate-export": ("publish", "resolve"),
    "csr-candidate": ("verify", "finalize", "abandon"),
    "root-create": (),
    "intermediate-create": (),
    "service-issue": (),
    "service-renew": (),
    "service-verify": (),
    "list-expiry": (),
    "print-cert": (),
    "export-ansible": (),
    "backup": (),
    "custody-report": (),
    "ca-passphrase-verify": (),
    "ca-rollover": ("migrate", "status", "prepare", "recover"),
}

COMPATIBILITY_COMMANDS = {
    f"platform-pki-{command}": command
    for command in COMMANDS
}


def invocation_name(argv0: str) -> str:
    return Path(argv0).name
