"""Shared default-deny confirmation for interactive PKI decisions."""

from __future__ import annotations

import sys

from .errors import ApplicationError


def confirm_action(
    action: str,
    service: str,
    request_id: str,
    *,
    operation: str | None = None,
    yes: bool = False,
) -> None:
    """Confirm one explicit action and coordinate on an interactive terminal."""

    if yes:
        return
    if not sys.stdin.isatty():
        raise ApplicationError(
            "Interactive confirmation requires a TTY; use --yes only after review"
        )
    print(f"Confirmation for {service} {request_id}", file=sys.stderr)
    if operation is not None:
        print(f"Operation: {operation}", file=sys.stderr)
    print(f"Do you want to {action}? [y/N] ", file=sys.stderr, end="", flush=True)
    if sys.stdin.readline().strip().lower() not in {"y", "yes"}:
        raise ApplicationError("Confirmation declined")
