"""Public, single-line application errors and exit-status helpers."""

from __future__ import annotations

import unicodedata


ERROR_STATUS = 1


def _validate_status(status: int) -> int:
    if isinstance(status, bool) or not isinstance(status, int):
        raise TypeError("status must be an integer")
    if not 1 <= status <= 255:
        raise ValueError("status must be between 1 and 255")
    return status


def shell_status(returncode: int) -> int:
    """Map a subprocess return code to the status convention used by shells."""

    if isinstance(returncode, bool) or not isinstance(returncode, int):
        raise TypeError("returncode must be an integer")
    return 128 - returncode if returncode < 0 else returncode


class ApplicationError(Exception):
    """An error whose message and status are explicitly safe for public output."""

    def __init__(self, message: str, *, status: int = ERROR_STATUS) -> None:
        if not isinstance(message, str):
            raise TypeError("message must be a string")
        if not message or any(
            unicodedata.category(character) in {"Cc", "Cf", "Cs", "Zl", "Zp"}
            for character in message
        ):
            raise ValueError("message must be a nonempty single line")
        self.message = message
        self.status = _validate_status(status)
        super().__init__(message)

    def __str__(self) -> str:
        return self.message

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(message={self.message!r}, "
            f"status={self.status})"
        )


def render_error(error: ApplicationError) -> str:
    """Render exactly one uncolored diagnostic line for stderr."""

    if not isinstance(error, ApplicationError):
        raise TypeError("error must be an ApplicationError")
    return f"[ERROR] {error.message}\n"
