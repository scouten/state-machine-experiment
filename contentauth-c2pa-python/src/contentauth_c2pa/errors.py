"""Errors reported by the native library and by misuse of a session."""

from enum import IntEnum


class ErrorCode(IntEnum):
    """Native error codes; values are checked against the C header by the tests."""

    INVALID_ARGUMENT = 1
    UNSUPPORTED_TYPE = 2
    NOT_FOUND = 3
    READ = 4
    PANIC = 5
    BUILD = 6


class C2paError(Exception):
    """A failure reported by the native library, with its code and Debug-style name."""

    def __init__(self, code: ErrorCode | int, name: str, message: str) -> None:
        super().__init__(f"{name}: {message}" if name else message)
        self.code = code
        self.name = name
        self.message = message


class ClosedError(RuntimeError):
    """The session or result was closed, or consumed by `finish()`."""
