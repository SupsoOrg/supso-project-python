"""The single error type the API raises, tagged with the canonical error
``code`` from the cross-language spec (``spec/SPEC.md`` §4).

Hosts switch on ``code`` to render an actionable message — ``"expired"`` reads
differently from ``"wrong_project"`` reads differently from ``"no_certificate"``.
"""

from __future__ import annotations

from typing import Literal

#: Canonical error names shared by every implementation (SPEC §4).
ErrorCode = Literal[
    "malformed",
    "base64",
    "bad_ed25519_signature",
    "bad_mldsa_signature",
    "invalid_json",
    "unsupported_schema",
    "bad_timestamp",
    "expired",
    "wrong_project",
    "requirement_not_met",
    "no_certificate",
    "none_valid",
    "bad_trusted_key",
]


class SupsoError(Exception):
    """Why a license could not be accepted.

    Carries the canonical :data:`ErrorCode` in :attr:`code` so callers can
    branch on the reason without parsing the human-readable message.
    """

    code: ErrorCode

    def __init__(self, code: ErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.message
