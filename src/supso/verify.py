"""Token verification: the hybrid signature + payload pipeline (SPEC §4–§5).

A token is three URL-safe-base64 segments joined by ``.``::

    base64url(payload_json) . base64url(ed25519_sig) . base64url(mldsa44_sig)

Both signatures cover the *encoded* payload bytes (the first segment as ASCII),
so the verifier never canonicalizes JSON. Acceptance requires **both**
signatures to verify — "hybrid" is AND, not OR.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from datetime import datetime, timezone
from typing import Any, NamedTuple, Optional

from cryptography.exceptions import InvalidSignature
from dilithium_py.ml_dsa import ML_DSA_44

from .errors import SupsoError
from .keys import IssuerKeys
from .license import License, Order, Organization, Project

SCHEMA_VERSION = 1
_ED25519_SIG_LEN = 64
_MLDSA44_SIG_LEN = 2420


class Verified(NamedTuple):
    """A token that passed every check except, possibly, expiry."""

    license: License
    expired: bool


def verify_token_internal(
    token: str,
    expected_project: Optional[str],
    keys: IssuerKeys,
    now: datetime,
) -> Verified:
    """Verify a token's signatures and payload against ``keys``.

    When ``expected_project`` is not ``None``, the payload's project slug must
    equal it. Expiry is reported via :attr:`Verified.expired` rather than raised,
    so the certificate search can recover a lapsed license for the grace window.
    """
    segments = token.split(".")
    if len(segments) != 3:
        raise SupsoError("malformed", "token must split into exactly three segments")
    payload_b64, ed_sig_b64, pq_sig_b64 = segments
    if not payload_b64 or not ed_sig_b64 or not pq_sig_b64:
        raise SupsoError("malformed", "token has an empty segment")

    signed_msg = payload_b64.encode("ascii")

    # ---- Ed25519 ----
    ed_sig = _decode_segment(ed_sig_b64)
    if len(ed_sig) != _ED25519_SIG_LEN:
        raise SupsoError("malformed", "Ed25519 signature is not 64 bytes")
    if not any(_safe_verify_ed(pk, ed_sig, signed_msg) for pk in keys.ed25519):
        raise SupsoError("bad_ed25519_signature", "Ed25519 signature is invalid")

    # ---- ML-DSA-44 ----
    pq_sig = _decode_segment(pq_sig_b64)
    if len(pq_sig) != _MLDSA44_SIG_LEN:
        raise SupsoError("malformed", "ML-DSA-44 signature is the wrong length")
    if not any(_safe_verify_pq(pk, signed_msg, pq_sig) for pk in keys.mldsa44):
        raise SupsoError("bad_mldsa_signature", "ML-DSA-44 signature is invalid")

    # ---- payload ----
    payload = _parse_payload(_decode_segment(payload_b64))
    if payload["v"] != SCHEMA_VERSION:
        raise SupsoError(
            "unsupported_schema", f"license schema version {payload['v']} is not supported"
        )

    project = _read_project(payload)
    if expected_project is not None and project.slug != expected_project:
        found = project.slug or "<none>"
        raise SupsoError(
            "wrong_project",
            f'license is not for project "{expected_project}" (found "{found}")',
        )

    expires_at = _parse_expiry(payload["order"]["expires_at"])
    organization = Organization(
        id=payload["organization"]["id"], name=payload["organization"]["name"]
    )
    order = Order(id=payload["order"]["id"], expires_at=expires_at)
    license = License(
        organization=organization,
        project=project,
        order=order,
        metadata=payload["metadata"] or {},
    )
    return Verified(license=license, expired=expires_at <= now)


def verify_token_strict(
    token: str, expected_project: str, keys: IssuerKeys, now: datetime
) -> License:
    """Verify a token, collapsing expiry to a raised ``expired`` error (no grace)."""
    result = verify_token_internal(token, expected_project, keys, now)
    if result.expired:
        raise SupsoError(
            "expired",
            f"license expired at {_iso(result.license.order.expires_at)} (now: {_iso(now)})",
        )
    return result.license


def inspect_token(token: str, keys: IssuerKeys, now: datetime) -> License:
    """Verify signatures, schema, and timestamp **without** binding to a project,
    returning the license even if expired. For tooling that enumerates
    certificates and reads the project from the payload. A forged token raises.
    """
    return verify_token_internal(token, None, keys, now).license


# ---- payload parsing ----


def _parse_payload(raw_bytes: bytes) -> dict[str, Any]:
    try:
        obj = json.loads(raw_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise SupsoError("invalid_json", "license payload is not valid JSON")
    if not isinstance(obj, dict):
        raise SupsoError("invalid_json", "license payload is not an object")
    v = obj.get("v")
    if not isinstance(v, int) or isinstance(v, bool):
        raise SupsoError("invalid_json", "license payload is missing `v`")
    organization = _require_object(obj.get("organization"), "organization")
    order = _require_object(obj.get("order"), "order")
    metadata = obj.get("metadata")
    return {
        "v": v,
        "organization": {
            "id": _require_string(organization.get("id"), "organization.id"),
            "name": _require_string(organization.get("name"), "organization.name"),
        },
        "order": {
            "id": _require_string(order.get("id"), "order.id"),
            "expires_at": _require_string(order.get("expires_at"), "order.expires_at"),
        },
        "metadata": metadata if isinstance(metadata, dict) else None,
    }


def _read_project(payload: dict[str, Any]) -> Project:
    """The product binding lives at ``metadata.project``; missing fields default to ``""``."""
    metadata = payload.get("metadata")
    proj = metadata.get("project") if isinstance(metadata, dict) else None

    def field(key: str) -> str:
        if isinstance(proj, dict):
            v = proj.get(key)
            if isinstance(v, str):
                return v
        return ""

    return Project(id=field("id"), slug=field("slug"), name=field("name"))


def _require_object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SupsoError("invalid_json", f"license payload is missing `{field}`")
    return value


def _require_string(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise SupsoError(
            "invalid_json", f"license payload field `{field}` is missing or not a string"
        )
    return value


# ---- expiry parsing (SPEC §5) ----

_DATE_ONLY = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
)


def _parse_expiry(s: str) -> datetime:
    """Parse ``order.expires_at``. A full RFC 3339 timestamp is used verbatim; a
    bare ``YYYY-MM-DD`` date expires at the **end** of that day (``23:59:59Z``).
    """
    if _DATE_ONLY.match(s):
        return _parse_iso(f"{s}T23:59:59Z", s)
    if _RFC3339.match(s):
        return _parse_iso(s, s)
    raise SupsoError("bad_timestamp", f"`order.expires_at` is not a valid timestamp: {s}")


def _parse_iso(value: str, original: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        raise SupsoError(
            "bad_timestamp", f"`order.expires_at` is not a valid timestamp: {original}"
        )
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


# ---- base64 + signatures ----

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def _decode_segment(s: str) -> bytes:
    """Strict URL-safe base64 (no padding) decode; raises ``base64`` on bad input."""
    if not _B64URL_RE.match(s):
        raise SupsoError("base64", "segment is not valid url-safe base64")
    if len(s) % 4 == 1:
        raise SupsoError("base64", "invalid base64 length")
    padded = s + "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except (ValueError, binascii.Error):
        raise SupsoError("base64", "segment is not valid url-safe base64")


def _safe_verify_ed(pk, sig: bytes, msg: bytes) -> bool:
    try:
        pk.verify(sig, msg)
        return True
    except InvalidSignature:
        return False


def _safe_verify_pq(pk: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        return bool(ML_DSA_44.verify(pk, msg, sig))
    except Exception:  # noqa: BLE001 - a malformed key/sig is just "does not verify"
        return False


__all__ = [
    "Verified",
    "verify_token_internal",
    "verify_token_strict",
    "inspect_token",
    "SCHEMA_VERSION",
]
