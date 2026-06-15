"""Locating and verifying license certificates on disk (SPEC §6–§7).

A *certificate file* is a single token (whitespace trimmed). The search order is
an explicit path, then ``$HOME/.supso/license_certificates/``, then
``./.supso/license_certificates/``. A live certificate always wins; failing
that, the most-recently-expired otherwise-valid one is honored if it lapsed
within the grace window.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import NamedTuple, Optional, Union

from .errors import SupsoError
from .keys import IssuerKeys
from .license import License
from .verify import verify_token_internal, _iso

#: The subdirectory under each ``.supso/`` base that holds certificates.
CERTIFICATE_SUBDIR = "license_certificates"


@dataclass(frozen=True)
class ValidValidity:
    kind: str = "valid"


@dataclass(frozen=True)
class GraceValidity:
    expired_at: datetime
    grace_until: datetime
    kind: str = "grace"


Validity = Union[ValidValidity, GraceValidity]


class Located(NamedTuple):
    license: License
    validity: Validity


class _GraceCandidate(NamedTuple):
    license: License
    expires_at: datetime


def locate(
    explicit: Optional[str],
    project: str,
    keys: IssuerKeys,
    grace_period: timedelta,
    now: datetime,
) -> Located:
    """Locate and verify a certificate for ``project``.

    When ``explicit`` is set, only that path is consulted (no fallback).
    ``grace_period`` is the grace window.
    """
    tried: list[tuple[str, str]] = []
    grace: Optional[_GraceCandidate] = None

    def verify_file(path: Path) -> Optional[License]:
        nonlocal grace
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as e:
            tried.append((str(path), f"could not read certificate: {e}"))
            return None
        try:
            result = verify_token_internal(raw.strip(), project, keys, now)
        except SupsoError as e:
            tried.append((str(path), e.message))
            return None
        if not result.expired:
            return result.license
        expires_at = result.license.order.expires_at
        tried.append((str(path), f"license expired at {_iso(expires_at)} (now: {_iso(now)})"))
        if grace is None or expires_at > grace.expires_at:
            grace = _GraceCandidate(license=result.license, expires_at=expires_at)
        return None

    def scan_dir(directory: Path) -> Optional[License]:
        try:
            entries = sorted(p for p in directory.iterdir() if not p.name.startswith("."))
        except OSError:
            return None
        for path in entries:
            if not path.is_file():
                continue
            lic = verify_file(path)
            if lic is not None:
                return lic
        return None

    found: Optional[License] = None
    if explicit is not None:
        ep = Path(explicit)
        if not ep.exists():
            raise SupsoError(
                "no_certificate", f"no license certificate found (searched: {explicit})"
            )
        found = scan_dir(ep) if ep.is_dir() else verify_file(ep)
        searched = [explicit]
    else:
        searched = _default_dirs()
        for directory in searched:
            found = scan_dir(Path(directory))
            if found is not None:
                break

    return _finalize(found, grace, tried, searched, grace_period, now)


def _finalize(
    found: Optional[License],
    grace: Optional[_GraceCandidate],
    tried: list[tuple[str, str]],
    searched: list[str],
    grace_period: timedelta,
    now: datetime,
) -> Located:
    if found is not None:
        return Located(license=found, validity=ValidValidity())
    if grace is not None:
        grace_until = grace.expires_at + grace_period
        if now <= grace_until:
            return Located(
                license=grace.license,
                validity=GraceValidity(expired_at=grace.expires_at, grace_until=grace_until),
            )
    if not tried:
        raise SupsoError(
            "no_certificate",
            f"no license certificate found (searched: {', '.join(searched)})",
        )
    detail = "; ".join(f"{p}: {why}" for p, why in tried)
    raise SupsoError("none_valid", f"no valid license certificate ({len(tried)} tried): {detail}")


def _default_dirs() -> list[str]:
    """Per-user ``$HOME`` first, then the project-local ``./.supso``."""
    dirs: list[str] = []
    home = os.environ.get("HOME") or os.environ.get("USERPROFILE")
    if home:
        dirs.append(str(Path(home) / ".supso" / CERTIFICATE_SUBDIR))
    dirs.append(str(Path(".supso") / CERTIFICATE_SUBDIR))
    return dirs
