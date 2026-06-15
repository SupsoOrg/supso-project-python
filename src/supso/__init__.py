"""``supso`` — Supported Source license verification.

Assert at startup that the downstream user holds a valid Supso license
certificate for your project. Verification is **100% offline**: it checks a
hybrid Ed25519 + ML-DSA-44 signature against Supso's baked-in public keys and
never touches the network. The library never terminates the host process — it
reports; the host decides.

.. code-block:: python

    import supso

    # Hard enforcement — raises SupsoError your app decides how to act on.
    license = supso.require_license("acme-db")

    # Soft enforcement — never raises; logs a notice on grace/failure.
    status = supso.check_license("acme-db")
    if supso.is_licensed(status):
        ...  # run normally

Or configure once and call the no-argument forms (SPEC §9):

.. code-block:: python

    supso.initialize_project("acme-db", grace_period_days=30)
    license = supso.require_license()
    status = supso.check_license()
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

from .certificate import GraceValidity, Located, locate
from .errors import ErrorCode, SupsoError
from .keys import (
    TRUSTED_ED25519_KEYS_HEX,
    TRUSTED_MLDSA44_KEYS_HEX,
    IssuerKeys,
)
from .license import (
    Grace,
    License,
    Order,
    Organization,
    Project,
    Status,
    Unlicensed,
    Valid,
    is_licensed,
    license_of,
)
from .verify import inspect_token, verify_token_internal, verify_token_strict

#: Default grace window: a lapsed certificate is honored this many days.
DEFAULT_GRACE_PERIOD_DAYS = 21

#: Logging policy for :meth:`Supso.check` (logging only — never aborts).
Enforcement = str  # one of "silent" | "warn" | "error"


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class _Requirements:
    min_seats: Optional[int] = None
    tier: Optional[str] = None
    features: list[str] = field(default_factory=list)
    min_days_remaining: Optional[int] = None


class Supso:
    """A configured license check. Build with :meth:`Supso.project` (or the
    module-level :func:`initialize_project`).

    Setter methods return ``self`` so they can be chained, mirroring the Rust and
    TypeScript builders.
    """

    def __init__(self, project: str) -> None:
        self._project = project
        self._enforcement: Enforcement = "warn"
        self._grace_period_days: int = DEFAULT_GRACE_PERIOD_DAYS
        self._certificate_path: Optional[str] = None
        self._issuer_keys: Optional[IssuerKeys] = None
        self._req = _Requirements()

    @classmethod
    def project(cls, name: str) -> "Supso":
        """Start a check for ``project``. The license's product slug must equal this."""
        return cls(name)

    # ---- configuration ----

    def enforcement(self, policy: Enforcement) -> "Supso":
        self._enforcement = policy
        return self

    def grace_period_days(self, days: int) -> "Supso":
        self._grace_period_days = days
        return self

    def certificate_path(self, path: str) -> "Supso":
        self._certificate_path = path
        return self

    def issuer_keys(self, keys: IssuerKeys) -> "Supso":
        self._issuer_keys = keys
        return self

    def require_seats(self, n: int) -> "Supso":
        self._req.min_seats = n
        return self

    def require_tier(self, tier: str) -> "Supso":
        self._req.tier = tier
        return self

    def require_feature(self, feature: str) -> "Supso":
        self._req.features.append(feature)
        return self

    def require_days_remaining(self, days: int) -> "Supso":
        self._req.min_days_remaining = days
        return self

    # ---- verification ----

    def verify(self) -> License:
        """Verify against the system clock, returning the license or raising."""
        return self.verify_at(_now())

    def verify_at(self, now: datetime) -> License:
        """:meth:`verify` against a supplied clock (for tests)."""
        located = self._locate(now)
        self._enforce_requirements(located.license, now)
        return located.license

    def check(self) -> Status:
        """Verify against the system clock, returning a :data:`Status` (never raises)."""
        return self.check_at(_now())

    def check_at(self, now: datetime) -> Status:
        """:meth:`check` against a supplied clock (for tests)."""
        status: Status
        try:
            located = self._locate(now)
            try:
                self._enforce_requirements(located.license, now)
                if isinstance(located.validity, GraceValidity):
                    status = Grace(
                        license=located.license,
                        expired_at=located.validity.expired_at,
                        grace_until=located.validity.grace_until,
                    )
                else:
                    status = Valid(license=located.license)
            except SupsoError as e:
                status = Unlicensed(error=e)
        except SupsoError as e:
            status = Unlicensed(error=e)
        self._log(status, now)
        return status

    # ---- internals ----

    def _keys(self) -> IssuerKeys:
        return self._issuer_keys if self._issuer_keys is not None else IssuerKeys.supso()

    def _locate(self, now: datetime) -> Located:
        explicit = self._certificate_path or os.environ.get("SUPSO_LICENSE_PATH")
        return locate(
            explicit,
            self._project,
            self._keys(),
            timedelta(days=self._grace_period_days),
            now,
        )

    def _enforce_requirements(self, license: License, now: datetime) -> None:
        r = self._req
        if r.min_seats is not None:
            have = license.seats() or 0
            if have < r.min_seats:
                raise SupsoError(
                    "requirement_not_met",
                    f"requires {r.min_seats} seats, license has {have}",
                )
        if r.tier is not None:
            have_tier = license.tier() or ""
            if have_tier != r.tier:
                raise SupsoError(
                    "requirement_not_met",
                    f'requires tier "{r.tier}", license has "{have_tier}"',
                )
        for feature in r.features:
            if not license.has_feature(feature):
                raise SupsoError("requirement_not_met", f'requires feature "{feature}"')
        if r.min_days_remaining is not None:
            have_days = license.days_remaining(now)
            if have_days < r.min_days_remaining:
                raise SupsoError(
                    "requirement_not_met",
                    f"requires {r.min_days_remaining} days remaining, license has {have_days}",
                )

    def _log(self, status: Status, now: datetime) -> None:
        if isinstance(status, Valid) or self._enforcement == "silent":
            return
        line = status_message(status, now)
        prefix = "supso:" if self._enforcement == "warn" else "supso [error]:"
        print(f"{prefix} {line}", file=sys.stderr)


# ---- status messaging ----

_DAY = timedelta(days=1)


def grace_message(status: Status, now: datetime) -> Optional[str]:
    """A renewal notice for a grace status, else ``None``."""
    if not isinstance(status, Grace):
        return None
    days_ago = max(0, int((now - status.expired_at) / _DAY))
    days_left = max(0, int((status.grace_until - now) / _DAY))
    return (
        f"Your {status.license.project.name} license expired {days_ago} day{_plural(days_ago)} "
        f"ago — you're in a grace period, but it will stop being accepted in {days_left} "
        f"day{_plural(days_left)}. Renew the license certificate to avoid an interruption."
    )


def status_message(status: Status, now: datetime) -> str:
    """One line safe to print or log, whatever the status."""
    if isinstance(status, Valid):
        lic = status.license
        return (
            f"{lic.project.name} licensed to {lic.organization.name} "
            f"(order {lic.order.id})"
        )
    if isinstance(status, Grace):
        return grace_message(status, now) or "license in grace period"
    return status.error.message


def _plural(n: int) -> str:
    return "" if n == 1 else "s"


# ---- module-level convenience functions (SPEC §9) ----

_configured: Optional[Supso] = None


def initialize_project(
    name: str,
    *,
    enforcement: Optional[Enforcement] = None,
    grace_period_days: Optional[int] = None,
    certificate_path: Optional[str] = None,
    issuer_keys: Optional[IssuerKeys] = None,
) -> Supso:
    """Configure the default project for the no-argument :func:`require_license`
    and :func:`check_license` calls, and return the configured :class:`Supso`.
    """
    global _configured
    s = Supso.project(name)
    if enforcement is not None:
        s.enforcement(enforcement)
    if grace_period_days is not None:
        s.grace_period_days(grace_period_days)
    if certificate_path is not None:
        s.certificate_path(certificate_path)
    if issuer_keys is not None:
        s.issuer_keys(issuer_keys)
    _configured = s
    return s


def _for(project: Optional[str]) -> Supso:
    if project is not None:
        return Supso.project(project)
    if _configured is None:
        raise SupsoError(
            "no_certificate",
            "no project configured — pass one or call initialize_project() first",
        )
    return _configured


def require_license(project: Optional[str] = None) -> License:
    """Verify a certificate for ``project`` against the system clock (raises).

    With no argument, uses the project set by :func:`initialize_project`.
    """
    return _for(project).verify()


def check_license(project: Optional[str] = None) -> Status:
    """Verify a certificate for ``project``, returning a :data:`Status` (never raises).

    With no argument, uses the project set by :func:`initialize_project`.
    """
    return _for(project).check()


def verify_token(token: str, project: str) -> License:
    """Verify a raw token for ``project`` (no on-disk search, no grace)."""
    return verify_token_with(token, project, IssuerKeys.supso(), _now())


def verify_token_with(
    token: str, project: str, keys: IssuerKeys, now: datetime
) -> License:
    """:func:`verify_token` with a caller-supplied clock and trust anchor."""
    return verify_token_strict(token, project, keys, now)


def inspect(token: str) -> License:
    """Verify a token without binding to a project, returning it even if expired."""
    return inspect_with(token, IssuerKeys.supso(), _now())


def inspect_with(token: str, keys: IssuerKeys, now: datetime) -> License:
    """:func:`inspect` with a caller-supplied clock and trust anchor."""
    return inspect_token(token, keys, now)


__all__ = [
    "Supso",
    "SupsoError",
    "ErrorCode",
    "IssuerKeys",
    "TRUSTED_ED25519_KEYS_HEX",
    "TRUSTED_MLDSA44_KEYS_HEX",
    "License",
    "Organization",
    "Project",
    "Order",
    "Status",
    "Valid",
    "Grace",
    "Unlicensed",
    "is_licensed",
    "license_of",
    "Enforcement",
    "DEFAULT_GRACE_PERIOD_DAYS",
    "initialize_project",
    "require_license",
    "check_license",
    "verify_token",
    "verify_token_with",
    "inspect",
    "inspect_with",
    "grace_message",
    "status_message",
]
