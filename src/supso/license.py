"""The data a verified license carries, and the outcome types the API returns."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping, Optional, Union

from .errors import SupsoError

_DAY_SECONDS = 86_400


@dataclass(frozen=True)
class Organization:
    """The buyer the license was issued to."""

    id: str
    name: str


@dataclass(frozen=True)
class Project:
    """The product the license is for, read from ``metadata.project``.

    Verification requires :attr:`slug` to equal the project slug the maintainer
    asked about.
    """

    id: str
    #: The stable, URL-safe handle a maintainer integrates against (e.g. ``"acme-db"``).
    slug: str
    #: Human-readable display name.
    name: str


@dataclass(frozen=True)
class Order:
    """The order behind the license and when it lapses."""

    id: str
    #: Expiry as a timezone-aware UTC :class:`~datetime.datetime`.
    expires_at: datetime


@dataclass(frozen=True)
class License:
    """A successfully-verified license."""

    organization: Organization
    project: Project
    order: Order
    #: Issuer-attached metadata: ``seats``, ``tier``, ``features``, …
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def seats(self) -> Optional[int]:
        """``metadata.seats`` as an integer, if present."""
        s = self.metadata.get("seats")
        # bool is a subclass of int — exclude it.
        if isinstance(s, int) and not isinstance(s, bool):
            return s
        return None

    def tier(self) -> Optional[str]:
        """``metadata.tier`` as a string, if present."""
        t = self.metadata.get("tier")
        return t if isinstance(t, str) else None

    def features(self) -> list[str]:
        """``metadata.features`` as a list of strings (empty if absent)."""
        f = self.metadata.get("features")
        if isinstance(f, list):
            return [x for x in f if isinstance(x, str)]
        return []

    def has_feature(self, feature: str) -> bool:
        """Whether ``metadata.features`` contains ``feature``."""
        return feature in self.features()

    def days_remaining(self, now: datetime) -> int:
        """Whole days from ``now`` until expiry (negative once expired)."""
        delta = self.order.expires_at - now
        secs = delta.total_seconds()
        # Truncate toward zero, matching the Rust/TS implementations.
        return int(secs / _DAY_SECONDS)


# ---- Status: the outcome of the non-raising `check` call ----


@dataclass(frozen=True)
class Valid:
    """A live, fully-valid license."""

    license: License
    kind: str = "valid"


@dataclass(frozen=True)
class Grace:
    """A lapsed license still honored within the grace window (SPEC §7)."""

    license: License
    expired_at: datetime
    grace_until: datetime
    kind: str = "grace"


@dataclass(frozen=True)
class Unlicensed:
    """No acceptable license was found; :attr:`error` says why."""

    error: SupsoError
    kind: str = "unlicensed"


#: The outcome of a non-raising :meth:`Supso.check`.
Status = Union[Valid, Grace, Unlicensed]


def is_licensed(status: Status) -> bool:
    """``True`` for ``valid`` or ``grace``."""
    return status.kind in ("valid", "grace")


def license_of(status: Status) -> Optional[License]:
    """The verified license for ``valid``/``grace``, else ``None``."""
    return None if isinstance(status, Unlicensed) else status.license
