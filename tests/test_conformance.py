"""Cross-language conformance suite — the Python consumer of the shared
``spec/`` vectors. Mirrors ``../rust/tests/conformance.rs`` and
``../typescript/test/conformance.test.ts``. Resolves the vectors from
``$SUPSO_VECTORS_DIR``, then a sibling ``../spec``; skips (rather than fails) if
neither exists.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

import pytest

from supso import IssuerKeys, License, Supso, verify_token_with
from supso.errors import SupsoError

TOKEN_FILES = [
    "valid.json",
    "expired.json",
    "wrong-project.json",
    "tampered.json",
    "bad-ed25519.json",
    "bad-mldsa.json",
    "unsupported-schema.json",
    "malformed.json",
    "bare-date-expiry.json",
]


def _vectors_dir() -> Optional[Path]:
    env = os.environ.get("SUPSO_VECTORS_DIR")
    if env and Path(env).exists():
        return Path(env)
    sibling = Path(__file__).resolve().parent.parent.parent / "spec"
    return sibling if (sibling / "test-keys.json").exists() else None


def _parse_instant(s: str) -> datetime:
    normalized = s[:-1] + "+00:00" if s.endswith("Z") else s
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _load_keys(directory: Path) -> IssuerKeys:
    raw = json.loads((directory / "test-keys.json").read_text())
    return IssuerKeys.from_hex(raw["ed25519"], raw["mldsa44"])


def _load_cases(path: Path) -> list[dict[str, Any]]:
    return json.loads(path.read_text())


def _assert_license(case: dict[str, Any], got: License) -> None:
    want = case["license"]
    assert want is not None, f"[{case['name']}] vector is missing license assertions"
    assert got.organization.id == want["organization"]["id"], f"[{case['name']}] org.id"
    assert got.organization.name == want["organization"]["name"], f"[{case['name']}] org.name"
    assert got.order.id == want["order"]["id"], f"[{case['name']}] order.id"
    assert got.order.expires_at == _parse_instant(
        want["order"]["expires_at"]
    ), f"[{case['name']}] order.expires_at"
    if "seats" in want:
        assert got.seats() == want["seats"], f"[{case['name']}] seats"
    if "tier" in want:
        assert got.tier() == want["tier"], f"[{case['name']}] tier"


def _token_cases() -> Iterator[tuple[str, dict[str, Any]]]:
    directory = _vectors_dir()
    if directory is None:
        return
    for file in TOKEN_FILES:
        path = directory / file
        if not path.exists():
            continue
        for case in _load_cases(path):
            yield f"{file}:{case['name']}", case


def _grace_cases() -> Iterator[tuple[str, dict[str, Any]]]:
    directory = _vectors_dir()
    if directory is None:
        return
    path = directory / "grace.json"
    if not path.exists():
        return
    for case in _load_cases(path):
        yield case["name"], case


@pytest.mark.skipif(_vectors_dir() is None, reason="no vectors (set SUPSO_VECTORS_DIR or populate ../spec)")
@pytest.mark.parametrize("case_id,case", list(_token_cases()), ids=lambda v: v if isinstance(v, str) else "")
def test_token_vectors(case_id: str, case: dict[str, Any]) -> None:
    keys = _load_keys(_vectors_dir())
    now = _parse_instant(case["now"])
    if case["expect"] == "valid":
        license = verify_token_with(case["token"], case["project"], keys, now)
        _assert_license(case, license)
    elif case["expect"] == "error":
        with pytest.raises(SupsoError) as excinfo:
            verify_token_with(case["token"], case["project"], keys, now)
        assert excinfo.value.code == case["error"], f"[{case['name']}] error code"
    else:
        pytest.fail(f"[{case['name']}] token vector has unexpected expect={case['expect']}")


@pytest.mark.skipif(_vectors_dir() is None, reason="no vectors (set SUPSO_VECTORS_DIR or populate ../spec)")
@pytest.mark.parametrize("case_id,case", list(_grace_cases()), ids=lambda v: v if isinstance(v, str) else "")
def test_grace_vectors(case_id: str, case: dict[str, Any]) -> None:
    keys = _load_keys(_vectors_dir())
    with tempfile.TemporaryDirectory(prefix="supso-conformance-") as tmp:
        (Path(tmp) / f"{case['project']}.cert").write_text(case["token"])
        status = (
            Supso.project(case["project"])
            .issuer_keys(keys)
            .certificate_path(tmp)
            .grace_period_days(case.get("grace_period_days", 21))
            .enforcement("silent")
            .check_at(_parse_instant(case["now"]))
        )

    expect = case["expect"]
    if expect == "valid":
        assert status.kind == "valid", f"[{case['name']}] expected valid"
        _assert_license(case, status.license)
    elif expect == "grace":
        assert status.kind == "grace", f"[{case['name']}] expected grace"
        _assert_license(case, status.license)
    elif expect == "error":
        assert status.kind == "unlicensed", f"[{case['name']}] expected error"
        assert status.error.code == case["error"], f"[{case['name']}] error code"
    else:
        pytest.fail(f"[{case['name']}] grace vector has unexpected expect={expect}")
