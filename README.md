# supso (Python)

Offline license checks for your project, from
[Supported Source](https://supso.org).

Add one call at startup to confirm the person running your software holds a valid
license for it. The check is **100% offline** — no network, no license server to
run, nothing phoning home. And the library **never shuts your app down**: it
tells you the result and you decide what to do.

```python
import supso

license = supso.require_license("acme-db")  # raises if unlicensed
print(f"licensed to {license.organization.name}, {license.seats()} seats")
```

## Install

```sh
pip install supso-project
```

The package imports as `supso`:

```python
import supso
```

## Usage

### Hard enforcement (raises)

```python
import supso

try:
    license = supso.require_license("acme-db")
    print(f"licensed to {license.organization.name}, {license.seats()} seats")
except supso.SupsoError as e:
    # e.code is the canonical reason: "expired", "wrong_project", "no_certificate", …
    print(f"license check failed ({e.code}): {e}")
    # your app decides whether to degrade, nag, or exit — the library never does.
```

### Soft enforcement (never raises)

```python
import supso

status = supso.check_license("acme-db")  # logs a notice on grace/failure
if supso.is_licensed(status):
    ...  # valid or within grace — run normally
```

`status` is one of `supso.Valid`, `supso.Grace`, or `supso.Unlicensed`
(distinguish via `status.kind` or `isinstance`).

### Configure once, then call bare

```python
import supso

supso.initialize_project("acme-db", grace_period_days=30)
license = supso.require_license()   # uses the configured project
status = supso.check_license()
```

### Gate on tier, seats, or features

```python
from supso import Supso

license = (
    Supso.project("acme-db")
    .require_tier("enterprise")
    .require_seats(25)
    .require_feature("audit-log")
    .grace_period_days(30)
    .certificate_path("/etc/acme/license.cert")  # optional explicit path
    .verify()
)
```

### Verify a raw token

```python
import supso

license = supso.verify_token(token_string, "acme-db")  # no disk search, no grace
```

## Where licenses are found

When you don't pass a token, the library looks for a `*.cert` file (each holding
one license) in this order:

1. an explicit path — the `certificate_path(...)` option or the
   `SUPSO_LICENSE_PATH` environment variable (authoritative; no fallback);
2. `~/.supso/license_certificates/`;
3. `./.supso/license_certificates/`.

A current license always wins. If none is current but one lapsed recently, it is
honored as `Grace` (default window 21 days) so your app keeps running while you
prompt the user to renew.

## Errors

Every failure is a `supso.SupsoError` carrying a stable `code` so you can branch
on the reason: `malformed`, `base64`, `bad_ed25519_signature`,
`bad_mldsa_signature`, `invalid_json`, `unsupported_schema`, `bad_timestamp`,
`expired`, `wrong_project`, `requirement_not_met`, `no_certificate`,
`none_valid`, `bad_trusted_key`.

## Development

```sh
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"
pytest
```

## License

Apache-2.0. See [`LICENSE-APACHE`](./LICENSE-APACHE).
