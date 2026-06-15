# supso (Python)

Supported Source license checks for your project, from [Supported Source](https://supso.org).

Use this library to enforce licensing, so you'll know who is using your project, and can
be sure they're paying for your paid licenses. It's just one call at startup to confirm 
the code running your software holds a valid license. The check is 100% offline, so there's
no network, no license server to run, nothing phoning home. 

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

### Hard enforcement (raises when missing license)

This is what we suggest you do.

```python
import supso
supso.require_license("acme-db")
```

### Soft enforcement (does not raise errors)

If you would like to handle it yourself, use `is_licensed` and then write your own logic.

```python
import supso

status = supso.check_license("acme-db")  # logs a notice on grace/failure
if supso.is_licensed(status):
    ...  # valid or within grace — run normally
```

`status` is one of `supso.Valid`, `supso.Grace`, or `supso.Unlicensed`
(distinguish via `status.kind` or `isinstance`).

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
