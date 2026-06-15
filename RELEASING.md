# Releasing `supso-project`

This library is published to [PyPI](https://pypi.org/project/supso-project/) so
maintainers can `pip install supso-project`. Three names are in play:

| Thing | Value |
|---|---|
| GitHub repo | `SupsoOrg/supso-project-python` |
| PyPI distribution | `supso-project` (what people `pip install`) |
| Import package | `supso` (what they `import`) |

There are two ways to publish: an **automated** GitHub Actions flow (recommended
— no credentials stored anywhere) and a **manual** flow from your laptop. Set up
the automated one once; fall back to manual if you ever need to.

---

## One-time setup (automated, recommended)

PyPI [Trusted Publishing](https://docs.pypi.org/trusted-publishers/) lets GitHub
Actions upload releases over OIDC, so there is no API token to create, store, or
leak.

1. **Create the PyPI project as a "pending" trusted publisher.** Go to
   <https://pypi.org/manage/account/publishing/> and add a publisher with:
   - PyPI Project Name: `supso-project`
   - Owner: `SupsoOrg`
   - Repository name: `supso-project-python`
   - Workflow name: `release.yml`
   - Environment name: `pypi`

   (This works *before* the project exists on PyPI — the first successful
   upload creates it and claims the name.)

2. **Add the release workflow** at `.github/workflows/release.yml` (see
   [Appendix](#appendix-releaseyml) below). Commit and push it.

That's it. From then on, releasing is just a git tag (next section).

---

## Cutting a release

1. **Make sure the suite is green** (against the shared spec vectors):

   ```sh
   pytest
   ```

2. **Bump the version** in `pyproject.toml`. Use
   [semantic versioning](https://semver.org/): patch for fixes, minor for
   backward-compatible additions, major for breaking API changes. PyPI will
   **reject a re-upload of an existing version**, so every release needs a new
   number.

   ```toml
   # pyproject.toml
   version = "1.0.1"
   ```

3. **Commit and tag.** The tag must be `v` + the version.

   ```sh
   git commit -am "Release v1.0.1"
   git tag v1.0.1
   git push origin main --tags
   ```

4. **Publish.**
   - **Automated:** create a GitHub Release for the tag
     (`gh release create v1.0.1 --generate-notes`). The workflow builds and
     uploads to PyPI automatically.
   - **Manual:** see [Manual publishing](#manual-publishing) below.

5. **Verify** the upload installs cleanly from PyPI:

   ```sh
   python -m venv /tmp/verify && /tmp/verify/bin/pip install "supso-project==1.0.1"
   /tmp/verify/bin/python -c "import supso; print('ok')"
   ```

---

## Manual publishing

Use this for the very first upload if you skipped the trusted-publisher setup,
or any time you need to publish from your machine.

1. **Create a PyPI API token** at <https://pypi.org/manage/account/token/>
   (scope it to the `supso-project` project once it exists; use an
   account-wide token for the first upload).

2. **Build** a fresh wheel + sdist:

   ```sh
   rm -rf dist
   uv build
   ```

3. **Check** the artifacts before uploading:

   ```sh
   uvx twine check dist/*
   ```

4. **(Optional) dry-run on TestPyPI** to rehearse without touching real PyPI:

   ```sh
   uv publish --publish-url https://test.pypi.org/legacy/ --token <test-pypi-token>
   # then: pip install --index-url https://test.pypi.org/simple/ supso-project
   ```

5. **Publish to PyPI:**

   ```sh
   uv publish --token <pypi-token>
   # or set UV_PUBLISH_TOKEN in the environment and run `uv publish`
   ```

6. **Tag** the release if you haven't already (step 3 of *Cutting a release*).

---

## Appendix: `release.yml`

Drop this at `.github/workflows/release.yml`. It builds on every published
GitHub Release and uploads to PyPI via the trusted publisher configured above —
no secrets required.

```yaml
name: Release

on:
  release:
    types: [published]

jobs:
  publish:
    runs-on: ubuntu-latest
    environment: pypi
    permissions:
      id-token: write   # required for trusted publishing (OIDC)
    steps:
      - uses: actions/checkout@v4

      - name: Install uv
        uses: astral-sh/setup-uv@v5

      - name: Build
        run: uv build

      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@release/v1
```
