# Releasing siemlab

A release is a Git tag. Pushing a tag `vX.Y.Z` runs `.github/workflows/release.yml`, which
builds the sdist and wheel, checks that the tag matches the package version, and attaches both
to a GitHub release. Publishing to PyPI is a second, optional job.

## Checklist

1. Update `__version__` in `src/siemlab/__init__.py` (the only place the version lives).
2. Move the "Unreleased" notes in `CHANGELOG.md` under the new version and date, and update
   the comparison links at the bottom.
3. Run the same checks as CI:

   ```bash
   siemlab wazuh5 fetch-schema
   siemlab validate --strict
   ruff check src tests && ruff format --check src tests && mypy
   pytest -W error --cov
   python -m build && twine check --strict dist/*
   ```

4. Commit, then tag and push:

   ```bash
   git tag -a v0.3.0 -m "siemlab 0.3.0"
   git push origin v0.3.0
   ```

5. Check the release page: it should list `siemlab-X.Y.Z.tar.gz` and
   `siemlab-X.Y.Z-py3-none-any.whl`.

## Publishing to PyPI (optional)

The release workflow publishes with PyPI's
[trusted publishing](https://docs.pypi.org/trusted-publishers/): no API token is stored
anywhere. One-time setup:

1. On PyPI, add a pending trusted publisher for the project `siemlab`: owner `exosphere8`,
   repository `siem-home-lab`, workflow `release.yml`, environment `pypi`.
2. In the GitHub repository, create the environment `pypi` (Settings > Environments) and,
   if you like, require your approval for it.
3. Set the repository variable `PUBLISH_TO_PYPI` to `true` (Settings > Secrets and
   variables > Actions > Variables).

Until step 3 is done, the PyPI job is skipped and releases only go to GitHub.

## Before selling

The code is MIT-licensed today, which allows anyone who receives a copy to redistribute it.
If you want to sell licenses rather than support or services, decide on the license before
the first paid release, and keep THIRD_PARTY_NOTICES.md with every copy you distribute.
