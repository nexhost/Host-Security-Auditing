# Delivery status and maintenance roadmap

## Implemented

- Phase 1: project packaging, configuration, safe logging, errors, SQLAlchemy/SQLite foundation, PySide6 main window, shared application service, CLI, installer, and core documentation.
- Phase 2: authorization/scope validation, allow/deny lists, target limits, fixed Nmap profiles, safe subprocess invocation, Nmap XML parsing, evidence preservation, and inventory persistence.
- Phase 3: dashboard totals, inventory tables, discovery form, background worker, cancellation, demo loader, and data-backed navigation.
- Phase 4: exposure and banner rules plus opt-in TLS analysis. Open ports never prove a vulnerability.
- Phase 5: CPE normalization, provider-neutral CVE correlation, CVSS classification, null and memory providers.
- Phase 6: documented HSA risk engine and persisted per-asset score.
- Phase 7: evidence-linked NIST CSF, CIS and ISO control mappings.
- Phase 8: JSON, CSV, HTML and optional WeasyPrint PDF reports with hashes.
- Phase 9: reproducible fingerprints and scan comparison.
- Phase 10: opt-in Wazuh, n8n and explicitly confirmed MISP adapters plus offline mocks.
- Phase 11: additive database migrations, PyInstaller spec, installers, tests and security documentation.

## Next increments

1. Add CI matrices for Linux GUI smoke testing and PostgreSQL.
2. Expand the rule/control catalogs and add a production CVE provider with caching and API rate controls.
3. Add richer charts, accessibility review, localization, and signed release artifacts.
4. Replace additive MVP migrations with Alembic before the first long-lived production schema.

Ruff and mypy are configured in `pyproject.toml` but must be installed through the `dev` extra before those checks can run.
