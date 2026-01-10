# Developer roadmap

This document replaces the phase-by-phase refactor plan with a concise view of where the project stands and what remains. It is the source of truth for engineering priorities; see git history for the archived, long-form plan.

## Current state
- CLI and domains: `mcbridge` exposes `ap` and `dns` commands (status/update/menu) via `mcbridge/cli.py`, backed by domain modules (`ap.py`, `dns.py`, `paths.py`, `common.py`).
- Provisioning: `mcbridge init` orchestrates first-run setup and packages `provision.sh` plus default `knownservers.json` under `mcbridge.resources`.
- Docs: Operator-facing install/usage/provisioning guides live alongside the web console docs, and design rationale is captured in `DESIGN.md`.
- Testing: Core validation and init behaviours are covered in `tests/` (exit codes, validation logging, timeout serialization).

## Remaining gaps and near-term goals
- Packaging/readiness: prepare for publishing (verify `pyproject` metadata, tighten dependencies, and add packaging docs/automation).
- CLI/logic separation: continue keeping CLI thin and reusable; ensure shared helpers live in `common.py`/`paths.py` and are covered by tests.
- Path/config single source: centralize filesystem paths in `paths.py` with minimal hardcoding and env overrides where appropriate.
- Provisioning convergence: keep `mcbridge init` delegating to the same update paths used during normal management and ensure history snapshots remain consistent.
- Documentation hygiene: maintain [PROVISIONING.md](PROVISIONING.md) as the canonical operator guide; avoid duplicating provisioning steps elsewhere.

## Nice-to-haves (deferred)
- Aggregated `mcbridge status` command for AP + DNS.
- Optional global CLI flags (`--debug`, `--version`) and clearer exit-code documentation surfaced in help text.
- Additional validation/rollback tests around service restarts and generated file diffs.
