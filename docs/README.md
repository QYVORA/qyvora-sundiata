# SUNDIATA — Documentation Index

**Status:** `CURRENT` (this index) · **Last reviewed:** 2026-09-30

SUNDIATA is identity & access assessment over Active Directory directory files.

## Pipeline and rules

```
IDENTITY → ACCOUNT → AUTHENTICATION → CREDENTIALS → PRIVILEGE → SECRETS → ATTACK-PATH → RISK
```

Rules: SDT-001…SDT-013.

## Safety boundary

`identity.live` is disabled by default and the corresponding safety
operation is refused — `sundiata.live.source` is refused. Secrets are redacted in output.

## What is actually written

**Authoritative for this tool, and currently non-empty:**

- `../README.md` — purpose, install, quick start, CLI, capabilities, safety

Cross-project contracts (authoritative, non-empty):

- [QYVORA-ECOSYSTEM.md](../../../../knowledge/qyvora-docs/09-technical/cross-project/QYVORA-ECOSYSTEM.md)
- [QYVORA-TOOL-OUTPUT-SPEC.md](../../../../knowledge/qyvora-docs/09-technical/cross-project/QYVORA-TOOL-OUTPUT-SPEC.md)
- [07-products overview](../../../../knowledge/qyvora-docs/07-products/sundiata/)

## Known gap — placeholder files (`UNVERIFIED`)

**26 Markdown files in this repository are zero-byte placeholders.**
They are tracked in git but contain no content, so they must not be
cited as documentation. This file is the honest index; the placeholders
are left in place rather than filled with placeholder prose, and are
tracked for completion.

Repository root:

- `CHANGELOG.md`
- `CODE_OF_CONDUCT.md`
- `CONTRIBUTING.md`
- `GOVERNANCE.md`
- `SECURITY.md`
- `SUPPORT.md`

`docs/` (20 placeholders):

- `docs/Account-Relationships.md`
- `docs/Architecture.md`
- `docs/Attack-Paths.md`
- `docs/Authentication.md`
- `docs/CLI.md`
- `docs/Configuration.md`
- `docs/Console.md`
- `docs/Credentials.md`
- `docs/Development.md`
- `docs/Evidence.md`
- `docs/Getting-Started.md`
- `docs/Identity-Discovery.md`
- `docs/Installation.md`
- `docs/Privileges.md`
- `docs/Reporting.md`
- `docs/Roadmap.md`
- `docs/Secrets.md`
- `docs/Security-Model.md`
- `docs/Targets.md`
- `docs/Validation.md`

Related root files that are **also** zero-byte: `LICENSE`, `NOTICE`.
Until they are populated, this tool's license is `UNVERIFIED` even
though its README shows a license badge. See
[`00-audit/LEGAL_REVIEW_REGISTER.md`](../../../../knowledge/qyvora-docs/00-audit/LEGAL_REVIEW_REGISTER.md).
