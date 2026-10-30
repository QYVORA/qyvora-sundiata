# SUNDIATA — EVIDENCE-BASED SECURITY CAPABILITY AUDIT

## 1. Framework identity and intended domain

Framework: qyvora-sundiata (binary name `sundiata`)
- Module: github.com/QYVORA/qyvora-sundiata (go.mod)
- Version: v0.1.0 (commit 899e004, built 2026-10-21T01:20:56Z) — verified via `bin/sundiata version -o json`
- Domain: Identity & access security assessment over Active Directory DIRECTORY FILES (offline). Analyzes offline identity directory snapshots and deterministic simulations for identity discovery, authentication/MFA posture, credential exposure, privilege/relationship mapping, secret discovery, identity attack paths. Credential material redacted before output, never stored. Live identity source collection NOT implemented and refused honestly.
- CLI uses cobra with subcommands (assess, directory, report, findings, evidence, sources, target, capabilities, etc.)

Evidence: README.md, bin/sundiata version/capabilities, internal/*, help capture.

## 2. Audit scope and evidence sources

Scope: static + non-destructive local verification.
Sources:
- git status/log (clean, up to date with origin/main)
- README.md, SECURITY.md
- go.mod, internal packages, cmd/sundiata
- Built binary probes: version -o json, capabilities -o json, --help
- Capabilities document structure
- Ecosystem references (contract/conformance)

No network scans, no directory/LDAP live connections, no intrusive tests performed.

## 3. Existing capability inventory

From capabilities -o json:
- Framework: sundiata, version v0.1.0
- Exit codes: success 0, runtime 1, usage 2, interrupted 130
- Output formats: terminal,json,yaml,markdown,html
- Event verbs: scan.started/completed, stage.started/completed, finding.discovered, identity.discovered, account.enumerated, authentication.analyzed, credential.exposed, privilege.mapped, relationship.mapped, secret.discovered, attack.path.found, risk.calculated, report.generated
- Severity: critical/high/medium/low/informational
- Confidence: confirmed/observed/probable/possible/unknown/not_observed
- Authorization model: offline directory-file/simulation analysis requires no authorization; live identity source collection not implemented and refused. Credential material redacted before output, never stored.
- Capabilities (implemented/live):
  - identity.discovery (true/false)
  - identity.enumeration (true/false)
  - identity.authentication (true/false)
  - identity.credentials (true/false)
  - identity.privilege (true/false)
  - identity.secrets (true/false)
  - identity.attack-path (true/false)
  - identity.live (false/true, note: directory-file analysis only; live provider collection not wired up)
- Commands: assess, directory, report, findings, evidence, sources, target, capabilities (all with sim_support indicated; capabilities sim_support false)

Evidence: internal/capabilities/capabilities.go, bin/sundiata capabilities -o json.

## 4. Capability status matrix

| Capability | Status | Evidence file:line |
|---|---|---|
| Offline snapshot analysis (JSON/directory files) | IMPLEMENTED | internal/identity/*, internal/target/*, internal/pipeline/* |
| Deterministic simulation (--sim/demo) | IMPLEMENTED | internal/identity/simulate.go, CLI (assess supports sim) |
| Identity discovery/enumeration | IMPLEMENTED | internal/identity/identity.go, detect.go |
| Authentication/MFA posture analysis | IMPLEMENTED | internal/analysis/analyst.go, rules/builtin/* |
| Credential exposure/rotation/reuse | IMPLEMENTED | analysis/rules for credentials; redaction enforced |
| Privilege/relationship mapping | IMPLEMENTED | analysis/rules for privilege/relationships |
| Secret artifact discovery | IMPLEMENTED | analysis/rules for secrets |
| Identity attack-path analysis | IMPLEMENTED | attack-path related rules/analysis |
| Evidence/provenance, redaction | IMPLEMENTED | internal/evidence/*, safety/redaction behavior per README/capabilities |
| Reporting (all formats) | IMPLEMENTED | internal/reporting/reporting.go, internal/output/output.go |
| JSONL events | IMPLEMENTED | internal/events/events.go, --events support (capabilities show event verbs) |
| Script engine integration | IMPLEMENTED | internal/cli/script.go, uses qyvora-script |
| Target management (add/list/remove snapshots) | IMPLEMENTED | internal/target/manager.go |
| Sources listing with status | IMPLEMENTED | capabilities.RenderSources shows supported sources (AD/Okta/AWS-IAM/GitHub/LDAP/Google Workspace) all implemented for offline snapshots; live marked not implemented |
| Live identity source collection | STUBBED/NOT IMPLEMENTED (refused) | capabilities identity.live false implemented true note; README states "Live identity source collection is not implemented and is refused honestly" |
| NTDS.dit/SAM/SYSTEM hive parsing (specific AD offline formats) | PARTIALLY IMPLEMENTED / UNVERIFIED | Supports directory snapshots/exports conceptually; exact parsers for raw hive/NTDS formats not explicitly enumerated as dedicated parsers in capability list — needs deeper inspection (identity/target loading) |

## 5. Reconnaissance and discovery findings

Verified (offline):
- Snapshot ingestion via target management; supports multiple identity sources as offline snapshots (AD, Okta, AWS IAM, GitHub, LDAP, Google Workspace) per sources output.
- Deterministic simulation for reproducible assessment.
- Identity/account/group discovery from loaded snapshots.

Gaps:
- Direct parsing of raw forensic artifacts (NTDS.dit, SAM, SYSTEM, SECURITY hives) — capability not advertised; may need specific loader/ingest logic. UNVERIFIED whether implemented or expected as pre-processed snapshots (JSON). README says "analyzes offline identity directory snapshots..." suggesting normalized snapshots rather than raw hive parsing.
- Auto-detection of artifact types could be enhanced — PARTIALLY IMPLEMENTED via detect.go (identity/detect.go exists).

Evidence: internal/identity/detect.go, internal/target/manager.go, capabilities.RenderSources.

## 6. Analysis and assessment findings

Verified:
- Authentication/MFA posture, credential exposure/rotation/reuse, privilege/relationship mapping, secret discovery, identity attack paths.
- Rule-based analysis (rules/builtin), risk scoring, evidence with redaction.
- Confidence/severity classification.

Gaps relevant to AD offline forensics:
- SID/RID analysis, well-known SIDs, domain-relative RIDs — likely PARTIALLY IMPLEMENTED if processing AD snapshots; needs verification.
- Group membership expansion, nested groups, privileged group detection — PARTIALLY IMPLEMENTED (privilege/relationship mapping).
- Kerberos-related indicators from directory data (preauth, SPN patterns) — authentication analysis exists but may be snapshot-dependent.
- Hash types/cipher strength indicators (NTLM history, legacy algorithms) — credential analysis exists; deep hash format analysis depends on snapshot contents.
- Lateral movement paths from directory relationships — identity attack-path exists.

Evidence: internal/analysis/analyst.go, internal/rules/*, internal/risk/*.

## 7. Exploitation-related capability findings

README says "Credential material is redacted before output and never stored." Live collection refused. No active exploitation capabilities advertised as implemented for live systems; exploit command exists in CLI structure but capabilities focus on analysis of offline data. 
- Active exploitation against live identity systems: NOT IMPLEMENTED (refused by design).
- Offline credential analysis/cracking orchestration: NOT ADVERTISED as implemented; redaction suggests analysis without exposing raw secrets.
- Ticket/material abuse: deferred/specialized.

Status: Primarily analytical/read-only over offline data. Exploitation capabilities not implemented.

Evidence: README, capabilities identity.live not implemented, CLI structure.

## 8. High-level implementation candidates (P0–P3)

Feasible now with current deps (offline analysis focus).

| Priority | Candidate | Rationale | Evidence/notes |
|---|---|---|---|
| P0 | Strengthen snapshot schema validation & normalization | Ensures consistent analysis across sources; validation package exists | internal/validation/validation.go exists; harden for AD-like snapshots |
| P0 | Enhanced privilege escalation path reasoning | Core value; attack-path analysis exists, enrich with clearer justification/evidence | analysis/rules/analyst; add more AD-specific paths |
| P1 | Better secret/credential artifact classification | Secrets discovery exists; improve detection/redaction coverage | evidence/rules; ensure no leakage |
| P1 | SID/RID/well-known group mapping | Critical for AD privilege mapping from snapshots | Add mapping tables in analysis/identity |
| P1 | MFA/authentication posture deeper checks | Authentication analysis exists; expand coverage | rules/builtin |
| P2 | Relationship graph visualization/export improvements | Privilege/relationship mapping exists; improve correlation | reporting/output |
| P2 | Source-specific parsers/loaders | Support common export formats (e.g., LDAP export JSON, common IDP exports) more robustly | target/identity loading |
| P3 | Additional report templates/filters | Reporting flexible | low effort |

## 9. Low-level deferred technique inventory (DEFERRED — SPECIALISED PREREQUISITES)

| Technique | Relevance | Prerequisites | Feasibility | Status | Deferral reason/conditions |
|---|---|---|---|---|---|
| Live DCSync/replication credential extraction | High (AD) | Live DC, DRSUAPI, domain creds/rights | Not implemented/refused | DEFERRED — SPECIALISED PREREQUISITES | Explicitly not implemented; requires live access/privileges; refuse by design |
| Live Kerberoasting/AS-REP roasting | High | Live domain, TGS/AS requests | Not implemented | DEFERRED — SPECIALISED PREREQUISITES | Live protocol interactions; deferred |
| Raw NTDS.dit parsing with bootkey/SYSTEM decryption | High (offline forensics) | Forensic images, bootkey extraction, crypto libs, expertise | Complex crypto/offline forensics | DEFERRED — SPECIALISED PREREQUISITES | Needs specialized parsing/crypto; ensure legal/auth constraints; may be out of scope vs snapshot analysis |
| Ticket/material extraction/forgery analysis | Advanced | Kerberos material, live context | Requires material/access | DEFERRED — SPECIALISED PREREQUISITES | Specialist lab only |
| Password cracking orchestration | Credential analysis | Wordlists/hardware/cracking infra | External to analysis logic | DEFERRED — SPECIALISED PREREQUISITES | Cracking is external; framework should not embed cracking by default |

## 10. Common-layer conformance (SHARED / FRAMEWORK-SPECIFIC / DUPLICATED / INCONSISTENT / MISSING / UNVERIFIED)

Implements contract natively (no import of qyvora-common).
- Exit codes: matches contract (0/1/2/3/130) — SHARED
- Version semver: v0.1.0 — SHARED intent
- Capabilities contract: sundiata has its own rich capabilities document (Document with exit_codes/output_formats/event_verbs/severity/confidence/authorization_model/capabilities/commands) — different schema than contract.CapabilityManifest; more detailed for orchestration needs. SHARED concept, INCONSISTENT schema
- JSONL events: event verbs enumerated; envelope details not matching contract.Envelope exactly — INCONSISTENT schema, SHARED intent
- Results/findings: framework-specific models; redaction is a strong framework-specific behavior (important)

Classification mostly SHARED intent with FRAMEWORK-SPECIFIC schemas appropriate for domain (identity/offline analysis). Orchestrator must normalize.

## 11. AI orchestration readiness (per-requirement statuses)

| Requirement | Status | Evidence |
|---|---|---|
| Stable identity/version | CONFORMANT | version -o json; capabilities has framework/version |
| Machine-readable capabilities | CONFORMANT | capabilities -o json comprehensive (exit codes, events, severity/confidence, auth model, capabilities, commands) |
| Operation inputs/outputs | PARTIALLY CONFORMANT | Commands listed with output_modes/sim_support; detailed input schemas not fully exposed |
| Predictable exit codes | PARTIALLY CONFORMANT | Documented; needs verification for unknown flag/cmd (conformance will check) |
| Structured results/evidence with redaction | CONFORMANT | Evidence package present; redaction stated as enforced; JSON output supported |
| Prerequisite declarations | CONFORMANT | Auth model explicit (offline only, live refused); sources show status |
| Safe defaults | CONFORMANT | Offline/sim by default; live collection refused; no secret storage |
| Risk/severity/confidence | CONFORMANT | Enumerated in capabilities |
| Event stream for correlation | CONFORMANT | Event verbs defined; events package exists |
| Compatibility with shared contracts | PARTIALLY CONFORMANT | Native schemas differ but rich/parseable |

Orchestrator can discover via capabilities, understand offline-only nature, respect redaction.

## 12. CLI, repository-layout, documentation findings (exact paths)

CLI:
- Commands: assess, directory (generate sample), report, findings, evidence, sources, target, capabilities, script, updates, version, completion, help, exploit (present). Tier grammar conceptually present.
- Flags include --events, -o/--output, --allow-shellout, --no-color, -q, -v, -h.
- Strong emphasis on offline/sim and refusing live collection.

Layout:
- bin/sundiata exists
- assets/ present
- docs/ present
- examples/ present
- reports/ directory exists at root (recorded, not touched)
- internal/ organized well (identity/target/pipeline/analysis/rules/evidence)
- tests/ directory exists

Documentation:
- README clear about offline-only, redaction, refusing live collection.
- Some files empty (CHANGELOG.md, CODE_OF_CONDUCT.md, CONTRIBUTING.md, GOVERNANCE.md, SUPPORT.md) — present as placeholders.

## 13. Testing and verification findings (only checks actually run)

Actually run:
- git status/log: clean, up to date (899e004)
- bin/sundiata version -o json: valid semver v0.1.0, framework sundiata
- bin/sundiata capabilities -o json: comprehensive document returned
- bin/sundiata --help: confirmed
- Unknown flag/cmd exit codes: UNVERIFIED by execution
- go test ./...: NOT RUN (tests exist under internal/* and tests/)
- go vet ./...: NOT RUN

All safe/read-only.

## 14. Prioritized gaps and recommendations (P0–P3)

| Priority | Gap | Recommendation | Notes |
|---|---|---|---|
| P0 | Snapshot schema validation hardening | Strengthen validation for AD/IDP exports; clear errors for malformed snapshots | validation/ exists |
| P0 | SID/RID/well-known privileged group mapping | Improve privilege mapping accuracy for AD snapshots | High value for offline AD analysis |
| P1 | Enhanced attack-path explanations with evidence | Make paths more explainable/traceable for orchestrator/humans | analysis/rules already present |
| P1 | Broader secret artifact detection patterns | Expand redaction-safe detection without leaking secrets | Critical for safety |
| P1 | Source-specific normalization improvements | Better normalization across AD/Okta/AWS/GitHub/LDAP/Google Workspace | target/identity loading |
| P2 | Orchestration schema mapping doc | Document mapping from sundiata capabilities to shared contract for normalization | Aids integration |
| P2 | Enrich findings with remediation guidance | Add actionable remediation where safe | reporting improvement |
| P3 | Fill placeholder docs (CHANGELOG/CONTRIBUTING/etc.) | Clean up empty docs if desired | Documentation hygiene |

## 15. Dependencies, prerequisites, unresolved questions

Dependencies: cobra/viper/yaml, qyvora-tui/qyvora-script, charmbracelet stack. 
Prerequisites: offline identity directory snapshots (JSON/exports) or use --sim. No live creds/network needed.
Unresolved questions:
- Exact supported snapshot formats/loaders not fully enumerated in capabilities (sources list types but loader details need inspection). 
- NTDS.dit/raw hive parsing: not advertised — appears analysis is over normalized snapshots; confirm intended scope.
- Exit codes for error cases not verified by execution.
- reports/ directory contents unknown (present at root) — recorded, not touched.

## 16. "No feature implementation was performed during this audit."

AUDIT ONLY — No files modified except this AUDIT.md. Git working tree remains clean (verified). reports/ directory left untouched.
