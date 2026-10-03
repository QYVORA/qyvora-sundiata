# Sundiata

> **Identity & access security assessment framework.**
> A terminal-first console and CLI for offline identity directory analysis:
> account enumeration, authentication and MFA posture, credential exposure,
> privilege mapping, secret discovery and identity attack paths.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Overview

Sundiata is QYVORA's identity & access security assessment framework for
**offline identity directory snapshots** and deterministic simulations.
It runs as a shared terminal-first console **and** a one-shot CLI with
identical commands, and produces evidence-backed findings with transparent
risk scoring. **Credential material is redacted before output and never
stored.** Live identity source collection is **not implemented and is
refused honestly**.

- **One workflow, two surfaces** — the console commands equal the CLI
  commands.
- **Deterministic `--sim`** — fixed dataset exercises every rule, no
  domain controller required, CI-ready.
- **Offline only** — analyzes only the directory files you explicitly
  provide.
- **Redaction first** — credential values are redacted, never stored,
  never printed.
- **Status** — shipped at v0.1.0 (Go 1.26+, MIT).

## Installation

```sh
git clone https://github.com/QYVORA/qyvora-sundiata.git
cd qyvora-sundiata
make build
sudo make install          # /usr/local layout (root)
make install-user          # ~/.local layout (no root)
```

Or build the single static binary directly with the Go toolchain:

```sh
go build ./cmd/sundiata
```

No release assets are published yet; `sundiata updates` installs release
builds once the first verifiable release exists.

## Quickstart

Full assessment, no input required, deterministic:

```sh
sundiata assess --sim       # risk 100/100 (critical)
```

Generate a sample identity directory and assess it:

```sh
sundiata directory --sim
sundiata assess directory.sim.json
```

Interactive console (REPL on a real terminal; stdin piping uses a plain line reader):

```sh
sundiata
assess --sim
findings
evidence
exit
```

Machine-readable output:

```sh
sundiata capabilities -o json
sundiata assess -o json
sundiata report -o json
```

## Commands

```
assess        run the analysis pipeline against a directory or simulation
capabilities  print the machine-readable capability contract
console       start the interactive assessment console
directory     generate a deterministic sample identity directory
evidence      inspect the latest assessment evidence
findings      inspect the latest assessment findings
report        render the latest assessment report from disk
rules         list the registered analysis rules
sources       list supported identity sources and their status
target        manage assessment targets (directory files and simulation)
updates       check for and install verified releases
version       print version and build metadata
```

Global flags: `-o/--output`, `-q/--quiet`, `--no-color`.

## Analysis rules

```
SDT-001  Plaintext credential exposure                   critical
SDT-002  Credential rotation overdue                      medium
SDT-003  Privileged identity without MFA                   high
SDT-004  Password never expires                           medium
SDT-005  Disabled identity retains access                 medium
SDT-006  Credential reuse across identities                high
SDT-007  Secret material in files                          high
SDT-008  Excess privilege membership                       high
SDT-009  Identity attack path to sensitive group          critical
SDT-010  Impersonation relationship                       medium
SDT-011  Legacy privileged account                         high
SDT-012  Excessive session lifetime                         low
SDT-013  Legacy authentication hash exposure               high
```

## Capabilities

`sundiata capabilities` prints the machine-readable contract. The
deliberate boundary: `identity.live` (live identity source collection) is
disabled — **offline directory snapshots only; credential values are
redacted before output and never stored**.

## Documentation

- **[`docs/README.md`](docs/README.md) — the documentation index.** It lists what is
  actually written, and names every zero-byte placeholder file explicitly so
  nothing empty is cited as documentation.
- Pipeline stages, analysis rules and risk scoring: the tool's own
  `capabilities` output, `docs/README.md`, and the QYVORA product overview.
- Cross-project contracts: the QYVORA tool output spec and ecosystem doc.

> **Documentation gap.** This repository still has zero-byte placeholder
> files (including `LICENSE` and `NOTICE`). `docs/README.md` names them all.

## Support

See [SUPPORT.md](SUPPORT.md). Report issues on GitHub.

## Contact

QYVORA OffSec — Tamale, Ghana
Website: https://qyvora.org · Security/Support: qyvorasec@gmail.com

## License

[MIT](LICENSE)

**Authorized use only.** Analyze identity directories you are authorized
to evaluate; no live sources are contacted and credential values are never
stored.