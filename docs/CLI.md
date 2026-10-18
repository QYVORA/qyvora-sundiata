# CLI Reference

`sundiata` follows the shared QYVORA tier grammar:

```
sundiata <tier> <module> [<action>] [target] [flags]
```

`<tier>` is one of `recon`, `exploit`, or `report`. Every pre-tier command remains available as a hidden alias.

## recon

_No recon-tier modules._

## exploit

_No exploit-tier modules._

## report

_No report-tier modules._

## Utilities

| Command | Purpose |
|---------|---------|
| `sundiata assess` | run the analysis pipeline against a directory or simulation |
| `sundiata directory` | generate a deterministic sample identity directory |
| `sundiata evidence` | inspect the latest assessment evidence |
| `sundiata findings` | inspect the latest assessment findings |
| `sundiata rules` | list the registered analysis rules |
| `sundiata sources` | list supported identity sources and their status |
| `sundiata target` | manage assessment targets (directory files and simulation) |
| `sundiata tui` | start the interactive terminal application |
| `docs script <file>` | Run a `.qs` script with the shared scripting engine (`run`/`build` subcommands) |
