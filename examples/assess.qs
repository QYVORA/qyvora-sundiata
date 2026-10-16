# assess.qs — a runnable example of the shared QYVORA scripting engine driving
# sundiata's offline identity analysis pipeline.
#
#     sundiata script run examples/assess.qs
#
# sundiata is offline and deterministic, so this needs no target setup: with no
# directory configured the binding runs the built-in simulation.

# Select the deterministic simulation (the default when no target is set).
set assess.sim -> "true"

# Run the full analysis pipeline. Capability ids such as "identity.discovery"
# run the pipeline up to and including that stage.
run assess

# Read live properties from the completed run via $(...).
echo -> "target   = $(target.name)"
echo -> "assets   = $(result.assets)"
echo -> "findings = $(result.findings)"
echo -> "score    = $(result.score) ($(result.level))"

# Show capability metadata and write a Markdown report artifact.
show identity.discovery
report -> "sundiata-report"

echo -> "done"
