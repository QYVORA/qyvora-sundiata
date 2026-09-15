package analysis_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/QYVORA/qyvora-sundiata/internal/analysis"
	"github.com/QYVORA/qyvora-sundiata/internal/events"
	"github.com/QYVORA/qyvora-sundiata/internal/evidence"
	"github.com/QYVORA/qyvora-sundiata/internal/pipeline"
	"github.com/QYVORA/qyvora-sundiata/internal/rules"
	"github.com/QYVORA/qyvora-sundiata/internal/rules/builtin"
	"github.com/QYVORA/qyvora-sundiata/pkg/models"
)

// TestSimulationPipelineProducesFindings runs the full analysis pipeline over
// the deterministic simulation and verifies that every known hazard ships a
// finding.
func TestSimulationPipelineProducesFindings(t *testing.T) {
	reg := rules.NewRegistry()
	reg.RegisterAll(builtin.All()...)

	var evBuf bytes.Buffer
	stream := events.NewStream(&evBuf)
	mgr := evidence.New("")
	step := &pipeline.Step{
		Target:   &models.Target{ID: "sim", Type: models.TargetSimulation},
		Sim:      true,
		Events:   stream,
		Evidence: mgr,
		Result: &models.Result{
			ID: "run", Framework: "sundiata", Target: &models.Target{ID: "sim"}, Sim: true,
		},
	}

	stages := analysis.Stages(reg, map[string]any{}, 1000)
	eng := pipeline.New(stages...)
	if err := eng.Run(context.Background(), step); err != nil {
		t.Fatalf("pipeline run: %v", err)
	}

	found := map[string]bool{}
	for _, f := range step.Result.Findings {
		found[f.RuleID] = true
	}
	expected := []string{"SDT-001", "SDT-002", "SDT-003", "SDT-004", "SDT-005",
		"SDT-006", "SDT-007", "SDT-008", "SDT-009", "SDT-010", "SDT-011", "SDT-012"}
	for _, id := range expected {
		if !found[id] {
			t.Errorf("expected finding %s in simulation", id)
		}
	}
	if mgr.Len() == 0 {
		t.Error("simulation produced no evidence")
	}
	if step.Result.Score <= 0 {
		t.Errorf("expected positive risk score, got %d", step.Result.Score)
	}
	if step.Result.Assets == 0 {
		t.Error("identity discovery found no identities")
	}

	// Event stream must be valid JSONL with the shared envelope.
	for _, line := range bytes.Split(bytes.TrimSpace(evBuf.Bytes()), []byte("\n")) {
		var ev map[string]any
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("invalid event line %q: %v", line, err)
		}
		if ev["framework"] != "sundiata" {
			t.Errorf("event framework = %v", ev["framework"])
		}
	}
}

// TestDirectoryPipelineAcceptsFileTarget exercises the file-path path with a
// raw directory document.
func TestDirectoryPipelineAcceptsFileTarget(t *testing.T) {
	reg := rules.NewRegistry()
	reg.RegisterAll(builtin.All()...)

	doc := `{"schema":"qyvora.sundiata.directory.v1","tenant":"demo","source":"okta",
	  "identities":[{"id":"id-api","name":"api-svc","kind":"service_account","enabled":true}],
	  "credentials":[{"id":"cr-1","identity":"id-api","type":"api_key","exposure":"plaintext","storage":"env file"}]}`
	path := writeTemp(t, doc)

	step := &pipeline.Step{
		Target:   &models.Target{ID: "dir", Type: models.TargetSnapshot, Value: path},
		Events:   events.NewStream(&bytes.Buffer{}),
		Evidence: evidence.New(""),
		Result:   &models.Result{ID: "run", Framework: "sundiata", Target: &models.Target{ID: "dir"}},
	}
	stages := analysis.Stages(reg, map[string]any{}, 1000)
	if err := pipeline.New(stages...).Run(context.Background(), step); err != nil {
		t.Fatalf("directory run: %v", err)
	}
	var got bool
	for _, f := range step.Result.Findings {
		if f.RuleID == "SDT-001" {
			got = true
		}
	}
	if !got {
		t.Error("expected SDT-001 for plaintext credential in directory")
	}
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/directory.json"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
