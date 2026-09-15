package identity_test

import (
	"testing"
	"time"

	"github.com/QYVORA/qyvora-sundiata/internal/identity"
)

func TestRotationOverdueIsDateAware(t *testing.T) {
	cr := []identity.Credential{
		{ID: "unpadded", RotatedAt: "2026-1-1", RotationDue: "2026-2-1"},
		{ID: "zero-padded", RotatedAt: "2026-01-01", RotationDue: "2026-02-01"},
		{ID: "current", RotatedAt: "2026-01-01", RotationDue: "2026-06-01"},
	}
	out := identity.RotationOverdue(cr, "2026-03-01T00:00:00Z")
	if len(out) != 2 {
		t.Fatalf("overdue = %+v, want unpadded and zero-padded (non-lexical correctness)", out)
	}
	for _, o := range out {
		if o.ID == "current" {
			t.Error("credential with future rotation due must not be overdue")
		}
	}
}

func TestRecentMFAWindow(t *testing.T) {
	modified := "2026-03-01T00:00:00Z"
	recent := identity.RecentMFA(identity.AuthPolicy{LastMFA: "2026-02-20T00:00:00Z"}, modified)
	if !recent {
		t.Error("MFA used 9 days ago must be recent")
	}
	stale := identity.RecentMFA(identity.AuthPolicy{LastMFA: "2025-06-01T00:00:00Z"}, modified)
	if stale {
		t.Error("MFA used ten months ago must not be recent")
	}
	none := identity.RecentMFA(identity.AuthPolicy{}, modified)
	if none {
		t.Error("empty last_mfa must never be recent")
	}
	implicit := time.Now().UTC().Truncate(time.Second).Add(-15 * 24 * time.Hour).Format(time.RFC3339)
	if !identity.RecentMFA(identity.AuthPolicy{LastMFA: implicit}, time.Now().UTC().Format(time.RFC3339)) {
		t.Error("window boundary sanity check failed")
	}
}

func TestComputeAttackPathsReachesSensitiveGroups(t *testing.T) {
	d := identity.Simulate(identity.SimulationOptions{})
	paths := identity.ComputeAttackPaths(d)
	if len(paths) == 0 {
		t.Fatal("simulation graph must contain attack paths")
	}
	for _, p := range paths {
		if p.Sensitivity != "high" && p.Sensitivity != "domain_admin" {
			t.Errorf("path %s ends at non-sensitive %s (%s)", p.ID, p.End, p.Sensitivity)
		}
		if p.Steps != len(p.Chain)-1 || p.Steps < 1 {
			t.Errorf("path %s steps %d vs chain %v", p.ID, p.Steps, p.Chain)
		}
		if p.End != p.Chain[len(p.Chain)-1] || p.Start != p.Chain[0] {
			t.Errorf("path %s chain endpoints do not match", p.ID)
		}
	}
	var hasLegacy bool
	for _, p := range paths {
		if p.Start == "id-legacy-admin" && p.End == "grp-dm" {
			hasLegacy = true
		}
	}
	if !hasLegacy {
		t.Error("legacy-admin is a direct domain-admin member and must appear as a one-step path")
	}
}

func TestComputeAttackPathsIsDeterministic(t *testing.T) {
	a := identity.Simulate(identity.SimulationOptions{})
	b := identity.Simulate(identity.SimulationOptions{})
	pa := identity.ComputeAttackPaths(a)
	pb := identity.ComputeAttackPaths(b)
	if len(pa) != len(pb) {
		t.Fatalf("path counts differ: %d vs %d", len(pa), len(pb))
	}
	for i := range pa {
		if pa[i].ID != pb[i].ID || pa[i].Start != pb[i].Start || pa[i].End != pb[i].End {
			t.Errorf("path %d differs: %+v vs %+v", i, pa[i], pb[i])
		}
	}
}

func TestComputeAttackPathsSkipsDisabledIntermediary(t *testing.T) {
	d := identity.Simulate(identity.SimulationOptions{})
	for i := range d.Relationships {
		if d.Relationships[i].From == "id-svcexport" {
			d.Relationships[i].Relation = "impersonates"
		}
	}
	// finance-export-bot -> ex-contractor (disabled) -> grp-finance must not exist
	for _, p := range identity.ComputeAttackPaths(d) {
		if p.Start == "id-svcexport" && len(p.Chain) > 2 {
			t.Errorf("disabled identity was traversed in %v", p.Chain)
		}
	}
}

func TestExposedSecretsPolarity(t *testing.T) {
	s := []identity.SecretArtifact{
		{ID: "found", Redacted: true},
		{ID: "clean", Redacted: false},
	}
	out := identity.ExposedSecrets(s)
	if len(out) != 1 || out[0].ID != "found" {
		t.Errorf("redacted=found artifacts must be the ones reported, got %+v", out)
	}
}
