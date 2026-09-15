package identity_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/QYVORA/qyvora-sundiata/internal/identity"
)

func TestParseSourceRejectsUnknown(t *testing.T) {
	if identity.ParseSource("salesforce") != "" {
		t.Error("unknown source should parse to empty")
	}
	for _, s := range []string{"active-directory", "okta", "aws-iam", "github", "ldap", "google-workspace"} {
		if identity.ParseSource(s) == "" {
			t.Errorf("known source %s rejected", s)
		}
	}
}

func TestLoadRejectsUnsupportedSchema(t *testing.T) {
	_, err := identity.Load(strings.NewReader(`{"schema":"qyvora.imhotep.snapshot.v1","tenant":"x","source":"okta"}`))
	if err == nil {
		t.Fatal("expected schema rejection")
	}
}

func TestLoadRejectsMissingSource(t *testing.T) {
	_, err := identity.Load(strings.NewReader(`{"schema":"qyvora.sundiata.directory.v1","tenant":"x"}`))
	if err == nil {
		t.Fatal("expected missing-source rejection")
	}
}

func TestSimulateIsDeterministic(t *testing.T) {
	a := identity.Simulate(identity.SimulationOptions{})
	b := identity.Simulate(identity.SimulationOptions{})
	ja, _ := identity.Marshal(a)
	jb, _ := identity.Marshal(b)
	if string(ja) != string(jb) {
		t.Error("simulation is not deterministic")
	}
}

func TestSimulateSurface(t *testing.T) {
	d := identity.Simulate(identity.SimulationOptions{})
	if d.Schema != "qyvora.sundiata.directory.v1" {
		t.Errorf("schema = %s", d.Schema)
	}
	if len(d.Identities) < 5 {
		t.Errorf("expected multiple identities, got %d", len(d.Identities))
	}
	if d.Source == "" {
		t.Error("simulation has no source")
	}
	data, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "password>") {
		t.Error("model must not embed secret values")
	}
}

func TestCredentialsNeverCarryValues(t *testing.T) {
	d := identity.Simulate(identity.SimulationOptions{})
	for _, c := range d.Credentials {
		if strings.Contains(strings.ToLower(c.Storage), "value=") {
			t.Errorf("credential %s embeds a value", c.ID)
		}
	}
}

func TestValidate(t *testing.T) {
	if problems := identity.Simulate(identity.SimulationOptions{}).Validate(); len(problems) > 0 {
		t.Errorf("simulation should validate clean: %v", problems)
	}
	d := &identity.Directory{Schema: identity.SchemaVersion}
	if problems := d.Validate(); len(problems) == 0 {
		t.Error("empty directory should report problems")
	}
}

func TestExposedCredentials(t *testing.T) {
	cr := []identity.Credential{
		{ID: "a", Exposure: "plaintext"},
		{ID: "b", Exposure: "encrypted"},
		{ID: "c", Exposure: "plaintext"},
	}
	out := identity.ExposedCredentials(cr)
	if len(out) != 2 {
		t.Errorf("exposed count = %d, want 2", len(out))
	}
}

func TestRotationOverdue(t *testing.T) {
	cr := []identity.Credential{
		{ID: "late", RotatedAt: "2025-01-01", RotationDue: "2025-06-01"},
		{ID: "fresh", RotatedAt: "2026-01-01", RotationDue: "2026-06-01"},
		{ID: "none", RotatedAt: "2026-01-01"},
	}
	out := identity.RotationOverdue(cr, "2026-03-01T00:00:00Z")
	if len(out) != 1 || out[0].ID != "late" {
		t.Errorf("overdue = %+v, want only late", out)
	}
}

func TestPrivilegedWithoutMFA(t *testing.T) {
	d := identity.Simulate(identity.SimulationOptions{})
	bad := identity.PrivilegedWithoutMFA(d)
	names := map[string]bool{}
	for _, id := range bad {
		names[id.Name] = true
	}
	if !names["legacy-admin"] {
		t.Error("legacy-admin should be privileged without MFA")
	}
	if names["mansi"] {
		t.Error("mansi has MFA enforced and should not be listed")
	}
}

func TestPasswordNeverExpires(t *testing.T) {
	d := identity.Simulate(identity.SimulationOptions{})
	out := identity.PasswordNeverExpires(d)
	if len(out) < 2 {
		t.Errorf("expected at least 2 never-expire policies, got %d", len(out))
	}
}

func TestDisabledWithActiveCredential(t *testing.T) {
	d := identity.Simulate(identity.SimulationOptions{})
	out := identity.DisabledWithActiveCredential(d)
	var found bool
	for _, id := range out {
		if id.Name == "ex-contractor" {
			found = true
		}
	}
	if !found {
		t.Error("ex-contractor is disabled with stale membership and should be listed")
	}
}

func TestCredentialReuse(t *testing.T) {
	d := identity.Simulate(identity.SimulationOptions{})
	reuse := identity.CredentialReuse(d.Credentials)
	if len(reuse) == 0 {
		t.Fatal("expected shared-credential reuse in simulation")
	}
	for _, r := range reuse {
		if len(r.Identities) < 2 {
			t.Errorf("reuse %s has <2 identities", r.Fingerprint)
		}
	}
}

func TestSensitiveMembershipsIncludeDisabled(t *testing.T) {
	d := identity.Simulate(identity.SimulationOptions{})
	rels := identity.SensitiveMemberships(d)
	found := false
	for _, r := range rels {
		if r.From == "id-exstaff" {
			found = true
		}
	}
	if !found {
		t.Error("disabled contractor membership in finance group not flagged")
	}
}

func TestHighValueAttackPaths(t *testing.T) {
	d := identity.Simulate(identity.SimulationOptions{})
	paths := identity.HighValueAttackPaths(d.AttackPaths)
	if len(paths) == 0 {
		t.Error("expected high-value attack paths in simulation")
	}
}

func TestSecretsAreRedacted(t *testing.T) {
	d := identity.Simulate(identity.SimulationOptions{})
	for _, s := range d.Secrets {
		if !s.Redacted {
			t.Errorf("secret artifact %s is not marked redacted", s.ID)
		}
		if strings.Contains(s.Location, "api_key=") {
			t.Errorf("secret artifact %s leaks a value", s.ID)
		}
	}
}

func TestCounts(t *testing.T) {
	d := identity.Simulate(identity.SimulationOptions{})
	c := d.Counts()
	if c.Identities != len(d.Identities) || c.Groups != len(d.Groups) {
		t.Error("counts mismatch")
	}
}
