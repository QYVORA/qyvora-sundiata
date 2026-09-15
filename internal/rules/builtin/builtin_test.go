package builtin

import (
	"context"
	"testing"

	"github.com/QYVORA/qyvora-sundiata/internal/analysis"
	"github.com/QYVORA/qyvora-sundiata/internal/identity"
	"github.com/QYVORA/qyvora-sundiata/internal/rules"
)

func TestIsLegacyAdminFlagsDomainAdminMembers(t *testing.T) {
	cases := []identity.Identity{
		{ID: "id-legacy-admin", Name: "legacy-admin", Enabled: true, Groups: []string{"grp-dm"}},
		{ID: "id-legacy-db", Name: "legacy-db-bot", Enabled: true},
		{ID: "id-old-svc", Name: "old-svc", Note: "legacy service account", Enabled: true},
		{ID: "id-moder", Name: "modern", Enabled: true, Admin: true},
		{ID: "id-disabled", Name: "legacy-gone", Enabled: false},
	}
	for _, c := range cases {
		got := isLegacyAdmin(c)
		want := c.ID != "id-moder" && c.ID != "id-disabled"
		if got != want {
			t.Errorf("isLegacyAdmin(%q) = %v, want %v", c.Name, got, want)
		}
	}
}

func TestLegacyCredentialRule(t *testing.T) {
	dir := &identity.Directory{
		Credentials: []identity.Credential{
			{ID: "c1", Identity: "i1", Type: "ntlmv1", Storage: "NTDS"},
			{ID: "c2", Identity: "i2", Type: "password", Storage: "vault"},
			{ID: "c3", Identity: "i3", Type: "LM", Storage: "SAM"},
		},
	}
	env := &analysis.Env{Directory: dir}
	sink := rules.NewSink()
	if err := (&legacyCredential{}).Run(context.Background(), env, sink); err != nil {
		t.Fatalf("run: %v", err)
	}
	if sink.Len() != 2 {
		t.Fatalf("sink = %d findings, want 2 (c1, c3)", sink.Len())
	}
	for _, f := range sink.List() {
		if f.RuleID != "SDT-013" {
			t.Errorf("unexpected rule %s", f.RuleID)
		}
	}
}

func TestAttackPathRuleComputesNotTrusts(t *testing.T) {
	dir := &identity.Directory{
		Identities: []identity.Identity{
			{ID: "start", Name: "start", Enabled: true, Groups: []string{"g"}},
			{ID: "orphan", Name: "orphan", Enabled: true},
		},
		Groups: []identity.Group{
			{ID: "g", Name: "Sensitive", Sensitivity: "high"},
		},
		// Input carries a stale path to a non-sensitive end; the rule must
		// recompute from the graph and ignore it.
		AttackPaths: []identity.AttackPath{
			{ID: "stale", Start: "start", End: "g", Sensitivity: "high", Shortest: true, Steps: 1},
		},
		Credentials: []identity.Credential{
			{ID: "c1", Identity: "orphan", Fingerprint: "f"},
		},
	}
	env := &analysis.Env{Directory: dir}
	sink := rules.NewSink()
	if err := (&attackPath{}).Run(context.Background(), env, sink); err != nil {
		t.Fatalf("run: %v", err)
	}
	if sink.Len() != 1 {
		t.Fatalf("sink = %d findings, want 1", sink.Len())
	}
	if sink.List()[0].RuleID != "SDT-009" {
		t.Errorf("unexpected rule %s", sink.List()[0].RuleID)
	}
}
