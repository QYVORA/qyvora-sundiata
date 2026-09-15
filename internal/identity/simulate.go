package identity

import (
	"time"
)

// SimulationOptions tunes the deterministic demo directory.
type SimulationOptions struct{}

// Simulate returns a deterministic sample directory exercising every analysis
// path: plaintext and unrotated credentials, privileged identities without
// MFA, password never-expiry, credential reuse, secrets in backup/config
// files, excess privilege memberships and an attack path to a sensitive group.
// All identities, credentials and hosts are clearly fake.
func Simulate(opts SimulationOptions) *Directory {
	d := &Directory{
		Schema:   SchemaVersion,
		Tenant:   "acme",
		Source:   SourceAD,
		Domain:   "corp.acme.test",
		ScopeID:  "corp.acme.test/identity",
		Label:    "simulated identity directory - all data fabricated",
		Modified: "2026-03-01T00:00:00Z",
		Identities: []Identity{
			{
				ID: "id-legacy-admin", Name: "legacy-admin", Kind: "user",
				Enabled: true, Admin: true, IsPrivileged: true, MFAEnforced: false,
				PasswordExpires: "2027-01-01T00:00:00Z",
				Groups:          []string{"grp-dm", "grp-ops"},
				Note:            "legacy administrative account with broad roles",
			},
			{
				ID: "id-billing-svc", Name: "billing-svc", Kind: "service_account",
				Enabled: true, Admin: false, IsPrivileged: false, MFAEnforced: false,
				Groups: []string{"grp-api"},
				Note:   "automation account with a static api key",
			},
			{
				ID: "id-svcexport", Name: "finance-export-bot", Kind: "service_account",
				Enabled: true, Admin: false, IsPrivileged: false, MFAEnforced: false,
				Groups: []string{"grp-finance"},
				Note:   "automation account in the finance group",
			},
			{
				ID: "id-alice", Name: "alice", Kind: "user",
				Enabled: true, Admin: false, IsPrivileged: false, MFAEnforced: true,
				PasswordExpires: "2026-12-01T00:00:00Z",
				Groups:          []string{"grp-engineers"},
			},
			{
				ID: "id-deploy-bot", Name: "deploy-bot", Kind: "app",
				Enabled: true, Admin: false, IsPrivileged: false, MFAEnforced: true,
				Groups: []string{"grp-ci"},
				Note:   "ci deployment principal",
			},
			{
				ID: "id-exstaff", Name: "ex-contractor", Kind: "user",
				Enabled: false, Admin: false, IsPrivileged: false, MFAEnforced: false,
				Locked: true, DisabledSince: "2025-11-20T00:00:00Z",
				Groups: []string{"grp-finance"},
				Note:   "disabled contractor still a member of the finance group",
			},
			{
				ID: "id-mansi", Name: "mansi", Kind: "user",
				Enabled: true, Admin: true, IsPrivileged: true, MFAEnforced: true,
				PasswordExpires: "2026-09-15T00:00:00Z",
				Groups:          []string{"grp-dm"},
			},
		},
		Groups: []Group{
			{ID: "grp-dm", Name: "Domain Admins", Sensitivity: "domain_admin", Members: []string{"id-legacy-admin", "id-mansi"},
				Description: "sensitive operational group"},
			{ID: "grp-ops", Name: "Operations", Sensitivity: "high", Members: []string{"id-legacy-admin", "id-mansi"}},
			{ID: "grp-api", Name: "API Access", Sensitivity: "standard", Members: []string{"id-billing-svc", "id-deploy-bot"}},
			{ID: "grp-finance", Name: "Finance", Sensitivity: "high", Members: []string{"id-svcexport", "id-exstaff", "id-alice"}},
			{ID: "grp-engineers", Name: "Engineers", Sensitivity: "standard", Members: []string{"id-alice"}},
			{ID: "grp-ci", Name: "CI/CD Agents", Sensitivity: "standard", Members: []string{"id-deploy-bot"}},
		},
		Credentials: []Credential{
			{ID: "cr-billing-apikey", Identity: "id-billing-svc", Type: "api_key",
				Exposure: "plaintext", Storage: "plaintext in integration config backup",
				DiscoveredBy: "secret-scan", Fingerprint: "a1b2c3d4",
				RotatedAt: "2024-03-01T00:00:00Z", RotationDue: "2024-09-01T00:00:00Z",
				Note: "static api key stored in plaintext and past rotation"},
			{ID: "cr-svcexport-pw", Identity: "id-svcexport", Type: "password",
				Exposure: "encrypted", Storage: "enterprise vault",
				Fingerprint: "e5f6a7b8", RotatedAt: "2025-10-01T00:00:00Z",
				RotationDue: "2026-04-01T00:00:00Z", Note: "shared automation password, reuse detected"},
			{ID: "cr-learn-pw", Identity: "id-exstaff", Type: "password",
				Exposure: "hashed", Storage: "directory store",
				Fingerprint: "e5f6a7b8", Note: "same fingerprint as finance-export-bot (reuse)"},
			{ID: "cr-legacy-ssh", Identity: "id-legacy-admin", Type: "ssh_key",
				Exposure: "memory_only", Storage: "session broker",
				Fingerprint: "77c8d9e0", RotatedAt: "2023-06-01T00:00:00Z",
				RotationDue: "2024-06-01T00:00:00Z", Note: "ssh key not rotated for two years"},
			{ID: "cr-alice-token", Identity: "id-alice", Type: "token",
				Exposure: "encrypted", Storage: "token management system",
				Fingerprint: "11223344", RotatedAt: "2026-02-10T00:00:00Z",
				RotationDue: "2026-03-10T00:00:00Z", Note: "short-lived token"},
		},
		AuthPolicies: []AuthPolicy{
			{Identity: "id-legacy-admin", Requirement: "mfa_optional", SessionHours: 24,
				PasswordMinLength: 8, PasswordNeverExpires: false, LastMFA: "2026-01-30T00:00:00Z"},
			{Identity: "id-billing-svc", Requirement: "none", SessionHours: 24,
				PasswordMinLength: 8, PasswordNeverExpires: true},
			{Identity: "id-mansi", Requirement: "mfa_required", SessionHours: 8,
				PasswordMinLength: 14, LastMFA: "2026-02-28T00:00:00Z", MFAChannel: "push"},
			{Identity: "id-alice", Requirement: "mfa_required", SessionHours: 8,
				PasswordMinLength: 14, LastMFA: "2026-02-27T00:00:00Z", MFAChannel: "otp"},
			{Identity: "id-svcexport", Requirement: "none", SessionHours: 168,
				PasswordMinLength: 8, PasswordNeverExpires: true},
			{Identity: "id-exstaff", Requirement: "mfa_optional", SessionHours: 72,
				PasswordMinLength: 8},
		},
		Relationships: []Relationship{
			{ID: "rel-1", From: "id-legacy-admin", To: "grp-dm", Relation: "member_of", Note: "permanent membership"},
			{ID: "rel-2", From: "id-billing-svc", To: "cr-billing-apikey", Relation: "uses_credential"},
			{ID: "rel-3", From: "id-svcexport", To: "grp-finance", Relation: "member_of"},
			{ID: "rel-4", From: "id-exstaff", To: "grp-finance", Relation: "member_of", Note: "membership not removed on offboarding"},
			{ID: "rel-5", From: "id-svcexport", To: "id-exstaff", Relation: "impersonates", Note: "shared password allows impersonation"},
			{ID: "rel-6", From: "id-deploy-bot", To: "grp-ci", Relation: "member_of"},
			{ID: "rel-7", From: "id-billing-svc", To: "grp-api", Relation: "member_of"},
			{ID: "rel-8", From: "id-legacy-admin", To: "id-billing-svc", Relation: "controls"},
			{ID: "rel-9", From: "id-legacy-admin", To: "cr-legacy-ssh", Relation: "uses_credential"},
		},
		Secrets: []SecretArtifact{
			{ID: "sec-1", Kind: "backup", Location: "backup/jobs/exports/billing-integration-2025-11.zip",
				Redacted: true, CredentialType: "api_key", Note: "plaintext api key in integration backup"},
			{ID: "sec-2", Kind: "env", Location: "deploy/integration.env",
				Redacted: true, CredentialType: "api_key", Note: "environment file committed into repository"},
			{ID: "sec-3", Kind: "script", Location: "scripts/export-sync.ps1",
				Redacted: true, CredentialType: "password", Note: "hardcoded automation password"},
			{ID: "sec-4", Kind: "config", Location: "home/legacy-admin/.ssh/id_rsa",
				Redacted: true, CredentialType: "ssh_key", Note: "private key on shared admin host"},
		},
		AttackPaths: []AttackPath{
			{
				ID: "ap-1", Start: "id-billing-svc",
				Chain: []string{"id-billing-svc", "uses_credential", "cr-billing-apikey", "read", "id-svcexport", "impersonates", "id-exstaff", "member_of", "grp-finance"},
				End:   "grp-finance", Sensitivity: "high", Shortest: true, Steps: 4},
			{
				ID: "ap-2", Start: "id-exstaff",
				Chain: []string{"id-exstaff", "member_of", "grp-finance"},
				End:   "grp-finance", Sensitivity: "high", Shortest: true, Steps: 1},
		},
	}
	normalize(d)
	return d
}

// TimestampedLabel appends a timestamp so generated example files are
// distinguishable; the dataset itself stays deterministic.
func TimestampedLabel(d *Directory, now time.Time) {
	if now.IsZero() {
		return
	}
	d.Label = d.Label + " @" + now.UTC().Format("2006-01-02T15:04:05Z")
}
