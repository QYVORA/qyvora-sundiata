// Package builtin registers the sundiata rule set. Every rule reads only the
// provided analysis Env — the identity directory — and produces
// machine-readable findings with attached evidence. Credential material is
// never printed: fingerprint prefixes only travel through rules.
package builtin

import (
	"context"
	"strings"

	"github.com/QYVORA/qyvora-sundiata/internal/analysis"
	"github.com/QYVORA/qyvora-sundiata/internal/events"
	"github.com/QYVORA/qyvora-sundiata/internal/identity"
	"github.com/QYVORA/qyvora-sundiata/internal/rules"
	"github.com/QYVORA/qyvora-sundiata/pkg/models"
)

// All returns the rules implicit in a stock assessment.
func All() []rules.Rule {
	return []rules.Rule{
		&plaintextCredential{},
		&rotationOverdue{},
		&privilegedNoMFA{},
		&passwordNeverExpires{},
		&disabledWithCredential{},
		&credentialReuse{},
		&secretInArtifact{},
		&excessPrivilege{},
		&attackPath{},
		&excessiveImpersonation{},
		&legacyAdmin{},
		&longSession{},
	}
}

// metadata assembles a rule Meta with sane defaults for this rule set.
func metadata(id, name, category, description, recommendation string, sev models.Severity) rules.Meta {
	return rules.Meta{
		ID:                id,
		Name:              name,
		Category:          category,
		Description:       description,
		DefaultSeverity:   sev,
		DefaultConfidence: models.ConfidenceObserved,
		Recommendation:    recommendation,
	}
}

// newFinding fills the derived fields of a finding uniformly.
func newFinding(m rules.Meta, env *analysis.Env, objects []string, attrs map[string]string, ev ...models.Evidence) *models.Finding {
	return &models.Finding{
		RuleID:         m.ID,
		Title:          m.Name,
		Category:       m.Category,
		Description:    m.Description,
		Recommendation: m.Recommendation,
		Severity:       m.DefaultSeverity,
		Confidence:     m.DefaultConfidence,
		Status:         models.StatusDetected,
		State:          models.StateObserved,
		Objects:        objects,
		Attributes:     attrs,
		Evidence:       ev,
		Timestamp:      models.Now(),
	}
}

// ---------------------------------------------------------------------------
// Credential exposure

type plaintextCredential struct{}

func (r *plaintextCredential) Meta() rules.Meta {
	return metadata("SDT-001", "Plaintext credential exposure", "credentials",
		"At least one credential is stored or recovered in plaintext, meaning its "+
			"value is readably exposed to anyone who reaches the storage location.",
		"Retire the exposed credential immediately, rotate the underlying secret, and "+
			"enforce vaulted storage with access logging for all credential material.",
		models.SeverityCritical)
}

func (r *plaintextCredential) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for _, c := range identity.ExposedCredentials(env.Directory.Credentials) {
		ev := env.AddEvidence(models.EvidenceObservation, "credentials", c.ID,
			c.Identity, "credential stored in plaintext (value redacted)")
		if env.Events != nil {
			env.Events.Info(events.CredentialExposed, map[string]any{
				"credential_id": c.ID, "exposure": c.Exposure, "redacted": true,
			})
		}
		sink.Add(newFinding(r.Meta(), env, []string{"credential:" + c.ID},
			map[string]string{
				"identity": c.Identity, "type": c.Type, "exposure": c.Exposure,
			}, ev))
	}
	return nil
}

type rotationOverdue struct{}

func (r *rotationOverdue) Meta() rules.Meta {
	return metadata("SDT-002", "Credential rotation overdue", "credentials",
		"Credentials have passed their rotation due date, widening the window in "+
			"which a leaked or reused secret remains valid.",
		"Rotate every overdue credential now, then enforce automated rotation with "+
			"warning and expiry deadlines.",
		models.SeverityMedium)
}

func (r *rotationOverdue) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for _, c := range identity.RotationOverdue(env.Directory.Credentials, env.Directory.Modified) {
		ev := env.AddEvidence(models.EvidenceObservation, "credentials", c.ID,
			c.Identity, "credential rotation is overdue")
		sink.Add(newFinding(r.Meta(), env, []string{"credential:" + c.ID},
			map[string]string{"identity": c.Identity, "rotation_due": c.RotationDue}, ev))
	}
	return nil
}

type credentialReuse struct{}

func (r *credentialReuse) Meta() rules.Meta {
	return metadata("SDT-006", "Credential reuse across identities", "credentials",
		"The same credential fingerprint is shared by more than one identity, letting "+
			"compromise of one account authenticate as the other.",
		"Stop sharing credentials; issue per-identity secrets and revoke the shared one.",
		models.SeverityHigh)
}

func (r *credentialReuse) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for _, reuse := range identity.CredentialReuse(env.Directory.Credentials) {
		ev := env.AddEvidence(models.EvidenceObservation, "credentials", reuse.Fingerprint,
			strings.Join(reuse.Identities, ","), "shared credential fingerprint (values redacted)")
		if env.Events != nil {
			env.Events.Info(events.CredentialExposed, map[string]any{
				"fingerprint": reuse.Fingerprint, "identities": reuse.Identities, "redacted": true,
			})
		}
		sink.Add(newFinding(r.Meta(), env, []string{"credential-fp:" + reuse.Fingerprint},
			map[string]string{"type": reuse.Type, "identities": strings.Join(reuse.Identities, ",")}, ev))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Authentication posture

type privilegedNoMFA struct{}

func (r *privilegedNoMFA) Meta() rules.Meta {
	return metadata("SDT-003", "Privileged identity without MFA", "authentication",
		"An identity holding admin or privileged roles has no enforced multi-factor "+
			"authentication, so a stolen password alone grants privileged access.",
		"Enforce MFA for every privileged identity and audit for exceptions on a "+
			"monthly cycle.",
		models.SeverityHigh)
}

func (r *privilegedNoMFA) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for _, id := range identity.PrivilegedWithoutMFA(env.Directory) {
		ev := env.AddEvidence(models.EvidenceObservation, "authentication", id.ID,
			id.Name, "privileged identity without enforced MFA")
		if env.Events != nil {
			env.Events.Info(events.AuthAnalyzed, map[string]any{
				"identity": id.ID, "mfa_enforced": false, "privileged": true,
			})
		}
		sink.Add(newFinding(r.Meta(), env, []string{"identity:" + id.ID},
			map[string]string{"name": id.Name, "admin": boolStr(id.Admin)}, ev))
	}
	return nil
}

type passwordNeverExpires struct{}

func (r *passwordNeverExpires) Meta() rules.Meta {
	return metadata("SDT-004", "Password never expires", "authentication",
		"An account policy disables password expiry, allowing stale or compromised "+
			"passwords to remain valid indefinitely.",
		"Define a credential lifetime for the affected accounts and migrate them to "+
			"managed identities where possible.",
		models.SeverityMedium)
}

func (r *passwordNeverExpires) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for _, p := range identity.PasswordNeverExpires(env.Directory) {
		name := env.Directory.Tenant
		for _, id := range env.Directory.Identities {
			if id.ID == p.Identity {
				name = id.Name
			}
		}
		ev := env.AddEvidence(models.EvidenceObservation, "authentication", p.Identity,
			name, "password never expires for this policy")
		sink.Add(newFinding(r.Meta(), env, []string{"policy:" + p.Identity},
			map[string]string{"identity": name, "min_length": itoa(p.PasswordMinLength)}, ev))
	}
	return nil
}

type longSession struct{}

func (r *longSession) Meta() rules.Meta {
	return metadata("SDT-012", "Excessive session lifetime", "authentication",
		"An account policy grants sessions measured in days, widening the exposure of "+
			"any stolen session token.",
		"Reduce interactive session lifetime and require reauthentication for "+
			"sensitive actions.",
		models.SeverityLow)
}

func (r *longSession) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for _, p := range env.Directory.AuthPolicies {
		if p.SessionHours <= 24 {
			continue
		}
		name := env.Directory.Tenant
		for _, id := range env.Directory.Identities {
			if id.ID == p.Identity {
				name = id.Name
			}
		}
		ev := env.AddEvidence(models.EvidenceObservation, "authentication", p.Identity,
			name, "session lifetime exceeds 24 hours")
		sink.Add(newFinding(r.Meta(), env, []string{"policy:" + p.Identity},
			map[string]string{"identity": name, "session_hours": itoa(p.SessionHours)}, ev))
	}
	return nil
}

type disabledWithCredential struct{}

func (r *disabledWithCredential) Meta() rules.Meta {
	return metadata("SDT-005", "Disabled identity retains access", "lifecycle",
		"A disabled or offboarded identity still owns credentials or group membership, "+
			"leaving a back door once access is reviewed again.",
		"Complete the offboarding checklist: revoke credentials and remove group "+
			"membership when disabling an identity.",
		models.SeverityMedium)
}

func (r *disabledWithCredential) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for _, id := range identity.DisabledWithActiveCredential(env.Directory) {
		ev := env.AddEvidence(models.EvidenceObservation, "lifecycle", id.ID,
			id.Name, "disabled identity retains credentials or membership")
		sink.Add(newFinding(r.Meta(), env, []string{"identity:" + id.ID},
			map[string]string{"name": id.Name, "groups": itoa(len(id.Groups))}, ev))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Secrets and privilege

type secretInArtifact struct{}

func (r *secretInArtifact) Meta() rules.Meta {
	return metadata("SDT-007", "Secret material in files", "secrets",
		"Credentials or secret material were discovered in backups, environment "+
			"files, scripts or configuration files. Values are redacted in all output.",
		"Rotate every secret referenced by the artifacts, purge the files, and add "+
			"secret scanning to the pipeline that produced them.",
		models.SeverityHigh)
}

func (r *secretInArtifact) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for _, s := range identity.ExposedSecrets(env.Directory.Secrets) {
		ev := env.AddEvidence(models.EvidenceArtifact, "secrets", s.ID,
			s.Location, "secret material present (value redacted)")
		if env.Events != nil {
			env.Events.Info(events.SecretDiscovered, map[string]any{
				"artifact": s.ID, "kind": s.Kind, "redacted": true,
			})
		}
		sink.Add(newFinding(r.Meta(), env, []string{"secret:" + s.ID},
			map[string]string{"kind": s.Kind, "location": s.Location, "redacted": "true"}, ev))
	}
	return nil
}

type excessPrivilege struct{}

func (r *excessPrivilege) Meta() rules.Meta {
	return metadata("SDT-008", "Excess privilege membership", "privilege",
		"Identities hold membership in high-sensitivity or administrative groups "+
			"with no evident business need, expanding the blast radius of compromise.",
		"Review and reduce group memberships to the minimum needed; use time-limited "+
			"privileged access where possible.",
		models.SeverityHigh)
}

func (r *excessPrivilege) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for _, rel := range identity.SensitiveMemberships(env.Directory) {
		name := rel.From
		group := rel.To
		for _, id := range env.Directory.Identities {
			if id.ID == rel.From {
				name = id.Name
			}
		}
		for _, g := range env.Directory.Groups {
			if g.ID == rel.To {
				group = g.Name
			}
		}
		ev := env.AddEvidence(models.EvidenceObservation, "privilege", rel.ID,
			rel.From, "membership in sensitive group "+group)
		if env.Events != nil {
			env.Events.Info(events.PrivilegeMapped, map[string]any{
				"identity": rel.From, "group": rel.To, "sensitivity": groupSensitivity(env.Directory, rel.To),
			})
		}
		sink.Add(newFinding(r.Meta(), env, []string{"relationship:" + rel.ID},
			map[string]string{"identity": name, "group": group, "note": rel.Note}, ev))
	}
	return nil
}

type excessiveImpersonation struct{}

func (r *excessiveImpersonation) Meta() rules.Meta {
	return metadata("SDT-010", "Impersonation relationship", "privilege",
		"An identity is permitted to impersonate another, including disabled or "+
			"shared-credential accounts. Impersonation doubles the lateral-movement "+
			"surface when a single account is compromised.",
		"Grant impersonation only through a workflow that logs the target, purpose "+
			"and time window; revoke standing impersonation.",
		models.SeverityMedium)
}

func (r *excessiveImpersonation) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for _, rel := range env.Directory.Relationships {
		if rel.Relation != "impersonates" {
			continue
		}
		ev := env.AddEvidence(models.EvidenceObservation, "privilege", rel.ID,
			rel.From, "identity may impersonate "+rel.To)
		sink.Add(newFinding(r.Meta(), env, []string{"relationship:" + rel.ID},
			map[string]string{"from": rel.From, "to": rel.To, "note": rel.Note}, ev))
	}
	return nil
}

type legacyAdmin struct{}

func (r *legacyAdmin) Meta() rules.Meta {
	return metadata("SDT-011", "Legacy privileged account", "privilege",
		"An aging administrative identity holds broad roles as a permanent standing "+
			"grant, a classic persistence and takeover target.",
		"Replace standing legacy administration with rebaselined, MFA-protected "+
			"permission sets and periodic owner review.",
		models.SeverityHigh)
}

func (r *legacyAdmin) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for _, id := range env.Directory.Identities {
		if !isLegacyAdmin(id) {
			continue
		}
		ev := env.AddEvidence(models.EvidenceObservation, "privilege", id.ID,
			id.Name, "legacy privileged account with standing roles")
		sink.Add(newFinding(r.Meta(), env, []string{"identity:" + id.ID},
			map[string]string{"name": id.Name, "kind": id.Kind}, ev))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Attack path

type attackPath struct{}

func (r *attackPath) Meta() rules.Meta {
	return metadata("SDT-009", "Identity attack path to sensitive group", "attack-path",
		"A compute identity can reach a high-sensitivity or administrative group "+
			"through credential and relationship hops, enabling privilege escalation.",
		"Break the shortest path: rotate or revoke the original credential, remove "+
			"the impersonation edge, and re-run path analysis until the group is unreachable.",
		models.SeverityCritical)
}

func (r *attackPath) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for _, p := range identity.HighValueAttackPaths(env.Directory.AttackPaths) {
		ev := env.AddEvidence(models.EvidenceObservation, "attack-path", p.ID,
			p.Start, "attack path to "+p.End+" ("+itoa(p.Steps)+" steps)")
		if env.Events != nil {
			env.Events.Info(events.AttackPathFound, map[string]any{
				"start": p.Start, "end": p.End, "shortest": p.Shortest,
			})
		}
		sink.Add(newFinding(r.Meta(), env, []string{"attack-path:" + p.ID},
			map[string]string{
				"start": p.Start, "end": p.End, "shortest": boolStr(p.Shortest),
				"steps": itoa(p.Steps),
			}, ev))
	}
	return nil
}

func isLegacyAdmin(id identity.Identity) bool {
	if !id.Enabled {
		return false
	}
	if id.Name == "legacy-admin" || strings.HasPrefix(id.Name, "legacy-") {
		return true
	}
	for _, g := range id.Groups {
		if g == "grp-dm" {
			return false
		}
	}
	return false
}

func groupSensitivity(d *identity.Directory, id string) string {
	for _, g := range d.Groups {
		if g.ID == id {
			return g.Sensitivity
		}
	}
	return "standard"
}

func boolStr(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
