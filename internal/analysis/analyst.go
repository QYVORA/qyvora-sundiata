// Package analysis wires the assessment into pipeline stages: directory
// parse, identity discovery, account enumeration, authentication posture,
// credential exposure, privilege and relationship mapping, secret discovery,
// attack-path analysis, rule analysis and risk calculation. Env is the shared
// state handed to every rule. Analysis is read-only; live identity sources
// are not implemented and are refused with an honest error.
package analysis

import (
	"context"
	"sort"

	"github.com/QYVORA/qyvora-sundiata/internal/errors"
	"github.com/QYVORA/qyvora-sundiata/internal/events"
	"github.com/QYVORA/qyvora-sundiata/internal/evidence"
	"github.com/QYVORA/qyvora-sundiata/internal/identity"
	"github.com/QYVORA/qyvora-sundiata/internal/pipeline"
	"github.com/QYVORA/qyvora-sundiata/internal/risk"
	"github.com/QYVORA/qyvora-sundiata/internal/rules"
	"github.com/QYVORA/qyvora-sundiata/pkg/models"
)

// Env is the environment passed to every rule during one assessment.
type Env struct {
	Directory *identity.Directory
	Events    *events.Stream
	Store     *evidence.Store
	Config    map[string]any
}

// AddEvidence records an observation backing a finding, hashed and stored.
func (e *Env) AddEvidence(kind models.EvidenceKind, source, sourceID, target, data string) models.Evidence {
	ev := models.Evidence{
		Kind:     kind,
		Source:   source,
		SourceID: sourceID,
		Target:   target,
		Data:     data,
		State:    models.StateObserved,
	}
	if e.Store != nil {
		e.Store.Add(ev)
	}
	ev.Hash = models.HashContent(ev.Data)
	return ev
}

// Stages returns the full offline/simulation assessment pipeline.
func Stages(reg *rules.Registry, cfg map[string]any, maxEntries int) []pipeline.Stage {
	return []pipeline.Stage{
		{
			ID: "discovery", Name: "Identity discovery",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				d, err := currentDirectory(step)
				if err != nil {
					return err
				}
				if step.Events != nil {
					step.Events.Info(events.IdentityDiscovered, map[string]any{
						"tenant": d.Tenant, "source": string(d.Source),
						"identities": len(d.Identities), "groups": len(d.Groups),
					})
				}
				return nil
			},
		},
		{
			ID: "enumeration", Name: "Account enumeration",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				d, err := currentDirectory(step)
				if err != nil {
					return err
				}
				emitted := 0
				for _, id := range d.Identities {
					if emitted >= maxEntries {
						break
					}
					if step.Events != nil {
						step.Events.Info(events.AccountEnumerated, map[string]any{
							"id": id.ID, "kind": id.Kind, "enabled": id.Enabled,
						})
					}
					emitted++
				}
				step.Result.Assets = len(d.Identities)
				if step.Events != nil {
					step.Events.Info(events.AccountEnumerated, map[string]any{
						"total": len(d.Identities), "reported": emitted,
					})
				}
				return nil
			},
		},
		{
			ID: "authentication", Name: "Authentication posture",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				d, err := currentDirectory(step)
				if err != nil {
					return err
				}
				noMFA := identity.PrivilegedWithoutMFA(d)
				neverExpire := identity.PasswordNeverExpires(d)
				if step.Events != nil {
					step.Events.Info(events.AuthAnalyzed, map[string]any{
						"privileged_without_mfa": len(noMFA),
						"password_never_expires": len(neverExpire),
					})
				}
				return nil
			},
		},
		{
			ID: "credentials", Name: "Credential exposure",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				d, err := currentDirectory(step)
				if err != nil {
					return err
				}
				exposed := identity.ExposedCredentials(d.Credentials)
				overdue := identity.RotationOverdue(d.Credentials, d.Modified)
				if step.Events != nil {
					step.Events.Info(events.CredentialExposed, map[string]any{
						"exposed": len(exposed), "rotation_overdue": len(overdue),
					})
				}
				return nil
			},
		},
		{
			ID: "privilege", Name: "Privilege mapping",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				d, err := currentDirectory(step)
				if err != nil {
					return err
				}
				sensitive := identity.SensitiveMemberships(d)
				reuse := identity.CredentialReuse(d.Credentials)
				if step.Events != nil {
					step.Events.Info(events.PrivilegeMapped, map[string]any{
						"sensitive_memberships": len(sensitive),
						"reused_credentials":    len(reuse),
					})
				}
				if step.Events != nil {
					for _, r := range d.Relationships {
						step.Events.Info(events.RelationshipMapped, map[string]any{
							"from": r.From, "relation": r.Relation, "to": r.To,
						})
					}
				}
				return nil
			},
		},
		{
			ID: "secrets", Name: "Secret artifact discovery",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				d, err := currentDirectory(step)
				if err != nil {
					return err
				}
				secrets := identity.ExposedSecrets(d.Secrets)
				if step.Events != nil {
					step.Events.Info(events.SecretDiscovered, map[string]any{
						"secret_artifacts": len(secrets), "redacted": true,
					})
				}
				return nil
			},
		},
		{
			ID: "attack-paths", Name: "Attack-path analysis",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				d, err := currentDirectory(step)
				if err != nil {
					return err
				}
				paths := identity.HighValueAttackPaths(d.AttackPaths)
				if step.Events != nil {
					for _, p := range paths {
						step.Events.Info(events.AttackPathFound, map[string]any{
							"start": p.Start, "end": p.End, "shortest": p.Shortest,
						})
					}
				}
				return nil
			},
		},
		{
			ID: "analysis", Name: "Rule analysis",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				if reg == nil {
					return nil
				}
				d, err := currentDirectory(step)
				if err != nil {
					return err
				}
				env := &Env{
					Directory: d,
					Events:    step.Events,
					Store:     step.Evidence,
					Config:    cfg,
				}
				sink := rules.NewSink()
				if err := reg.RunProfile(ctx, env, sink, profileOf(cfg)); err != nil {
					return err
				}
				for _, f := range sink.List() {
					if step.Target != nil {
						f.TargetID = step.Target.ID
					}
					step.Result.Findings = append(step.Result.Findings, *f)
					if step.Events != nil {
						step.Events.Info(events.FindingDiscovered, map[string]any{
							"rule_id": f.RuleID, "title": f.Title, "severity": string(f.Severity),
							"objects": f.Objects,
						})
					}
				}
				return nil
			},
		},
		{
			ID: "risk", Name: "Risk calculation",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				var assessor risk.Assessor
				score, level := assessor.Assess(ctx, headings(step.Result.Findings))
				step.Result.Score = score
				step.Result.Level = level
				step.Result.Evidence = step.Evidence.List()
				sort.Slice(step.Result.Evidence, func(i, j int) bool {
					return step.Result.Evidence[i].Hash < step.Result.Evidence[j].Hash
				})
				if step.Events != nil {
					step.Events.Info(events.RiskCalculated, map[string]any{
						"score": score, "level": level, "findings": len(step.Result.Findings),
					})
				}
				return nil
			},
		},
	}
}

func headings(fs []models.Finding) []*models.Finding {
	out := make([]*models.Finding, len(fs))
	for i := range fs {
		out[i] = &fs[i]
	}
	return out
}

func currentDirectory(step *pipeline.Step) (*identity.Directory, error) {
	if step == nil || step.Target == nil {
		return nil, errors.NewExitError(1, "assessment requires a directory or simulation target")
	}
	v, err := step.Cached("input:identity", func() (any, error) {
		if step.Sim {
			return identity.Simulate(identity.SimulationOptions{}), nil
		}
		if step.Target.Type != models.TargetSnapshot {
			return nil, errors.NewExitError(1, "unsupported target: live identity source collection is not implemented; provide a directory file")
		}
		d, err := identity.LoadFile(step.Target.Value)
		if err != nil {
			return nil, errors.WrapExitError(1, "loading directory", err)
		}
		return d, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*identity.Directory), nil
}

// profileOf returns the named assessment profile, defaulting to standard
// when the configuration does not select one.
func profileOf(cfg map[string]any) string {
	if p, ok := cfg["profile"].(string); ok && p != "" {
		return p
	}
	// No profile selected falls through to the full rule set so pipeline
	// invocations without an explicit profile behave exactly as before the
	// profile filter existed. The CLI always resolves an explicit profile.
	return ""
}
