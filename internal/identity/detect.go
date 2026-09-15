package identity

import (
	"strings"
)

// ExposedCredentials returns credentials whose exposure class makes their
// value recoverable by an attacker (plaintext or stored unencrypted).
func ExposedCredentials(cr []Credential) []Credential {
	var out []Credential
	for _, c := range cr {
		switch strings.ToLower(c.Exposure) {
		case "plaintext":
			out = append(out, c)
		}
	}
	return out
}

// RotationOverdue returns credentials past their rotation due date. The
// comparison is lexical against the directory modified stamp, so the dataset
// stays deterministic.
func RotationOverdue(cr []Credential, modified string) []Credential {
	var out []Credential
	for _, c := range cr {
		if c.RotationDue == "" {
			continue
		}
		if c.RotatedAt == "" && c.RotationDue < modified {
			out = append(out, c)
			continue
		}
		if c.RotationDue != "" && c.RotatedAt < c.RotationDue && c.RotationDue < modified {
			out = append(out, c)
		}
	}
	return out
}

// PrivilegedWithoutMFA returns identities that hold privileged or admin roles
// yet have no enforced MFA requirement.
func PrivilegedWithoutMFA(d *Directory) []Identity {
	var out []Identity
	for _, id := range d.Identities {
		if !id.Enabled {
			continue
		}
		priv := id.IsPrivileged || id.Admin
		mfa := id.MFAEnforced
		if p, ok := policyFor(d, id.ID); ok {
			switch p.Requirement {
			case "mfa_required":
				mfa = true
			case "none", "mfa_optional":
				mfa = id.MFAEnforced
			}
		}
		if priv && !mfa {
			out = append(out, id)
		}
	}
	return out
}

func policyFor(d *Directory, id string) (AuthPolicy, bool) {
	for _, p := range d.AuthPolicies {
		if p.Identity == id {
			return p, true
		}
	}
	return AuthPolicy{}, false
}

// PasswordNeverExpires returns identities whose auth policy disables password
// expiry, especially privileged ones.
func PasswordNeverExpires(d *Directory) []AuthPolicy {
	var out []AuthPolicy
	for _, p := range d.AuthPolicies {
		if p.PasswordNeverExpires {
			out = append(out, p)
		}
	}
	return out
}

// DisabledWithActiveCredential returns disabled identities that still own
// credentials or retain group membership.
func DisabledWithActiveCredential(d *Directory) []Identity {
	var out []Identity
	for _, id := range d.Identities {
		if id.Enabled {
			continue
		}
		hasCred := false
		for _, c := range d.Credentials {
			if c.Identity == id.ID {
				hasCred = true
				break
			}
		}
		if len(id.Groups) > 0 || hasCred {
			out = append(out, id)
		}
	}
	return out
}

// CredentialReuse finds credentials shared between two or more identities,
// keyed on fingerprint.
type Reuse struct {
	Fingerprint string   `json:"fingerprint"`
	Type        string   `json:"type"`
	Identities  []string `json:"identities"`
}

func CredentialReuse(cr []Credential) []Reuse {
	buckets := map[string]*Reuse{}
	for _, c := range cr {
		if c.Fingerprint == "" {
			continue
		}
		b, ok := buckets[c.Fingerprint]
		if !ok {
			b = &Reuse{Fingerprint: c.Fingerprint, Type: c.Type}
			buckets[c.Fingerprint] = b
		}
		b.Identities = append(b.Identities, c.Identity)
	}
	var out []Reuse
	for _, b := range buckets {
		if len(b.Identities) > 1 {
			out = append(out, *b)
		}
	}
	return out
}

// ExposedSecrets returns secret artifacts flagged as containing plaintext
// credential material (backups, environment files, scripts, configs).
func ExposedSecrets(s []SecretArtifact) []SecretArtifact {
	var out []SecretArtifact
	for _, a := range s {
		if a.Redacted {
			out = append(out, a)
		}
	}
	return out
}

// SensitiveMemberships returns identities with membership in sensitive groups.
func SensitiveMemberships(d *Directory) []Relationship {
	var out []Relationship
	for _, r := range d.Relationships {
		if r.Relation != "member_of" {
			continue
		}
		if g, ok := groupFor(d, r.To); ok && (g.Sensitivity == "high" || g.Sensitivity == "domain_admin") {
			out = append(out, r)
		}
	}
	return out
}

// HighValueAttackPaths returns attack paths ending at high-sensitivity or
// domain-admin groups, shortest-first.
func HighValueAttackPaths(ap []AttackPath) []AttackPath {
	var out []AttackPath
	for _, p := range ap {
		if p.Sensitivity == "high" || p.Sensitivity == "domain_admin" {
			out = append(out, p)
		}
	}
	return out
}

func groupFor(d *Directory, id string) (Group, bool) {
	for _, g := range d.Groups {
		if g.ID == id {
			return g, true
		}
	}
	return Group{}, false
}
