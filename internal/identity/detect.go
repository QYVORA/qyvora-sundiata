package identity

import (
	"strings"
	"time"
)

// FeatureMFAWindow is the recency window inside which observed MFA usage is
// considered active evidence in the directory.
const FeatureMFAWindow = 30 * 24 * time.Hour

// timeOf parses a timestamp in any of the layouts sundiata accepts. Directory
// data may carry RFC3339 stamps or plain YYYY-MM-DD dates.
func timeOf(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// before compares two timestamps chronologically. Rank keys derived from the
// digit runs make mixed or unpadded formats ("2026-1-1" vs "2026-01-01")
// compare correctly; dates that cannot be ranked fall back to a lexical
// comparison so output stays deterministic.
func before(a, b string) bool {
	ar, aok := stampRank(a)
	br, bok := stampRank(b)
	if aok && bok {
		return ar < br
	}
	return a < b
}

// stampRank builds a zero-padded chronological key from the digit runs of a
// date-ish stamp (year, then two-digit month/day/time components). It returns
// false for strings that carry no full date.
func stampRank(s string) (string, bool) {
	runs := digitRuns(s)
	if len(runs) < 3 || len(runs[0]) != 4 {
		return "", false
	}
	pad := func(r string, width int) string {
		for len(r) < width {
			r = "0" + r
		}
		if len(r) > width {
			r = r[:width]
		}
		return r
	}
	rank := pad(runs[0], 4)
	for _, r := range runs[1:] {
		rank += pad(r, 2)
	}
	return rank, true
}

func digitRuns(s string) []string {
	var out []string
	start := -1
	for i := 0; i < len(s); i++ {
		d := s[i] >= '0' && s[i] <= '9'
		if d && start < 0 {
			start = i
		}
		if !d && start >= 0 {
			out = append(out, s[start:i])
			start = -1
		}
	}
	if start >= 0 {
		out = append(out, s[start:])
	}
	return out
}

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

// RotationOverdue returns credentials past their rotation due date. Stamps are
// compared chronologically (not lexically), so mixed or unpadded date formats
// still evaluate correctly and the result stays deterministic.
func RotationOverdue(cr []Credential, modified string) []Credential {
	var out []Credential
	for _, c := range cr {
		if c.RotationDue == "" {
			continue
		}
		if c.RotatedAt == "" && before(c.RotationDue, modified) {
			out = append(out, c)
			continue
		}
		if c.RotatedAt != "" && before(c.RotatedAt, c.RotationDue) && before(c.RotationDue, modified) {
			out = append(out, c)
		}
	}
	return out
}

// RecentMFA reports whether an auth policy records MFA usage inside the
// window ending at the directory modified stamp. It lets callers distinguish
// "no enforcement at all" from "used in practice but not enforced".
func RecentMFA(p AuthPolicy, modified string) bool {
	t, ok := timeOf(p.LastMFA)
	if !ok {
		return false
	}
	ref, ok := timeOf(modified)
	if !ok {
		return false
	}
	return !t.Before(ref.Add(-FeatureMFAWindow))
}

// PrivilegedWithoutMFA returns identities that hold privileged or admin roles
// yet have no enforced MFA requirement. Lookups are map-backed so large
// directories are O(n) rather than O(n²).
func PrivilegedWithoutMFA(d *Directory) []Identity {
	policy := map[string]AuthPolicy{}
	for _, p := range d.AuthPolicies {
		if _, exists := policy[p.Identity]; !exists {
			policy[p.Identity] = p
		}
	}
	var out []Identity
	for _, id := range d.Identities {
		if !id.Enabled {
			continue
		}
		priv := id.IsPrivileged || id.Admin
		mfa := id.MFAEnforced
		if p, ok := policy[id.ID]; ok {
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
	owned := map[string]bool{}
	for _, c := range d.Credentials {
		owned[c.Identity] = true
	}
	var out []Identity
	for _, id := range d.Identities {
		if id.Enabled {
			continue
		}
		if len(id.Groups) > 0 || owned[id.ID] {
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
	var order []string
	for _, c := range cr {
		if c.Fingerprint == "" {
			continue
		}
		b, ok := buckets[c.Fingerprint]
		if !ok {
			b = &Reuse{Fingerprint: c.Fingerprint, Type: c.Type}
			buckets[c.Fingerprint] = b
			order = append(order, c.Fingerprint)
		}
		b.Identities = append(b.Identities, c.Identity)
	}
	var out []Reuse
	for _, fp := range order {
		if b := buckets[fp]; len(b.Identities) > 1 {
			out = append(out, *b)
		}
	}
	return out
}

// ExposedSecrets returns secret artifacts flagged as containing plaintext
// credential material (backups, environment files, scripts, configs). The
// artifact's Redacted flag is the discovery stamp: true means a secret was
// detected and its value redacted before storage, so redacted artifacts are
// exactly the ones reported.
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
	sensitive := map[string]bool{}
	for _, g := range d.Groups {
		if g.Sensitivity == "high" || g.Sensitivity == "domain_admin" {
			sensitive[g.ID] = true
		}
	}
	var out []Relationship
	for _, r := range d.Relationships {
		if r.Relation != "member_of" {
			continue
		}
		if sensitive[r.To] {
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

// ComputeAttackPaths derives, from the directory graph itself, the shortest
// path from every enabled identity to the nearest high-sensitivity or
// domain-admin group. Edges are group memberships (identity.Groups, group
// member lists and member_of relationships) and identity-to-identity
// impersonation; shared-credential reuse adds the same escalation edge its
// owners share. Disabled identities are not traversable.
//
// Attack paths are computed here rather than trusted from the input document
// so analysis is self-contained and always reflects the loaded graph. The
// returned paths are shortest-first: BFS from all sensitive groups over the
// reversed graph yields the minimal hop count per start.
func ComputeAttackPaths(d *Directory) []AttackPath {
	enabled := map[string]bool{}
	order := make([]string, 0, len(d.Identities))
	for _, id := range d.Identities {
		if id.Enabled {
			enabled[id.ID] = true
			order = append(order, id.ID)
		}
	}

	var edges [][2]string
	edgeSet := map[string]bool{}
	addEdge := func(a, b string) {
		if a == b {
			return
		}
		key := a + "\x00" + b
		if edgeSet[key] {
			return
		}
		edgeSet[key] = true
		edges = append(edges, [2]string{a, b})
	}

	for _, id := range d.Identities {
		if !enabled[id.ID] {
			continue
		}
		for _, g := range id.Groups {
			addEdge(id.ID, g)
		}
	}
	for _, g := range d.Groups {
		for _, m := range g.Members {
			if enabled[m] {
				addEdge(m, g.ID)
			}
		}
	}
	for _, r := range d.Relationships {
		if !enabled[r.From] {
			continue
		}
		switch r.Relation {
		case "member_of":
			if !enabled[r.To] {
				addEdge(r.From, r.To)
			}
		case "impersonates":
			if enabled[r.To] {
				addEdge(r.From, r.To)
			}
		}
	}

	fpOwners := map[string][]string{}
	for _, c := range d.Credentials {
		if c.Fingerprint == "" || !enabled[c.Identity] {
			continue
		}
		fpOwners[c.Fingerprint] = append(fpOwners[c.Fingerprint], c.Identity)
	}
	for _, owners := range fpOwners {
		for i := 0; i < len(owners); i++ {
			for j := i + 1; j < len(owners); j++ {
				addEdge(owners[i], owners[j])
				addEdge(owners[j], owners[i])
			}
		}
	}

	groupSens := map[string]string{}
	var targets []string
	for _, g := range d.Groups {
		groupSens[g.ID] = g.Sensitivity
		if g.Sensitivity == "high" || g.Sensitivity == "domain_admin" {
			targets = append(targets, g.ID)
		}
	}

	rev := map[string][]string{}
	for _, e := range edges {
		rev[e[1]] = append(rev[e[1]], e[0])
	}

	dist := map[string]int{}
	next := map[string]string{}
	queue := make([]string, 0, len(targets))
	for _, t := range targets {
		dist[t] = 0
		queue = append(queue, t)
	}
	for len(queue) > 0 {
		u := queue[0]
		queue = queue[1:]
		du := dist[u]
		for _, v := range rev[u] {
			if _, seen := dist[v]; seen {
				continue
			}
			dist[v] = du + 1
			next[v] = u
			queue = append(queue, v)
		}
	}

	var out []AttackPath
	for _, id := range order {
		if _, reachable := dist[id]; !reachable {
			continue
		}
		chain := []string{id}
		end := ""
		for {
			n := next[chain[len(chain)-1]]
			chain = append(chain, n)
			if dist[n] == 0 {
				end = n
				break
			}
		}
		out = append(out, AttackPath{
			ID:          "path:" + id + ":" + end,
			Start:       id,
			Chain:       chain,
			End:         end,
			Sensitivity: groupSens[end],
			Shortest:    true,
			Steps:       len(chain) - 1,
		})
	}
	return out
}
