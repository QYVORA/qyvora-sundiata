// Package identity implements the identity and credential snapshot model for
// sundiata. A directory document is a read-only JSON model of an identity
// provider: identities, groups, credential and secret references, auth
// policies, relationships and attack paths.
//
// Credential SECRETS ARE NEVER STORED IN THE MODEL. Credential rows carry only
// type, exposure class, storage location, a fingerprint and rotation state.
// Output is always redacted; analysis never prints plaintext values.
package identity

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// SchemaVersion is the directory document schema this build reads and writes.
const SchemaVersion = "qyvora.sundiata.directory.v1"

// Source identifies the identity provider a directory came from.
type Source string

const (
	SourceAD        Source = "active-directory"
	SourceOkta      Source = "okta"
	SourceAWSIAM    Source = "aws-iam"
	SourceGitHub    Source = "github"
	SourceLDAP      Source = "ldap"
	SourceWorkspace Source = "google-workspace"
	SourceLive      Source = "live"
	SourceNone      Source = ""
)

// ParseSource normalizes a source name, returning None for unknown values.
func ParseSource(s string) Source {
	switch Source(strings.ToLower(strings.TrimSpace(s))) {
	case SourceAD, SourceOkta, SourceAWSIAM, SourceGitHub, SourceLDAP, SourceWorkspace:
		return Source(strings.ToLower(strings.TrimSpace(s)))
	case "live":
		return SourceLive
	default:
		return SourceNone
	}
}

// Directory is the full offline identity surface of one tenant.
type Directory struct {
	Schema        string           `json:"schema"`
	Tenant        string           `json:"tenant"`
	Source        Source           `json:"source"`
	ScopeID       string           `json:"scope_id,omitempty"`
	Domain        string           `json:"domain,omitempty"`
	Label         string           `json:"label,omitempty"`
	Modified      string           `json:"modified,omitempty"`
	Identities    []Identity       `json:"identities,omitempty"`
	Groups        []Group          `json:"groups,omitempty"`
	Credentials   []Credential     `json:"credentials,omitempty"`
	AuthPolicies  []AuthPolicy     `json:"auth_policies,omitempty"`
	Relationships []Relationship   `json:"relationships,omitempty"`
	Secrets       []SecretArtifact `json:"secrets,omitempty"`
	AttackPaths   []AttackPath     `json:"attack_paths,omitempty"`
}

// Identity is one directory principal.
type Identity struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Kind            string   `json:"kind"` // user/service_account/machine/app/group
	Enabled         bool     `json:"enabled"`
	Admin           bool     `json:"admin"`
	IsPrivileged    bool     `json:"is_privileged"`
	MFAEnforced     bool     `json:"mfa_enforced"`
	Locked          bool     `json:"locked,omitempty"`
	DisabledSince   string   `json:"disabled_since,omitempty"`
	PasswordExpires string   `json:"password_expires,omitempty"`
	Groups          []string `json:"groups,omitempty"`
	Note            string   `json:"note,omitempty"`
}

// Group is a directory group with a sensitivity rating.
type Group struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Members     []string `json:"members,omitempty"`
	Sensitivity string   `json:"sensitivity"` // standard/high/domain_admin
	Description string   `json:"description,omitempty"`
}

// Credential is a reference to an identity credential. Raw secret values are
// never represented; only exposure class, storage, fingerprint and rotation.
type Credential struct {
	ID           string `json:"id"`
	Identity     string `json:"identity"`
	Type         string `json:"type"`     // password/api_key/ssh_key/token/certificate/database
	Exposure     string `json:"exposure"` // plaintext/encrypted/hashed/memory_only
	Storage      string `json:"storage"`
	DiscoveredBy string `json:"discovered_by,omitempty"`
	Fingerprint  string `json:"fingerprint,omitempty"` // hash prefix only
	RotatedAt    string `json:"rotated_at,omitempty"`
	RotationDue  string `json:"rotation_due,omitempty"`
	Note         string `json:"note,omitempty"`
}

// AuthPolicy describes the authentication posture of one identity.
type AuthPolicy struct {
	Identity             string `json:"identity"`
	Requirement          string `json:"requirement"` // mfa_required/mfa_optional/none
	SessionHours         int    `json:"session_hours"`
	PasswordMinLength    int    `json:"password_min_length"`
	PasswordNeverExpires bool   `json:"password_never_expires"`
	LastMFA              string `json:"last_mfa,omitempty"`
	MFAChannel           string `json:"mfa_channel,omitempty"`
}

// Relationship links two identities or an identity to a resource.
type Relationship struct {
	ID       string `json:"id"`
	From     string `json:"from"`
	To       string `json:"to"`
	Relation string `json:"relation"` // member_of/has_role/can_read/can_write/impersonates/uses_credential/controls
	Note     string `json:"note,omitempty"`
}

// SecretArtifact is a discovered artifact that holds credential material. The
// artifact is always redacted; no values are stored.
type SecretArtifact struct {
	ID             string `json:"id"`
	Kind           string `json:"kind"` // env/config/script/backup/ci_secret/npmrc/key_file/docker
	Location       string `json:"location"`
	Redacted       bool   `json:"redacted"`
	CredentialType string `json:"credential_type,omitempty"`
	Note           string `json:"note,omitempty"`
}

// AttackPath is a computed identity attack path to a sensitive group.
type AttackPath struct {
	ID          string   `json:"id"`
	Start       string   `json:"start"`
	Chain       []string `json:"chain"`
	End         string   `json:"end"`
	Sensitivity string   `json:"sensitivity"`
	Shortest    bool     `json:"shortest"`
	Steps       int      `json:"steps"`
}

// Load parses a directory from r, rejecting documents that do not declare the
// directory schema.
func Load(r io.Reader) (*Directory, error) {
	var d Directory
	dec := json.NewDecoder(r)
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("parsing directory: %w", err)
	}
	if d.Schema != SchemaVersion {
		return nil, fmt.Errorf("unsupported directory schema %q (want %s)", d.Schema, SchemaVersion)
	}
	if d.Source = ParseSource(string(d.Source)); d.Source == SourceNone {
		return nil, fmt.Errorf("directory declares no supported identity source (active-directory|okta|aws-iam|github|ldap|google-workspace)")
	}
	normalize(&d)
	return &d, nil
}

// LoadFile loads a directory from a file path.
func LoadFile(path string) (*Directory, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return Load(f)
}

func normalize(d *Directory) {
	if d.Domain == "" && d.Tenant != "" {
		d.Domain = d.Tenant
	}
	if d.ScopeID == "" {
		d.ScopeID = d.Domain
	}
}

// Counts returns per-category inventory totals, used by reports.
type Counts struct {
	Identities  int `json:"identities"`
	Groups      int `json:"groups"`
	Credentials int `json:"credentials"`
	Policies    int `json:"policies"`
	Relations   int `json:"relationships"`
	Secrets     int `json:"secret_artifacts"`
	AttackPaths int `json:"attack_paths"`
}

// Counts computes the inventory totals of a directory.
func (d *Directory) Counts() Counts {
	return Counts{
		Identities:  len(d.Identities),
		Groups:      len(d.Groups),
		Credentials: len(d.Credentials),
		Policies:    len(d.AuthPolicies),
		Relations:   len(d.Relationships),
		Secrets:     len(d.Secrets),
		AttackPaths: len(d.AttackPaths),
	}
}

// Validate runs structural sanity checks on a parsed directory.
func (d *Directory) Validate() []string {
	var problems []string
	if d.Schema != SchemaVersion {
		problems = append(problems, "missing directory schema version")
	}
	if d.Tenant == "" {
		problems = append(problems, "missing tenant (organizational identifier)")
	}
	if ParseSource(string(d.Source)) == SourceNone {
		problems = append(problems, "missing identity source")
	}
	if len(d.Identities) == 0 {
		problems = append(problems, "directory holds no identities; run `sundiata directory` to generate a sample")
	}
	return problems
}

// Marshal renders a directory as indented JSON.
func Marshal(d *Directory) ([]byte, error) {
	return json.MarshalIndent(d, "", "  ")
}
