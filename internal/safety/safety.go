// Package safety implements the architectural safety model of sundiata.
//
// Every operation carries metadata describing its class, risk, authorization
// requirement, whether it changes remote state, and whether it is reversible.
// Identity directory analysis is read-only and offline by default: snapshot
// and simulation analysis need no authorization and never touch an identity
// provider. Live directory collection is not implemented and is refused with
// an honest error rather than faked. Credential material encountered during
// assessment is redacted before any output; raw values are never stored.
package safety

import "github.com/QYVORA/qyvora-sundiata/pkg/models"

// Class identifies a family of assessment operation.
type Class string

const (
	ClassDiscovery  Class = "discovery"
	ClassAnalysis   Class = "analysis"
	ClassLiveSource Class = "live-source"
)

// OperationMetadata describes one operation's safety contract.
type OperationMetadata struct {
	ID           string              `json:"id"`
	Name         string              `json:"name"`
	Description  string              `json:"description"`
	Class        Class               `json:"class"`
	Risk         models.RiskLevel    `json:"risk"`
	NoiseLevel   models.NoiseLevel   `json:"noise_level"`
	TargetType   string              `json:"target_type"`
	AuthRequired bool                `json:"authorization_required"`
	Confirm      bool                `json:"confirmation_required"`
	ChangesState bool                `json:"changes_state"`
	Reversible   bool                `json:"reversible"`
}

// Known operations.
var (
	// OpDirectoryParse analyzes an offline identity directory snapshot. Read-only, no auth.
	OpDirectoryParse = OperationMetadata{
		ID: "sundiata.directory.parse", Name: "identity directory snapshot analysis",
		Description: "Parse and analyze an offline identity directory snapshot file.",
		Class:       ClassDiscovery, Risk: models.RiskS1, NoiseLevel: models.NoiseLevelPassive, TargetType: "directory",
		AuthRequired: false, Confirm: false, ChangesState: false, Reversible: true,
	}
	// OpAnalyze runs the analysis pipeline over collected identities. Read-only.
	OpAnalyze = OperationMetadata{
		ID: "sundiata.analyze", Name: "identity and credential analysis",
		Description: "Run identity discovery, authentication, credential exposure, privilege, relationship, secret and attack-path analysis.",
		Class:       ClassAnalysis, Risk: models.RiskS1, NoiseLevel: models.NoiseLevelPassive, TargetType: "any",
		AuthRequired: false, Confirm: false, ChangesState: false, Reversible: true,
	}
	// OpLiveSource would contact a real identity provider. Not implemented.
	OpLiveSource = OperationMetadata{
		ID: "sundiata.live.source", Name: "live identity source collection",
		Description: "Query a live identity provider API (NOT IMPLEMENTED).",
		Class:       ClassLiveSource, Risk: models.RiskS2, NoiseLevel: models.NoiseLevelModerate, TargetType: "directory",
		AuthRequired: true, Confirm: true, ChangesState: false, Reversible: true,
	}
)

// Implemented reports whether an operation actually exists in this build.
// Live identity source collection is deliberately not implemented; calling it
// must produce an honest error rather than pretend capability.
func (op OperationMetadata) Implemented() bool {
	return op.ID != OpLiveSource.ID
}

// RequiresAuthorization reports whether an operation only runs on an
// authorized target.
func (op OperationMetadata) RequiresAuthorization() bool { return op.AuthRequired }
