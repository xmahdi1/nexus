// Package ansible admits reviewed, immutable automation projects and target plans.
package ansible

import "time"

type Project struct {
	ID        string    `gorm:"primaryKey" json:"id"`
	ServerID  string    `json:"serverId"`
	Name      string    `json:"name"`
	CreatedBy string    `json:"createdBy"`
	CreatedAt time.Time `json:"createdAt"`
	Archived  bool      `json:"archived"`
}

func (Project) TableName() string { return "ansible_projects" }

type Revision struct {
	SourceConnectionID string    `json:"sourceConnectionId,omitempty"`
	SourceRepositoryID int64     `json:"sourceRepositoryId,omitempty"`
	SourceCommitSHA    string    `json:"sourceCommitSha,omitempty"`
	ID                 string    `gorm:"primaryKey" json:"id"`
	ProjectID          string    `json:"projectId"`
	ServerID           string    `json:"serverId"`
	Digest             string    `json:"digest"`
	BundleEnc          string    `json:"-"`
	CreatedBy          string    `json:"createdBy"`
	CreatedAt          time.Time `json:"createdAt"`
}

func (Revision) TableName() string { return "ansible_revisions" }

type Plan struct {
	PresetID          string     `json:"presetId,omitempty"`
	ID                string     `gorm:"primaryKey" json:"id"`
	ProjectID         string     `json:"projectId"`
	RevisionID        string     `json:"revisionId"`
	ServerID          string     `json:"serverId"`
	ActorID           string     `json:"actorId"`
	SourceSessionID   string     `json:"-"`
	Digest            string     `json:"digest"`
	ConfigEnc         string     `json:"-"`
	State             string     `json:"state"`
	ApprovedBy        string     `json:"approvedBy,omitempty"`
	ApproverSessionID string     `json:"-"`
	CreatedAt         time.Time  `json:"createdAt"`
	ExpiresAt         time.Time  `json:"expiresAt"`
	ApprovedAt        *time.Time `json:"approvedAt,omitempty"`
}

func (Plan) TableName() string { return "ansible_plans" }

type Variable struct {
	Name     string   `json:"name"`
	Kind     string   `json:"kind"`
	Required bool     `json:"required"`
	Choices  []string `json:"choices,omitempty"`
}
type CollectionLock struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	SHA256    string `json:"sha256"`
}
type Bundle struct {
	Collections []CollectionLock  `json:"collections,omitempty"`
	Main        string            `json:"main"`
	Files       map[string]string `json:"files"`
	Variables   []Variable        `json:"variables"`
}
type VaultReference struct {
	ServerID string `json:"serverId"`
	Mount    string `json:"mount"`
	Path     string `json:"path"`
	Field    string `json:"field"`
	Version  int    `json:"version"`
}
type Options struct {
	Mode           string          `json:"mode"`
	Tags           []string        `json:"tags"`
	SkipTags       []string        `json:"skipTags"`
	Verbosity      int             `json:"verbosity"`
	TimeoutSeconds int             `json:"timeoutSeconds"`
	VaultPassword  *VaultReference `json:"vaultPassword,omitempty"`
}
type Target struct {
	ServerID string `json:"serverId"`
	Host     string `json:"host"`
	User     string `json:"user"`
	Port     int    `json:"port"`
}
type frozenTarget struct {
	Target
	Fingerprint string `json:"fingerprint"`
}
type frozenConfig struct {
	PresetID       string            `json:"presetId,omitempty"`
	ActorID        string            `json:"actorId"`
	SessionID      string            `json:"sessionId"`
	ProjectID      string            `json:"projectId"`
	RevisionID     string            `json:"revisionId"`
	RevisionDigest string            `json:"revisionDigest"`
	Controller     frozenTarget      `json:"controller"`
	GroupID        string            `json:"groupId"`
	Targets        []frozenTarget    `json:"targets"`
	Variables      map[string]any    `json:"variables"`
	Options        Options           `json:"options"`
	VaultBindings  map[string]string `json:"vaultBindings"`
}
type PlanRequest struct {
	RevisionID     string         `json:"revisionId"`
	RevisionDigest string         `json:"revisionDigest"`
	GroupID        string         `json:"groupId"`
	ServerIDs      []string       `json:"serverIds"`
	Variables      map[string]any `json:"variables"`
	Options        Options        `json:"options"`
}
type PlanView struct {
	Plan
	GroupID        string         `json:"groupId"`
	RevisionDigest string         `json:"revisionDigest"`
	Targets        []Target       `json:"targets"`
	VariableNames  []string       `json:"variableNames"`
	Variables      map[string]any `json:"variables,omitempty"`
	Options        Options        `json:"options"`
}
