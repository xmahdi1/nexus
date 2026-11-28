// Package backups coordinates source-specific exports and repository snapshots.
package backups

import (
	"errors"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrInput         = errors.New("invalid backup settings")
	ErrDenied        = errors.New("backup authority unavailable")
	ErrDisabled      = errors.New("backups disabled")
	ErrBusy          = errors.New("backup host has an unresolved run")
	ErrConflict      = errors.New("backup identity changed")
	idPattern        = regexp.MustCompile(`^[a-f0-9]{32}$`)
	snapshotPattern  = regexp.MustCompile(`^[a-f0-9]{64}$`)
	containerPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	volumePattern    = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
	databasePattern  = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.-]{0,79}$`)
	hostPattern      = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.:-]{0,252}$`)
)

const LocalHost = "@nexus"

type Repository struct {
	Kind         string `json:"kind"`
	Location     string `json:"location"`
	Password     string `json:"password"`
	AccessKey    string `json:"accessKey,omitempty"`
	SecretKey    string `json:"secretKey,omitempty"`
	Region       string `json:"region,omitempty"`
	SessionToken string `json:"sessionToken,omitempty"`
	BucketLookup string `json:"bucketLookup,omitempty"`
}
type Database struct {
	Host                 string `json:"host,omitempty"`
	Port                 int    `json:"port,omitempty"`
	Name                 string `json:"name,omitempty"`
	User                 string `json:"user,omitempty"`
	Password             string `json:"password,omitempty"`
	ContainerEnvironment bool   `json:"containerEnvironment,omitempty"`
}
type Source struct {
	Kind        string   `json:"kind"`
	Label       string   `json:"label"`
	Path        string   `json:"path,omitempty"`
	ContainerID string   `json:"containerId,omitempty"`
	Volume      string   `json:"volume,omitempty"`
	Database    Database `json:"database,omitempty"`
}
type Timing struct {
	Mode            string     `json:"mode"`
	At              *time.Time `json:"at,omitempty"`
	IntervalMinutes int        `json:"intervalMinutes,omitempty"`
}
type Definition struct {
	ExportLimitGiB int        `json:"exportLimitGiB"`
	Name           string     `json:"name"`
	Repository     Repository `json:"repository"`
	Sources        []Source   `json:"sources"`
	Timing         Timing     `json:"timing"`
	RuntimeSeconds int        `json:"runtimeSeconds"`
	AllowLiveFiles bool       `json:"allowLiveFiles"`
}
type sealedDefinition struct {
	Definition
	ServerID    string `json:"serverId"`
	OwnerID     string `json:"ownerId"`
	HostBinding string `json:"hostBinding"`
}
type Policy struct {
	ID              string     `gorm:"primaryKey" json:"id"`
	ServerID        string     `json:"serverId"`
	Name            string     `json:"name"`
	ActorID         string     `json:"actorId"`
	ConfigEnc       string     `json:"-"`
	Digest          string     `json:"-"`
	Mode            string     `json:"mode"`
	IntervalMinutes int        `json:"intervalMinutes"`
	NextAt          *time.Time `json:"nextAt,omitempty"`
	Enabled         bool       `json:"enabled"`
	Archived        bool       `json:"archived"`
	LastRunID       string     `json:"lastRunId,omitempty"`
	LastState       string     `json:"lastState"`
	LastSuccessAt   *time.Time `json:"lastSuccessAt,omitempty"`
	LastCheckAt     *time.Time `json:"lastCheckAt,omitempty"`
	LastRestoreAt   *time.Time `json:"lastRestoreAt,omitempty"`
	CreatedAt       time.Time  `json:"createdAt"`
}

func (Policy) TableName() string { return "backup_policies" }

type RepositoryView struct {
	Kind     string `json:"kind"`
	Location string `json:"location"`
	Region   string `json:"region,omitempty"`
}
type SourceView struct {
	Kind        string `json:"kind"`
	Label       string `json:"label"`
	Path        string `json:"path,omitempty"`
	ContainerID string `json:"containerId,omitempty"`
	Volume      string `json:"volume,omitempty"`
}
type PolicyView struct {
	Repository RepositoryView `json:"repository"`
	Sources    []SourceView   `json:"sources"`
	Policy
	SourceKinds    []string `json:"sourceKinds"`
	RepositoryKind string   `json:"repositoryKind"`
}
type Candidate struct {
	ID          string `json:"id"`
	Source      Source `json:"source"`
	Consistency string `json:"consistency"`
	State       string `json:"state"`
	Note        string `json:"note"`
}
type Discovery struct {
	Sources   []Candidate     `json:"sources"`
	Tools     map[string]bool `json:"tools"`
	Truncated bool            `json:"truncated"`
}
type Snapshot struct {
	ID   string `json:"id"`
	Time string `json:"time"`
}
type Result struct {
	State       string           `json:"state"`
	Phase       string           `json:"phase,omitempty"`
	SnapshotID  string           `json:"snapshotId,omitempty"`
	Files       int64            `json:"files,omitempty"`
	Bytes       int64            `json:"bytes,omitempty"`
	Snapshots   []Snapshot       `json:"snapshots,omitempty"`
	RestorePath string           `json:"restorePath,omitempty"`
	Verified    bool             `json:"verified"`
	Retention   *RetentionResult `json:"retention,omitempty"`
}

func text(value string, max int) bool {
	return utf8.ValidString(value) && len(value) <= max && !strings.ContainsAny(value, "\x00\r\n")
}
func validPath(value string) bool {
	return text(value, 4096) && path.IsAbs(value) && path.Clean(value) == value && !strings.HasPrefix(value, "//")
}
func (d Definition) Validate(local bool) error {
	if d.ExportLimitGiB < 0 || d.ExportLimitGiB > 1024 {
		return ErrInput
	}
	if strings.TrimSpace(d.Name) == "" || !text(d.Name, 80) || len(d.Sources) < 1 || len(d.Sources) > 25 || d.RuntimeSeconds < 60 || d.RuntimeSeconds > 86400 {
		return ErrInput
	}
	repo := d.Repository
	if repo.Password == "" || !text(repo.Password, 4096) || !text(repo.AccessKey, 1024) || !text(repo.SecretKey, 4096) || !text(repo.SessionToken, 8192) || !text(repo.Region, 80) {
		return ErrInput
	}
	switch repo.Kind {
	case "local":
		if !validPath(repo.Location) || repo.Location == "/" || repo.AccessKey != "" || repo.SecretKey != "" || repo.SessionToken != "" || repo.BucketLookup != "" {
			return ErrInput
		}
	case "s3":
		if repo.BucketLookup != "" && repo.BucketLookup != "auto" && repo.BucketLookup != "path" && repo.BucketLookup != "dns" {
			return ErrInput
		}
		if !strings.HasPrefix(repo.Location, "s3:https://") || !text(repo.Location, 2048) || repo.AccessKey == "" || repo.SecretKey == "" {
			return ErrInput
		}
		parsed, err := url.Parse(strings.TrimPrefix(repo.Location, "s3:"))
		if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path == "" || parsed.Path == "/" {
			return ErrInput
		}
	default:
		return ErrInput
	}
	seen := map[Source]bool{}
	for _, source := range d.Sources {
		if !text(source.Label, 120) || seen[source] {
			return ErrInput
		}
		seen[source] = true
		if local {
			if source.Kind != "nexus" || len(d.Sources) != 1 || source.Path != "" || source.ContainerID != "" || source.Volume != "" || source.Database != (Database{}) {
				return ErrInput
			}
			continue
		}
		switch source.Kind {
		case "files", "sqlite":
			if !validPath(source.Path) || source.Path == "/proc" || source.Path == "/sys" || source.Path == "/dev" || source.Path == "/run" || source.ContainerID != "" || source.Volume != "" || source.Database != (Database{}) {
				return ErrInput
			}
			for _, prefix := range []string{"/proc/", "/sys/", "/dev/", "/run/"} {
				if strings.HasPrefix(source.Path, prefix) {
					return ErrInput
				}
			}
			if source.Kind == "files" && !d.AllowLiveFiles {
				return ErrInput
			}
		case "docker-volume":
			if !volumePattern.MatchString(source.Volume) || source.Path != "" || source.ContainerID != "" || source.Database != (Database{}) || !d.AllowLiveFiles {
				return ErrInput
			}
		case "docker-bind":
			if !containerPattern.MatchString(source.ContainerID) || !validPath(source.Path) || source.Volume != "" || source.Database != (Database{}) || !d.AllowLiveFiles {
				return ErrInput
			}
		case "postgres", "mysql", "mariadb", "mongodb":
			db := source.Database
			if source.Path != "" || source.Volume != "" || !text(db.Password, 4096) || (db.Name != "" && !databasePattern.MatchString(db.Name)) || (db.User != "" && !databasePattern.MatchString(db.User)) {
				return ErrInput
			}
			if source.ContainerID != "" {
				if !containerPattern.MatchString(source.ContainerID) || db.Host != "" || db.Port != 0 {
					return ErrInput
				}
				if source.Kind == "mongodb" {
					if db.ContainerEnvironment {
						return ErrInput
					}
				} else if !db.ContainerEnvironment || db.Password != "" || db.User != "" || db.Name != "" {
					return ErrInput
				}
			} else if db.ContainerEnvironment || !hostPattern.MatchString(db.Host) || db.Port < 1 || db.Port > 65535 || db.User == "" {
				return ErrInput
			}
		default:
			return ErrInput
		}
	}
	switch d.Timing.Mode {
	case "manual":
		if d.Timing.At != nil || d.Timing.IntervalMinutes != 0 {
			return ErrInput
		}
	case "once":
		if d.Timing.At == nil || d.Timing.IntervalMinutes != 0 {
			return ErrInput
		}
	case "interval":
		if d.Timing.IntervalMinutes < 15 || d.Timing.IntervalMinutes > 525600 {
			return ErrInput
		}
	default:
		return ErrInput
	}

	return nil
}
