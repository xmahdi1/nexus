package inventory

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/models"
	"gorm.io/gorm"
)

const MaxNoteBytes = 32 << 10
const documentResourceLimit = 500

var ErrDocumentInput = errors.New("invalid inventory notes")
var ErrDocumentConflict = errors.New("inventory notes changed")

type DocumentNotes struct {
	ServerID  string    `gorm:"primaryKey" json:"-"`
	Notes     string    `json:"notes"`
	Revision  int       `json:"revision"`
	UpdatedAt time.Time `json:"-"`
}

func (DocumentNotes) TableName() string { return "inventory_documents" }

type Document struct {
	ServerName        string         `json:"serverName"`
	Notes             DocumentNotes  `json:"manual"`
	Resources         []Item         `json:"resources"`
	Limited           bool           `json:"limited"`
	CollectionStatus  string         `json:"collectionStatus,omitempty"`
	CollectionWarning string         `json:"collectionWarning,omitempty"`
	Sources           []SourceResult `json:"sources"`
	Markdown          string         `json:"markdown"`
}

func documentNotes(tx *gorm.DB, server string) (DocumentNotes, error) {
	notes := DocumentNotes{ServerID: server}
	err := tx.First(&notes, "server_id=?", server).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return notes, nil
	}
	return notes, err
}

func (s *Service) Document(ctx context.Context, actor, server string) (Document, error) {
	result := Document{Resources: []Item{}, Sources: []SourceResult{}}
	err := s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if server == "" || !authorization.New(tx).All(actor, server, "inventory.read", "inventory.export") {
			return authorization.ErrDenied
		}
		var target models.Server
		if err := tx.Select("name").Take(&target, "id=?", server).Error; err != nil {
			return err
		}
		result.ServerName = target.Name
		notes, err := documentNotes(tx, server)
		if err != nil {
			return err
		}
		result.Notes = notes
		var run Run
		if err := tx.Select("id", "status", "warning").Where("server_id=?", server).
			Order("started_at DESC, id DESC").Take(&run).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		result.CollectionStatus, result.CollectionWarning = run.Status, run.Warning
		if run.ID != "" {
			if err := tx.Where("server_id=? AND run_id=?", server, run.ID).Order("source").Find(&result.Sources).Error; err != nil {
				return err
			}
		}
		var resources []Resource
		if err := tx.Where("server_id=? AND data_state <> ?", server, "retired").
			Order("CASE WHEN kind='host' THEN 0 ELSE 1 END, kind, display_name, id").
			Limit(documentResourceLimit + 1).Find(&resources).Error; err != nil {
			return err
		}
		if len(resources) > documentResourceLimit {
			result.Limited = true
			resources = resources[:documentResourceLimit]
		}
		cutoff, err := freshnessCutoff(tx, server)
		if err != nil {
			return err
		}
		for _, resource := range resources {
			if resource.DataState == "fresh" && resource.LastVerifiedAt.Before(cutoff) {
				resource.DataState = "stale"
			}
			details, err := detailsFor(tx, resource)
			if err != nil {
				return err
			}
			result.Resources = append(result.Resources, Item{resource, details})
		}
		return nil
	})
	if err == nil {
		result.Markdown = renderDocument(result)
	}
	return result, err
}

func (s *Service) SaveDocumentNotes(ctx context.Context, access *auth.Access, server, body string, revision int) (DocumentNotes, error) {
	var result DocumentNotes
	if len(body) > MaxNoteBytes || !utf8.ValidString(body) || strings.ContainsRune(body, 0) || revision < 0 || revision >= 1<<31-1 {
		return result, ErrDocumentInput
	}
	if server == "" || access == nil || s.Sessions == nil {
		return result, authorization.ErrDenied
	}
	err := s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		sessions := *s.Sessions
		sessions.DB = tx
		if _, err := sessions.AccessForSession(access.Session.ID, access.User.ID); err != nil {
			return authorization.ErrDenied
		}
		policy := authorization.New(tx)
		if !policy.All(access.User.ID, server, "inventory.read", "inventory.edit") {
			return authorization.ErrDenied
		}
		var err error
		result, err = documentNotes(tx, server)
		if err != nil {
			return err
		}
		if revision != result.Revision {
			return ErrDocumentConflict
		}
		if body == result.Notes {
			return nil
		}
		result.Notes, result.Revision, result.UpdatedAt = body, revision+1, time.Now().UTC()
		if revision == 0 {
			err = tx.Create(&result).Error
		} else {
			err = tx.Model(&result).Select("notes", "revision", "updated_at").Updates(&result).Error
		}
		if err != nil {
			return err
		}
		return policy.Record(access.User.ID, "inventory.documentation.notes", server, "saved", "")
	})
	return result, err
}

var markdownEscapes = strings.NewReplacer(
	`\`, `\\`, `[`, `\[`, `]`, `\]`, `<`, `\<`, `>`, `\>`,
	`&`, `\&`, `*`, `\*`, `_`, `\_`, "`", "\\`", `!`, `\!`, `|`, `\|`, `#`, `\#`, `~`, `\~`,
)

func markdownText(value string) string {
	return markdownEscapes.Replace(strings.Join(strings.FieldsFunc(value, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
	}), " "))
}

func renderDocument(report Document) string {
	var doc strings.Builder
	fmt.Fprintf(&doc, "# %s\n\n## Observed inventory\n\n", markdownText(report.ServerName))
	if report.CollectionStatus != "" {
		fmt.Fprintf(&doc, "Latest collection: %s. %s\n\n", markdownText(report.CollectionStatus), markdownText(report.CollectionWarning))
	}
	for _, source := range report.Sources {
		fmt.Fprintf(&doc, "- Collector %s: %s at %s (run %s).\n", markdownText(source.Source), markdownText(source.Status), source.CollectedAt.UTC().Format(time.RFC3339), markdownText(source.RunID))
	}
	if len(report.Sources) > 0 {
		doc.WriteByte('\n')
	}
	if report.Limited {
		fmt.Fprintf(&doc, "This report includes the first %d active inventory records. See Inventory for more.\n\n", documentResourceLimit)
	}
	if len(report.Resources) == 0 {
		doc.WriteString("No observations recorded.\n")
	}
	sections := map[string]string{
		"host": "Host", "interface": "Interfaces", "address": "IP addresses",
		"route": "Routes", "service": "Services", "container": "Containers", "port": "Ports",
		"block_device": "Block devices", "mount": "Mounts", "resolver": "Configured DNS resolvers",
		"docker_network": "Docker networks", "docker_volume": "Docker volumes", "docker_image": "Docker images",
		"compose_project": "Observed Compose projects",
		"proxy_route":     "Configured proxy routes", "tls_certificate": "On-disk public certificates",
	}
	lastKind := ""
	for _, item := range report.Resources {
		if lastKind != item.Kind {
			fmt.Fprintf(&doc, "\n### %s\n\n", sections[item.Kind])
			lastKind = item.Kind
		}
		fmt.Fprintf(&doc, "- **%s**", markdownText(item.DisplayName))
		if text := documentFacts(item.Details); text != "" {
			fmt.Fprintf(&doc, " · %s", markdownText(text))
		}
		fmt.Fprintf(&doc, " · %s, %s · verified %s\n", markdownText(item.Source), markdownText(item.DataState), item.LastVerifiedAt.UTC().Format(time.RFC3339))
		if item.LastRunID != "" {
			fmt.Fprintf(&doc, "  Last confirming run: %s.\n", markdownText(item.LastRunID))
		}
	}
	doc.WriteString("\n## Manual notes\n\n")
	doc.WriteString(report.Notes.Notes)
	if !strings.HasSuffix(report.Notes.Notes, "\n") {
		doc.WriteByte('\n')
	}
	return doc.String()
}

func documentFacts(facts any) string {
	switch v := facts.(type) {
	case Host:
		return fmt.Sprintf("%s, kernel %s", v.OS, v.Kernel)
	case NetworkInterface:
		return fmt.Sprintf("%s, MTU %d", v.State, v.MTU)
	case NetworkAddress:
		return fmt.Sprintf("%s, %s scope", v.InterfaceName, v.Scope)
	case NetworkRoute:
		return fmt.Sprintf("%s, device %s, gateway %s, metric %d", v.Type, v.InterfaceName, v.Gateway, v.Metric)
	case ServiceUnit:
		return fmt.Sprintf("%s, %s, %s", v.Load, v.Active, v.Sub)
	case Container:
		facts := fmt.Sprintf("%s, %s", v.Image, v.State)
		if v.Health != "" {
			facts += ", health " + v.Health
		}
		if v.ComposeProject != "" {
			facts += ", Compose project " + v.ComposeProject
		}
		return facts
	case Port:
		return strings.ReplaceAll(v.Exposure, "_", " ")
	case BlockDevice:
		return fmt.Sprintf("%s, %d bytes, read-only: %t", v.Type, v.SizeBytes, v.ReadOnly)
	case Mount:
		return fmt.Sprintf("%s, device %s", v.FilesystemType, v.DeviceNumber)
	case Resolver:
		return fmt.Sprintf("order %d in resolv.conf", v.Priority)
	case DockerNetwork:
		return v.Driver + ", " + v.Scope
	case DockerVolume:
		return v.Driver + ", " + v.Scope
	case DockerImage:
		return strings.Join(v.References, ", ")
	case ProxyRoute:
		return fmt.Sprintf("%s, %s match, TLS configured: %t, upstreams %s", v.Engine, v.MatchKind, v.TLS, strings.Join(v.Upstreams, ", "))
	case ProxyCertificate:
		return fmt.Sprintf("%s, issuer %s, name matches: %t, expires %s, SHA-256 %s", v.Engine, v.Issuer,
			v.NameMatches, v.NotAfter.UTC().Format(time.RFC3339), v.FingerprintSHA256)
	}
	return ""
}
