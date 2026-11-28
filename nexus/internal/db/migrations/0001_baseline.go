// Package migrations holds immutable schema snapshots. Add a new version instead
// of editing a released snapshot when application models change.
package migrations

import (
	"gorm.io/gorm"
	"time"
)

type LoginEvent struct {
	ID        uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	IP        string    `json:"ip"`
	Success   bool      `json:"success"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"createdAt"`
}

type Server struct {
	ID            string    `gorm:"primaryKey"          json:"id"`
	Name          string    `gorm:"not null"             json:"name"`
	Host          string    `gorm:"not null"             json:"host"`
	Port          int       `gorm:"not null;default:22"  json:"port"`
	Username      string    `gorm:"not null"             json:"username"`
	PublicKey     string    `gorm:"type:text"            json:"publicKey"`
	PrivateKeyEnc string    `gorm:"type:text"            json:"-"`
	Fingerprint   string    `                            json:"fingerprint"`
	KnownHostKey  string    `gorm:"type:text"            json:"-"`
	Tags          string    `gorm:"type:text;default:''" json:"tags"`
	CreatedAt     time.Time `                            json:"createdAt"`
	UpdatedAt     time.Time `                            json:"updatedAt"`
}

type ServerAlertConfig struct {
	ID string `gorm:"primaryKey" json:"id"`

	CPUEnabled    bool    `gorm:"default:false" json:"cpuEnabled"`
	CPUThreshold  float64 `gorm:"default:90"    json:"cpuThreshold"`
	RAMEnabled    bool    `gorm:"default:false" json:"ramEnabled"`
	RAMThreshold  float64 `gorm:"default:90"    json:"ramThreshold"`
	DiskEnabled   bool    `gorm:"default:false" json:"diskEnabled"`
	DiskThreshold float64 `gorm:"default:85"    json:"diskThreshold"`

	SSLEnabled    bool `gorm:"default:false" json:"sslEnabled"`
	SSLDaysBefore int  `gorm:"default:14"    json:"sslDaysBefore"`

	UpdatedAt time.Time `json:"updatedAt"`
}

type ScheduledTask struct {
	ID              string     `gorm:"primaryKey"        json:"id"`
	ServerID        string     `gorm:"not null;index"    json:"serverId"`
	Name            string     `json:"name"`
	Command         string     `json:"command"`
	IntervalMinutes int        `gorm:"default:60"        json:"intervalMinutes"`
	Enabled         bool       `gorm:"default:true"      json:"enabled"`
	LastRunAt       *time.Time `json:"lastRunAt"`
	NextRunAt       *time.Time `json:"nextRunAt"`
	LastOutput      string     `json:"lastOutput"`
	LastStatus      string     `gorm:"default:'pending'" json:"lastStatus"`
	CreatedAt       time.Time  `json:"createdAt"`
}

type AlertConfig struct {
	ID               string `gorm:"primaryKey"   json:"id"`
	TelegramEnabled  bool   `json:"telegramEnabled"`
	TelegramToken    string `json:"telegramToken"`
	TelegramChatID   string `json:"telegramChatId"`
	NotifyServerDown bool   `gorm:"default:true" json:"notifyServerDown"`
	NotifyServerUp   bool   `gorm:"default:true" json:"notifyServerUp"`
	NotifyContainer  bool   `gorm:"default:true" json:"notifyContainer"`
}

type MonitoredContainer struct {
	ID          string `gorm:"primaryKey"        json:"id"`
	ServerID    string `gorm:"not null;index"    json:"serverId"`
	ContainerID string `gorm:"not null"          json:"containerId"`
	Name        string `                         json:"name"`
}

type DeployedApp struct {
	ID          string    `gorm:"primaryKey"        json:"id"`
	ServerID    string    `gorm:"not null;index"    json:"serverId"`
	TemplateID  string    `                         json:"templateId"`
	Name        string    `                         json:"name"`
	ComposePath string    `                         json:"composePath"`
	VarsJSON    string    `                         json:"varsJson"`
	Status      string    `gorm:"default:'running'" json:"status"`
	DeployedAt  time.Time `                         json:"deployedAt"`
}

type CustomTemplate struct {
	ID          string    `gorm:"primaryKey" json:"id"`
	Name        string    `json:"name"`
	Icon        string    `json:"icon"`
	Category    string    `json:"category"`
	Description string    `json:"description"`
	DocURL      string    `json:"docUrl"`
	PostDeploy  string    `json:"postDeploy"`
	VarsJSON    string    `json:"varsJson"`
	Compose     string    `json:"compose"`
	CreatedAt   time.Time `json:"createdAt"`
}

type ProxyRule struct {
	ID         string    `gorm:"primaryKey"            json:"id"`
	ServerID   string    `gorm:"not null;index"        json:"serverId"`
	Domain     string    `gorm:"not null"              json:"domain"`
	Target     string    `gorm:"not null"              json:"target"`
	ProxyType  string    `gorm:"not null"              json:"proxyType"`
	SSLEnabled bool      `gorm:"default:false"         json:"sslEnabled"`
	CreatedAt  time.Time `                             json:"createdAt"`
}

type Service struct {
	ID          string    `gorm:"primaryKey"   json:"id"`
	Name        string    `gorm:"not null"     json:"name"`
	URL         string    `gorm:"not null"     json:"url"`
	Icon        string    `                    json:"icon"`
	Description string    `                    json:"description"`
	Category    string    `                    json:"category"`
	Color       string    `                    json:"color"`
	SortOrder   int       `gorm:"default:0"   json:"sortOrder"`
	CreatedAt   time.Time `                    json:"createdAt"`
}

// Baseline adopts all tables previously migrated by application constructors.
func Baseline(tx *gorm.DB) error {
	if err := tx.AutoMigrate(&Server{}, &ProxyRule{}, &Service{}, &AlertConfig{},
		&MonitoredContainer{}, &ServerAlertConfig{}, &ScheduledTask{}, &DeployedApp{},
		&CustomTemplate{}, &LoginEvent{}); err != nil {
		return err
	}
	return tx.Where("id = ?", "default").FirstOrCreate(&AlertConfig{ID: "default", NotifyServerDown: true, NotifyServerUp: true, NotifyContainer: true}).Error
}
