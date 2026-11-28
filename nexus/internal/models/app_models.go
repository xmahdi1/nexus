package models

import "time"

type DeployedApp struct {
	ID          string    `gorm:"primaryKey"        json:"id"`
	ServerID    string    `gorm:"not null;index"    json:"serverId"`
	TemplateID  string    `                         json:"templateId"`
	Name        string    `                         json:"name"`
	ComposePath string    `                         json:"composePath"`
	VarsEnc     string    `                         json:"-"`
	Status      string    `gorm:"default:'running'" json:"status"`
	DeployedAt  time.Time `                         json:"deployedAt"`
}

type CustomTemplate struct {
	ID            string    `gorm:"primaryKey" json:"id"`
	Name          string    `json:"name"`
	Icon          string    `json:"icon"`
	Category      string    `json:"category"`
	Description   string    `json:"description"`
	DocURL        string    `json:"docUrl"`
	DefinitionEnc string    `json:"-"`
	CreatedAt     time.Time `json:"createdAt"`
}
