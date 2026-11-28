package models

import "time"

type ProxyRule struct {
	ID         string    `gorm:"primaryKey"            json:"id"`
	ServerID   string    `gorm:"not null;index"        json:"serverId"`
	Domain     string    `gorm:"not null"              json:"domain"`
	Target     string    `gorm:"not null"              json:"target"`
	ProxyType  string    `gorm:"not null"              json:"proxyType"`
	SSLEnabled bool      `gorm:"default:false"         json:"sslEnabled"`
	CreatedAt  time.Time `                             json:"createdAt"`
}
