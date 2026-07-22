package models

import "time"

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
