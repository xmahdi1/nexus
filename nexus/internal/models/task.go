package models

import "time"

type ScheduledTask struct {
	Supervised      bool       `json:"supervised"`
	LeaseUntil      *time.Time `json:"-"`
	ActorID         string     `json:"actorId"`
	CreatedBy       string     `json:"createdBy"`
	RunID           string     `json:"-"`
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
