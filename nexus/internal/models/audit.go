package models

import "time"

type LoginEvent struct {
	ID        uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	IP        string    `json:"ip"`
	Success   bool      `json:"success"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"createdAt"`
}
