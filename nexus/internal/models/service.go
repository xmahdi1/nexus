package models

import "time"

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