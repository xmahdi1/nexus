package models

import "time"

// User is an account record, not a public API response. No account HTTP API is
// exposed yet. Always construct an explicit response when one is introduced.
type User struct {
	ID           string     `gorm:"primaryKey" json:"id"`
	Username     string     `json:"username"`
	DisplayName  string     `json:"displayName"`
	Email        *string    `json:"email,omitempty"`
	PasswordHash string     `json:"-"`
	Status       string     `json:"status"`
	CreatedAt    time.Time  `json:"createdAt"`
	UpdatedAt    time.Time  `json:"updatedAt"`
	LastLoginAt  *time.Time `json:"lastLoginAt,omitempty"`
}
