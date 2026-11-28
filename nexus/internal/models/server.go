package models

import "time"

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
