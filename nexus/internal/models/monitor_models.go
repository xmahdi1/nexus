package models

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