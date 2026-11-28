package models

// ExecutionHostLock reserves a controller or frozen target for one run. Only
// verified termination or proof of no dispatch releases it.
type ExecutionHostLock struct {
	ServerID string `gorm:"primaryKey"`
	RunID    string
}
