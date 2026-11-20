package models

import "time"

type SupervisedRun struct {
	ID                string     `gorm:"primaryKey" json:"id"`
	TaskID            string     `json:"taskId"`
	ServerID          string     `json:"serverId"`
	ActorID           string     `json:"actorId"`
	CommandHash       string     `json:"-"`
	State             string     `json:"state"`
	InvocationID      string     `json:"-"`
	OutputEnc         string     `json:"-"`
	ExitCode          *int       `json:"exitCode"`
	Truncated         bool       `json:"truncated"`
	ArtifactsRemoved  bool       `json:"artifactsRemoved"`
	Detail            string     `json:"detail"`
	CreatedAt         time.Time  `json:"createdAt"`
	DispatchStartedAt *time.Time `json:"dispatchStartedAt"`
	CancelRequestedAt *time.Time `json:"cancelRequestedAt"`
	VerifiedAt        *time.Time `json:"verifiedAt"`
	LastCheckedAt     *time.Time `json:"lastCheckedAt"`
	FinishedAt        *time.Time `json:"finishedAt"`
}
