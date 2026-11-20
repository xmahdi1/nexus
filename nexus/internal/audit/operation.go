package audit

import (
	"errors"
	"regexp"
	"time"

	"gorm.io/gorm"
)

var operationIdentifier = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
var ErrOperationID = errors.New("invalid operation identifier")

type Operation struct {
	ID                    string     `json:"id"`
	State                 string     `json:"state"`
	Action                string     `json:"action"`
	ActorID               string     `json:"actorId"`
	ServerID              string     `json:"serverId"`
	ResourceType          string     `json:"resourceType"`
	ResourceID            string     `json:"resourceId"`
	StartedAt             time.Time  `json:"startedAt"`
	CompletedAt           *time.Time `json:"completedAt"`
	RemoteStateVerified   bool       `json:"remoteStateVerified"`
	AutomaticRetryAllowed bool       `json:"automaticRetryAllowed"`
	Guidance              string     `json:"guidance"`
}

// Inspect derives HTTP lifecycle metadata only. A missing completion remains
// pending even if old: it may be active, crashed, or missing its final audit write.
func Inspect(db *gorm.DB, id string) (Operation, error) {
	var result Operation
	if !operationIdentifier.MatchString(id) {
		return result, ErrOperationID
	}
	var events []Event
	if err := db.Where("operation_id=? AND source IN ('http','websocket')", id).Order("id desc").Limit(3).Find(&events).Error; err != nil {
		return result, err
	}
	if len(events) == 0 {
		return result, gorm.ErrRecordNotFound
	}
	latest := events[0]
	result = Operation{ID: id, State: latest.Outcome, Action: latest.Action, ActorID: latest.ActorID, ServerID: latest.ServerID, ResourceType: latest.ResourceType, ResourceID: latest.ResourceID, StartedAt: events[len(events)-1].At,
		Guidance: "Inspect the target using authorized read-only status checks and compare the intended change before deciding whether to retry. HTTP/audit results do not independently verify remote state."}
	if latest.Outcome == "started" {
		result.State = "pending"
	} else {
		at := latest.At
		result.CompletedAt = &at
	}
	return result, nil
}
