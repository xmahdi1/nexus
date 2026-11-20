package jobsupervisor

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/db"
	"github.com/xmahdi1/nexus/internal/models"
)

func TestPersistedRunTerminalStateAndOutputSurviveLostObservation(t *testing.T) {
	key := bytes.Repeat([]byte{8}, 32)
	database, err := db.Init(filepath.Join(t.TempDir(), "runs.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	connection, _ := database.DB()
	defer connection.Close()
	service := NewService(database, key, nil)
	run := models.SupervisedRun{ID: strings.Repeat("a", 32), ServerID: "host", TaskID: "task", ActorID: "actor", CommandHash: Digest("fixture"), State: "prepared", CreatedAt: time.Now().UTC()}
	if err := database.Create(&run).Error; err != nil {
		t.Fatal(err)
	}
	invocation := strings.Repeat("b", 32)
	if err := service.Save(run, Snapshot{State: "running", Verified: true, InvocationID: invocation, Output: "private partial output"}); err != nil {
		t.Fatal(err)
	}
	if err := service.Save(run, Snapshot{State: "unknown", Detail: "transport_lost"}); err != nil {
		t.Fatal(err)
	}
	database.First(&run, "id=?", run.ID)
	if run.InvocationID != invocation || run.FinishedAt != nil || run.VerifiedAt != nil || run.State != "unknown" {
		t.Fatal("lost observation invented completion or discarded identity", run)
	}
	result, err := service.Cached(run)
	if err != nil || result.Output != "private partial output" || result.Verified {
		t.Fatal("partial history misrepresented", err)
	}
	code := 0
	if err := service.Save(run, Snapshot{State: "exited", Verified: true, Empty: true, ExitCode: &code, InvocationID: invocation, Output: "private final output"}); err != nil {
		t.Fatal(err)
	}
	if err := service.Save(run, Snapshot{State: "unknown"}); err != nil {
		t.Fatal(err)
	}
	database.First(&run, "id=?", run.ID)
	result, err = service.Cached(run)
	if err != nil || !result.Terminal() || result.Output != "private final output" {
		t.Fatal("terminal proof lost", err)
	}
	if run.OutputEnc == "" || strings.Contains(run.OutputEnc, "private final output") {
		t.Fatal("output persisted in plaintext")
	}
}

func TestCancellationBeforeDispatchIsDurableAndCannotStart(t *testing.T) {
	key := bytes.Repeat([]byte{8}, 32)
	database, err := db.Init(filepath.Join(t.TempDir(), "runs.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	connection, _ := database.DB()
	defer connection.Close()
	service := NewService(database, key, nil)
	run := models.SupervisedRun{ID: strings.Repeat("a", 32), ServerID: "host", TaskID: "task", ActorID: "actor", CommandHash: Digest("fixture"), State: "prepared", CreatedAt: time.Now().UTC()}
	if err := database.Create(&run).Error; err != nil {
		t.Fatal(err)
	}
	result, err := service.Inspect(context.Background(), run, "cancel")
	if err != nil || !result.NoDispatch || result.State != "not_started" {
		t.Fatal("pre-dispatch cancellation not resolved", result, err)
	}
	// A nil pool deliberately proves no network path is needed or reached here.
	result, err = service.Dispatch(context.Background(), run, "fixture")
	if err != nil || !result.NoDispatch {
		t.Fatal("cancelled reservation could be dispatched", result, err)
	}
	database.First(&run, "id=?", run.ID)
	if run.CancelRequestedAt == nil || run.DispatchStartedAt != nil || run.FinishedAt == nil {
		t.Fatal("cancellation/dispatch ordering lost", run)
	}
}

func TestUnsupportedInspectionDoesNotProveTermination(t *testing.T) {
	// Unsupported START is explicitly marked NoDispatch by the protocol. Merely
	// losing supervisor support while observing an existing run must stay unresolved.
	key := bytes.Repeat([]byte{8}, 32)
	database, err := db.Init(filepath.Join(t.TempDir(), "runs.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	connection, _ := database.DB()
	defer connection.Close()
	service := NewService(database, key, nil)
	run := models.SupervisedRun{ID: strings.Repeat("a", 32), ServerID: "host", TaskID: "task", ActorID: "actor", CommandHash: Digest("fixture"), State: "running", CreatedAt: time.Now().UTC()}
	if err := database.Create(&run).Error; err != nil {
		t.Fatal(err)
	}
	if err := service.Save(run, Snapshot{State: "unsupported"}); err != nil {
		t.Fatal(err)
	}
	database.First(&run, "id=?", run.ID)
	if run.FinishedAt != nil {
		t.Fatal("unsupported observation invented termination")
	}
	if err := service.Save(run, Snapshot{State: "unsupported", NoDispatch: true}); err != nil {
		t.Fatal(err)
	}
	database.First(&run, "id=?", run.ID)
	if run.FinishedAt == nil {
		t.Fatal("known no-dispatch result was not resolved")
	}
}
