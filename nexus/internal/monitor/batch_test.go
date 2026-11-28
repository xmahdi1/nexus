package monitor

import (
	"context"
	"testing"
	"time"
)

func TestCheckBatchLimitsWorkAndStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	const total = maxConcurrentChecks * 2
	started := make(chan struct{}, total)
	done := make(chan struct{})
	go func() {
		defer close(done)
		checkBatch(ctx, make([]struct{}, total), func(struct{}) {
			started <- struct{}{}
			<-ctx.Done()
		})
	}()

	for range maxConcurrentChecks {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("the worker batch did not start")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the worker batch did not stop")
	}
	if extra := len(started); extra != 0 {
		t.Fatalf("%d jobs ran outside the initial worker batch", extra)
	}
}
