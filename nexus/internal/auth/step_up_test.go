package auth

import (
	"testing"
	"time"
)

func TestStepUpIsFactorBoundExpiringAndTransactional(t *testing.T) {
	s, admin := ownerFixture(t)
	_, codes := enableFactor(t, s, admin, "current legacy password")
	pending, err := s.Login("owner", "current legacy password", "", "")
	if err != nil {
		t.Fatal(err)
	}
	login, err := s.VerifyRecovery(pending.PendingToken, codes[0], "", "")
	if err != nil {
		t.Fatal(err)
	}
	access := mustAccess(t, s, login.Token)
	now := s.now().Add(6 * time.Minute)
	s.now = func() time.Time { return now }
	if access.RecentMFA() {
		t.Fatal("stale proof accepted")
	}
	if err := s.StepUp(access, "wrong password", codes[1]); err == nil {
		t.Fatal("bad password accepted")
	}
	if err := s.StepUp(access, "current legacy password", codes[1]); err != nil {
		t.Fatal(err)
	}
	fresh := mustAccess(t, s, login.Token)
	if !fresh.RecentMFA() {
		t.Fatal("stepup not saved")
	}
	if err := s.StepUp(fresh, "current legacy password", codes[1]); err == nil {
		t.Fatal("recovery replayed")
	}
	if err := s.DB.Exec(`CREATE TRIGGER reject_step_up BEFORE INSERT ON authorization_events WHEN NEW.action='auth.step_up' BEGIN SELECT RAISE(ABORT,'fixture'); END`).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.StepUp(fresh, "current legacy password", codes[2]); err == nil {
		t.Fatal("unaudited proof accepted")
	}
	s.DB.Exec("DROP TRIGGER reject_step_up")
	if err := s.StepUp(fresh, "current legacy password", codes[2]); err != nil {
		t.Fatal("rolled back code consumed", err)
	}
}
