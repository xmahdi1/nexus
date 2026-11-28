package auth

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/models"
)

func ownerFixture(t *testing.T) (*Service, *Access) {
	t.Helper()
	s, cfg := sessionFixture(t)
	activateFixture(t, s, cfg)
	return s, mustAccess(t, s, mustLogin(t, s, "owner", "current legacy password"))
}
func inviteUser(t *testing.T, s *Service, admin *Access, name, role string) (InviteResult, *Access) {
	t.Helper()
	invite, err := s.CreateInvitation(admin, InviteOptions{Username: name, RoleID: role, ScopeType: "global"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptInvitation(invite.Token, "invited fixture password"); err != nil {
		t.Fatal(err)
	}
	return invite, mustAccess(t, s, mustLogin(t, s, name, "invited fixture password"))
}
func enableFactor(t *testing.T, s *Service, a *Access, password string) (string, []string) {
	t.Helper()
	enrollment, err := s.SetupMFA(a, password)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := totp.GenerateCode(enrollment.Secret, s.now())
	codes, err := s.EnableMFA(a, enrollment.SetupToken, code)
	if err != nil {
		t.Fatal(err)
	}
	return enrollment.Secret, codes
}
func TestInvitationBindingExpiryReplayAndAdmission(t *testing.T) {
	s, admin := ownerFixture(t)
	invite, err := s.CreateInvitation(admin, InviteOptions{Username: "VIEWER", RoleID: "viewer", ScopeType: "global", ExpiresHours: 1}, "")
	if err != nil {
		t.Fatal(err)
	}
	var saved Invitation
	s.DB.First(&saved, "id=?", invite.Invitation.ID)
	if saved.TokenHash == invite.Token || strings.Contains(saved.TokenHash, invite.Token) {
		t.Fatal("stored invitation plaintext")
	}
	if _, err := s.Login("viewer", "invited fixture password", "", ""); err == nil {
		t.Fatal("invited account authenticated before redemption")
	}
	if _, err := s.AcceptInvitation(invite.Token, "invited fixture password"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptInvitation(invite.Token, "attacker replacement password"); err == nil {
		t.Fatal("invitation replayed")
	}
	viewer := mustAccess(t, s, mustLogin(t, s, "viewer", "invited fixture password"))
	if viewer.User.ID != saved.UserID || viewer.User.ID == admin.User.ID {
		t.Fatal("identity not bound to invitation")
	}
	expired, err := s.CreateInvitation(admin, InviteOptions{Username: "expired", RoleID: "viewer", ScopeType: "global", ExpiresHours: 1}, "")
	if err != nil {
		t.Fatal(err)
	}
	later := s.now().Add(2 * time.Hour)
	s.now = func() time.Time { return later }
	if _, err := s.AcceptInvitation(expired.Token, "expired fixture password"); err == nil {
		t.Fatal("expired invite accepted")
	}
}
func TestInviteRevocationScopeAndInviterAuthority(t *testing.T) {
	s, admin := ownerFixture(t)
	for _, tc := range []struct {
		name   string
		change func(InviteResult)
	}{
		{"revoked", func(i InviteResult) {
			if err := s.RevokeInvitation(admin, i.Invitation.ID, ""); err != nil {
				t.Fatal(err)
			}
		}},
		{"grantgone", func(i InviteResult) { s.DB.Where("principal_id=?", i.Invitation.UserID).Delete(&authorization.Grant{}) }},
		{"inviternotadmin", func(i InviteResult) {
			s.DB.Where("principal_id=? AND role_id='admin'", admin.User.ID).Delete(&authorization.Grant{})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "inviternotadmin" {
				defer s.DB.Create(&authorization.Grant{ID: "restore-admin", PrincipalID: admin.User.ID, PrincipalKind: "user", RoleID: "admin", ScopeType: "global", CreatedBy: "fixture", CreatedAt: s.now()})
			}
			invite, err := s.CreateInvitation(admin, InviteOptions{Username: tc.name, RoleID: "viewer", ScopeType: "global"}, "")
			if err != nil {
				t.Fatal(err)
			}
			tc.change(invite)
			if _, err := s.AcceptInvitation(invite.Token, "invited fixture password"); err == nil {
				t.Fatal("unapproved invite accepted")
			}
		})
	}
}
func TestPerUserFactorsRecoveryCodesAndLockout(t *testing.T) {
	s, admin := ownerFixture(t)
	_, viewer := inviteUser(t, s, admin, "viewer", "viewer")
	secret, codes := enableFactor(t, s, viewer, "invited fixture password")
	if len(codes) != 10 {
		t.Fatal("missing recovery codes")
	}
	remaining, err := s.RecoveryRemaining(viewer.User.ID)
	if err != nil || remaining != 10 {
		t.Fatal("recovery count incorrect")
	}
	var stored recoveryCode
	s.DB.Where("user_id=?", viewer.User.ID).First(&stored)
	if strings.Contains(stored.CodeHash, strings.ReplaceAll(codes[0], "-", "")) {
		t.Fatal("stored recovery plaintext")
	}
	result, err := s.Login("viewer", "invited fixture password", "", "")
	if err != nil || !result.MFARequired {
		t.Fatal("per-user MFA missing")
	}
	_ = secret
	code := "invalid"
	if _, err := s.VerifyMFA(result.PendingToken, code, "", ""); err == nil {
		t.Fatal("wrong time MFA accepted")
	}
	result, err = s.Login("viewer", "invited fixture password", "", "")
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := s.VerifyRecovery(result.PendingToken, codes[0], "", "")
	if err != nil {
		t.Fatal(err)
	}
	a := mustAccess(t, s, recovered.Token)
	if a.User.ID != viewer.User.ID || a.Session.MFAAt == nil {
		t.Fatal("recovery authenticated wrong account")
	}
	result, _ = s.Login("viewer", "invited fixture password", "", "")
	if _, err := s.VerifyRecovery(result.PendingToken, codes[0], "", ""); err == nil {
		t.Fatal("recovery code replayed")
	}
	owner := mustLogin(t, s, "owner", "current legacy password")
	mustAccess(t, s, owner) // Viewer MFA never replaces owner MFA state.
	for i := 0; i < 5; i++ {
		s.Login("viewer", "wrong password", "", "")
	}
	if _, err := s.Login("viewer", "invited fixture password", "", ""); err == nil {
		t.Fatal("locked account bypassed lockout")
	}
	now := s.now().Add(16 * time.Minute)
	s.now = func() time.Time { return now }
	if result, err := s.Login("viewer", "invited fixture password", "", ""); err != nil || !result.MFARequired {
		t.Fatal("lockout did not expire")
	}
}
func TestStatusAndLastAdministratorConcurrentGuard(t *testing.T) {
	s, admin := ownerFixture(t)
	if err := s.ChangeStatus(admin, admin.User.ID, "disabled", ""); !errors.Is(err, authorization.ErrLastAdmin) {
		t.Fatalf("last admin disabled: %v", err)
	}
	_, second := inviteUser(t, s, admin, "second", "admin")
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, entry := range []*Access{admin, second} {
		wg.Add(1)
		go func(a *Access) { defer wg.Done(); results <- s.ChangeStatus(a, a.User.ID, "disabled", "") }(entry)
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 || !authorization.AdministratorRemains(s.DB) {
		t.Fatal("concurrent operations removed all administrators")
	}
}
func TestResetReconciliationAndMandatoryEnrollment(t *testing.T) {
	s, admin := ownerFixture(t)
	_, viewer := inviteUser(t, s, admin, "viewer", "viewer")
	_, err := s.IssueReset(admin, viewer.User.ID, "mfa", "lost factor", "")
	if !errors.Is(err, ErrStepUp) {
		t.Fatal("MFA reset without administrator MFA")
	}
	ownerSecret, _ := enableFactor(t, s, admin, "current legacy password")
	now := s.now().Add(30 * time.Second)
	s.now = func() time.Time { return now }
	challenge, _ := s.Login("owner", "current legacy password", "", "")
	ownerCode, _ := totp.GenerateCode(ownerSecret, now)
	login, err := s.VerifyMFA(challenge.PendingToken, ownerCode, "", "")
	if err != nil {
		t.Fatal(err)
	}
	admin = mustAccess(t, s, login.Token)
	if _, err := s.IssueReset(admin, admin.User.ID, "mfa", "self last admin", ""); !errors.Is(err, authorization.ErrLastAdmin) {
		t.Fatal("reset blocked last admin guard incorrectly")
	}
	before := mustLogin(t, s, "viewer", "invited fixture password")
	reset, err := s.IssueReset(admin, viewer.User.ID, "mfa", "lost factor", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(before); err == nil {
		t.Fatal("invalid token accepted")
	}
	if authorization.New(s.DB).Check(viewer.User.ID, "servers.read", "") {
		t.Fatal("recovery-pending principal authorized")
	}
	if _, err := s.Login("viewer", "invited fixture password", "", ""); err == nil {
		t.Fatal("reset did not block old credentials")
	}
	enrollment, err := s.BeginMFAReset(reset.Token, "new recovery password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Login("viewer", "new recovery password", "", ""); err == nil {
		t.Fatal("password active before factor confirmation")
	}
	code, _ := totp.GenerateCode(enrollment.Secret, s.now())
	codes, err := s.ConfirmMFAReset(enrollment.SetupToken, code)
	if err != nil || len(codes) != 10 {
		t.Fatalf("factor recovery failed: %v", err)
	}
	if _, err := s.ConfirmMFAReset(enrollment.SetupToken, code); err == nil {
		t.Fatal("reset enrollment replayed")
	}
	if _, err := s.BeginMFAReset(reset.Token, "another recovery password"); err == nil {
		t.Fatal("reset token replayed")
	}
	challenge, err = s.Login("viewer", "new recovery password", "", "")
	if err != nil || !challenge.MFARequired {
		t.Fatal("reset bypassed new MFA")
	}
	var user models.User
	s.DB.First(&user, "id=?", viewer.User.ID)
	if user.Status != "active" {
		t.Fatal("recovery corrupted status")
	}
}

func TestPasswordRecoveryPreservesFactorAndRotatesCodes(t *testing.T) {
	s, admin := ownerFixture(t)
	_, viewer := inviteUser(t, s, admin, "viewer", "viewer")
	_, oldCodes := enableFactor(t, s, viewer, "invited fixture password")
	reset, err := s.IssueReset(admin, viewer.User.ID, "password", "forgot password", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CompletePasswordReset(reset.Token, "replacement fixture password", ""); err == nil {
		t.Fatal("reset bypassed factor")
	}
	codes, err := s.CompletePasswordReset(reset.Token, "replacement fixture password", oldCodes[0])
	if err != nil || len(codes) != 10 {
		t.Fatalf("reset failed: %v", err)
	}
	if _, err := s.CompletePasswordReset(reset.Token, "attacker replacement password", oldCodes[1]); err == nil {
		t.Fatal("reset replayed")
	}
	if _, err := s.Login("viewer", "invited fixture password", "", ""); err == nil {
		t.Fatal("old password survived")
	}
	challenge, err := s.Login("viewer", "replacement fixture password", "", "")
	if err != nil || !challenge.MFARequired {
		t.Fatal("reset removed factor")
	}
	if _, err := s.VerifyRecovery(challenge.PendingToken, oldCodes[1], "", ""); err == nil {
		t.Fatal("old recovery code survived rotation")
	}
	challenge, err = s.Login("viewer", "replacement fixture password", "", "")
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.VerifyRecovery(challenge.PendingToken, codes[0], "", "")
	if err != nil {
		t.Fatal(err)
	}
	current := mustAccess(t, s, result.Token)
	fresh, err := s.RegenerateRecovery(current, "replacement fixture password")
	if err != nil || len(fresh) != 10 {
		t.Fatal("regeneration failed", err)
	}
	if _, err := s.Authenticate(result.Token); err == nil {
		t.Fatal("regeneration retained session")
	}
}

func TestResetExpiryDisablementAndLocalLastAdminRecovery(t *testing.T) {
	t.Run("disabled target", func(t *testing.T) {
		s, admin := ownerFixture(t)
		_, viewer := inviteUser(t, s, admin, "viewer", "viewer")
		reset, err := s.IssueReset(admin, viewer.User.ID, "password", "forgot password", "")
		if err != nil {
			t.Fatal(err)
		}
		if err := s.ChangeStatus(admin, viewer.User.ID, "disabled", ""); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ResetInfo(reset.Token); err == nil {
			t.Fatal("disabled target used reset")
		}
		if err := s.ChangeStatus(admin, viewer.User.ID, "active", ""); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ResetInfo(reset.Token); err == nil {
			t.Fatal("reactivation revived reset")
		}
	})
	t.Run("expiry", func(t *testing.T) {
		s, admin := ownerFixture(t)
		_, viewer := inviteUser(t, s, admin, "viewer", "viewer")
		reset, err := s.IssueReset(admin, viewer.User.ID, "password", "forgot password", "")
		if err != nil {
			t.Fatal(err)
		}
		now := s.now().Add(31 * time.Minute)
		s.now = func() time.Time { return now }
		if _, err := s.CompletePasswordReset(reset.Token, "replacement fixture password", ""); err == nil {
			t.Fatal("expired reset accepted")
		}
	})
	t.Run("local recovery", func(t *testing.T) {
		s, admin := ownerFixture(t)
		reset, err := s.LocalRecovery("owner", "lost sole administrator factor")
		if err != nil {
			t.Fatal(err)
		}
		if authorization.New(s.DB).Check(admin.User.ID, "users.manage", "") {
			t.Fatal("pending recovery retained access")
		}
		enrollment, err := s.BeginMFAReset(reset.Token, "replacement owner password")
		if err != nil {
			t.Fatal(err)
		}
		code, _ := totp.GenerateCode(enrollment.Secret, s.now())
		if codes, err := s.ConfirmMFAReset(enrollment.SetupToken, code); err != nil || len(codes) != 10 {
			t.Fatal("local recovery failed", err)
		}
		if !authorization.AdministratorRemains(s.DB) {
			t.Fatal("owner privileges lost")
		}
	})
}

func TestConcurrentInvitationRedemption(t *testing.T) {
	s, admin := ownerFixture(t)
	invite, err := s.CreateInvitation(admin, InviteOptions{Username: "race", RoleID: "viewer", ScopeType: "global"}, "")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.AcceptInvitation(invite.Token, "invited fixture password")
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("redemptions=%d", success)
	}
}

func TestResetRequesterDisablementPermanentlyRevokesLink(t *testing.T) {
	s, owner := ownerFixture(t)
	_, second := inviteUser(t, s, owner, "second", "admin")
	_, viewer := inviteUser(t, s, owner, "viewer", "viewer")
	reset, err := s.IssueReset(second, viewer.User.ID, "password", "forgot password", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ChangeStatus(owner, second.User.ID, "disabled", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.ChangeStatus(owner, second.User.ID, "active", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResetInfo(reset.Token); err == nil {
		t.Fatal("reactivating requester revived reset")
	}
}

func TestInvitationAuditFailureRollsBackAdmission(t *testing.T) {
	s, admin := ownerFixture(t)
	invite, err := s.CreateInvitation(admin, InviteOptions{Username: "viewer", RoleID: "viewer", ScopeType: "global"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Exec(`CREATE TRIGGER reject_accept BEFORE INSERT ON authorization_events WHEN NEW.action='users.invite.accept' BEGIN SELECT RAISE(ABORT,'fixture audit failure'); END`).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptInvitation(invite.Token, "invited fixture password"); err == nil {
		t.Fatal("unaudited admission succeeded")
	}
	if _, err := s.Login("viewer", "invited fixture password", "", ""); err == nil {
		t.Fatal("failed transaction admitted account")
	}
	if err := s.DB.Exec("DROP TRIGGER reject_accept").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptInvitation(invite.Token, "invited fixture password"); err != nil {
		t.Fatal("rollback consumed token", err)
	}
}
