package migrations

import "gorm.io/gorm"

func Accounts(tx *gorm.DB) error {
	return tx.Exec(`
 ALTER TABLE auth_credentials ADD COLUMN recovery_required numeric NOT NULL DEFAULT 0;
 CREATE TABLE account_admissions(user_id text PRIMARY KEY NOT NULL REFERENCES users(id),source text NOT NULL CHECK(source IN ('owner','invitation')),admitted_at datetime NOT NULL);
 INSERT INTO account_admissions(user_id,source,admitted_at) SELECT s.owner_user_id,'owner',CURRENT_TIMESTAMP FROM auth_state s JOIN identity_bootstrap b ON b.owner_user_id=s.owner_user_id AND b.id=1 JOIN users u ON u.id=s.owner_user_id WHERE s.id=1 AND s.mode='owner';
 CREATE TABLE account_invitations(id text PRIMARY KEY NOT NULL,user_id text NOT NULL REFERENCES users(id),token_hash text NOT NULL UNIQUE,inviter_id text NOT NULL,created_at datetime NOT NULL,expires_at datetime NOT NULL,redeemed_at datetime,revoked_at datetime);
 CREATE INDEX idx_account_invitations_user ON account_invitations(user_id);
 CREATE TABLE auth_recovery_codes(user_id text NOT NULL,code_hash text NOT NULL,created_at datetime NOT NULL,used_at datetime,PRIMARY KEY(user_id,code_hash));
 CREATE TABLE account_resets(id text PRIMARY KEY NOT NULL,user_id text NOT NULL REFERENCES users(id),token_hash text NOT NULL UNIQUE,kind text NOT NULL CHECK(kind IN ('password','mfa')),credential_epoch text NOT NULL,requested_by text NOT NULL,reason text NOT NULL,created_at datetime NOT NULL,expires_at datetime NOT NULL,used_at datetime,revoked_at datetime);
 CREATE INDEX idx_account_resets_user ON account_resets(user_id);
 CREATE TABLE account_reset_enrollments(token_hash text PRIMARY KEY NOT NULL,reset_id text NOT NULL REFERENCES account_resets(id),secret_enc text NOT NULL,password_hash text NOT NULL,expires_at datetime NOT NULL);
 CREATE TABLE auth_login_limits(key_hash text PRIMARY KEY NOT NULL,failures integer NOT NULL DEFAULT 0,locked_until datetime,updated_at datetime NOT NULL);
 `).Error
}
