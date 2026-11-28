package migrations

import "gorm.io/gorm"

func Sessions(tx *gorm.DB) error {
	return tx.Exec(`CREATE TABLE auth_state (
 id integer PRIMARY KEY CHECK(id=1), mode text NOT NULL CHECK(mode IN ('legacy','owner')),
 owner_user_id text NOT NULL DEFAULT '', activated_at datetime
 );
 INSERT INTO auth_state(id,mode) VALUES(1,'legacy');
 CREATE TABLE auth_credentials (
 user_id text PRIMARY KEY NOT NULL REFERENCES users(id),
 totp_secret_enc text NOT NULL DEFAULT '', totp_enabled numeric NOT NULL DEFAULT 0,
 version integer NOT NULL DEFAULT 1 CHECK(version>0)
 );
 CREATE TABLE auth_sessions (
 id text PRIMARY KEY NOT NULL, principal_id text NOT NULL, token_hash text NOT NULL UNIQUE,
 credential_epoch text NOT NULL, created_at datetime NOT NULL, last_used_at datetime NOT NULL,
 expires_at datetime NOT NULL, revoked_at datetime, mfa_at datetime,
 device_label text NOT NULL, client_ip text NOT NULL
 );
 CREATE INDEX idx_auth_sessions_principal ON auth_sessions(principal_id);
 CREATE TABLE auth_challenges (
 token_hash text PRIMARY KEY NOT NULL, principal_id text NOT NULL, credential_epoch text NOT NULL,
 purpose text NOT NULL CHECK(purpose IN ('login','enroll')), session_id text NOT NULL DEFAULT '',
 secret_enc text NOT NULL DEFAULT '', expires_at datetime NOT NULL
 );
 CREATE INDEX idx_auth_challenges_principal ON auth_challenges(principal_id);
 CREATE TABLE auth_totp_steps (principal_id text PRIMARY KEY NOT NULL, last_step integer NOT NULL);
 `).Error
}
