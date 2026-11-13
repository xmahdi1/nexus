package migrations

import "gorm.io/gorm"

// Identity adds dormant local accounts. HTTP authentication is deliberately not
// switched over until revocable sessions, MFA migration and authorization ship.
func Identity(tx *gorm.DB) error {
	return tx.Exec(`CREATE TABLE users (
 id text PRIMARY KEY NOT NULL,
 username text NOT NULL UNIQUE CHECK (
  length(username) BETWEEN 3 AND 64 AND username = lower(trim(username))
  AND username NOT GLOB '*[^a-z0-9_.-]*' AND username GLOB '[a-z0-9]*'
 ),
 display_name text NOT NULL CHECK(length(display_name) BETWEEN 1 AND 120),
 email text,
 password_hash text NOT NULL,
 status text NOT NULL CHECK(status IN ('invited','active','disabled')),
 created_at datetime NOT NULL,
 updated_at datetime NOT NULL,
 last_login_at datetime,
 CHECK(status != 'active' OR length(password_hash) > 0)
 );
 CREATE TABLE identity_bootstrap (
 id integer PRIMARY KEY CHECK(id = 1),
 owner_user_id text NOT NULL UNIQUE REFERENCES users(id) ON DELETE RESTRICT,
 created_at datetime NOT NULL,
 source text NOT NULL CHECK(source = 'local_cli')
 );`).Error
}
