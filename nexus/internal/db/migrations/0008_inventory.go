package migrations

import "gorm.io/gorm"

func Inventory(tx *gorm.DB) error {
	return tx.Exec(`
 CREATE TABLE discovery_runs(id text PRIMARY KEY NOT NULL,server_id text NOT NULL,actor_id text NOT NULL,status text NOT NULL,started_at datetime NOT NULL,finished_at datetime,warning text NOT NULL DEFAULT '');
 CREATE INDEX idx_discovery_runs_server ON discovery_runs(server_id,started_at);
 CREATE UNIQUE INDEX idx_discovery_one_running ON discovery_runs(server_id) WHERE status='running';
 CREATE TABLE inventory_resources(id text PRIMARY KEY NOT NULL,server_id text NOT NULL,kind text NOT NULL,natural_key text NOT NULL,display_name text NOT NULL,source text NOT NULL,fingerprint text NOT NULL,first_seen_at datetime NOT NULL,last_seen_at datetime NOT NULL,last_verified_at datetime NOT NULL,data_state text NOT NULL,UNIQUE(server_id,kind,natural_key));
 CREATE INDEX idx_inventory_scope ON inventory_resources(server_id,kind);
 CREATE TABLE inventory_hosts(resource_id text PRIMARY KEY NOT NULL,hostname text NOT NULL,os text NOT NULL,kernel text NOT NULL);
 CREATE TABLE inventory_containers(resource_id text PRIMARY KEY NOT NULL,engine_id text NOT NULL,image text NOT NULL,state text NOT NULL);
 CREATE TABLE inventory_ports(resource_id text PRIMARY KEY NOT NULL,container_id text NOT NULL,protocol text NOT NULL,address text NOT NULL,port integer NOT NULL,target_port integer NOT NULL,exposure text NOT NULL);
 CREATE TABLE inventory_changes(id integer PRIMARY KEY AUTOINCREMENT,server_id text NOT NULL,run_id text NOT NULL,resource_id text NOT NULL,kind text NOT NULL,at datetime NOT NULL);
 CREATE INDEX idx_inventory_changes_server ON inventory_changes(server_id,id);
 `).Error
}
