package migrations

import "gorm.io/gorm"

func InventoryDocker(tx *gorm.DB) error {
	return tx.Exec(`
ALTER TABLE inventory_containers ADD COLUMN image_id text NOT NULL DEFAULT '';
ALTER TABLE inventory_containers ADD COLUMN health text NOT NULL DEFAULT '';
ALTER TABLE inventory_containers ADD COLUMN compose_project text NOT NULL DEFAULT '';

CREATE TABLE inventory_docker_networks (
    resource_id text PRIMARY KEY NOT NULL,
    engine_id text NOT NULL,
    name text NOT NULL,
    driver text NOT NULL,
    scope text NOT NULL
);
CREATE TABLE inventory_docker_volumes (
    resource_id text PRIMARY KEY NOT NULL,
    name text NOT NULL,
    driver text NOT NULL,
    scope text NOT NULL
);
CREATE TABLE inventory_docker_images (
    resource_id text PRIMARY KEY NOT NULL,
    engine_id text NOT NULL,
    "references" text NOT NULL
);
CREATE TABLE inventory_compose_projects (
    resource_id text PRIMARY KEY NOT NULL,
    name text NOT NULL
);`).Error
}
