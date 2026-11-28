package db

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestAllEncryptedColumnsParticipateInKeyValidationAndRotation(t *testing.T) {
	database, err := Init(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	connection, _ := database.DB()
	defer connection.Close()
	registered := map[string]bool{}
	for _, field := range secretFields {
		registered[field.table+"."+field.column] = true
	}
	tables, err := database.Migrator().GetTables()
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range tables {
		columns, err := database.Migrator().ColumnTypes(table)
		if err != nil {
			t.Fatal(err)
		}
		for _, column := range columns {
			if strings.HasSuffix(column.Name(), "_enc") && !registered[table+"."+column.Name()] {
				t.Errorf("encrypted field missing from validation/rotation registry: %s.%s", table, column.Name())
			}
		}
	}
}
