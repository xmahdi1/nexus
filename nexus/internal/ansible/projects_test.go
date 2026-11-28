package ansible

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestImmutableProjectContentAndArchive(t *testing.T) {
	s, a, _, p, r := fixture(t)
	rows, err := s.Revisions(a, "controller", p.ID)
	if err != nil || len(rows) != 1 || rows[0].Digest != r.Digest {
		t.Fatal("revision metadata unavailable", err)
	}
	encoded, _ := json.Marshal(rows)
	if strings.Contains(string(encoded), "private-playbook") || strings.Contains(string(encoded), "bundleEnc") {
		t.Fatal("metadata revealed content")
	}
	bundle, err := s.Content(a, "controller", p.ID, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.CreateRevision(a, "controller", p.ID, bundle)
	if err != nil || second.ID == r.ID || second.Digest == r.Digest {
		t.Fatal("revision was overwritten or salts reused", err)
	}
	if err := s.Archive(a, "controller", p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateRevision(a, "controller", p.ID, bundle); !errors.Is(err, ErrConflict) {
		t.Fatal("archived project was edited", err)
	}
	if _, err := s.Content(a, "controller", p.ID, r.ID); err != nil {
		t.Fatal("archiving erased historical content", err)
	}
}
