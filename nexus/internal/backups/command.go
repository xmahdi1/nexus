package backups

import (
	"bytes"
	"compress/zlib"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

//go:embed engine.py
var engine string

//go:embed pins.json
var pins string

func engineSource() string { return "PINS=" + pins + "\n" + engine }
func Command() string {
	var data bytes.Buffer
	writer := zlib.NewWriter(&data)
	_, _ = writer.Write([]byte(engineSource()))
	_ = writer.Close()
	code := fmt.Sprintf("import base64,zlib;exec(compile(zlib.decompress(base64.b64decode(%q)),\"nexus-backup\",\"exec\"))", base64.StdEncoding.EncodeToString(data.Bytes()))
	return "exec /usr/bin/python3 -I -c '" + code + "'"
}
func privateRequest(action string, policy Policy, definition sealedDefinition, runID, workRoot, snapshot, nexusDirectory string) ([]byte, error) {
	return json.Marshal(struct {
		Action         string     `json:"action"`
		PolicyID       string     `json:"policyId"`
		RunID          string     `json:"runId"`
		Definition     Definition `json:"definition"`
		WorkRoot       string     `json:"workRoot"`
		RuntimeSeconds int        `json:"runtimeSeconds"`
		SnapshotID     string     `json:"snapshotId,omitempty"`
		NexusDirectory string     `json:"nexusDirectory,omitempty"`
	}{action, policy.ID, runID, definition.Definition, workRoot, definition.RuntimeSeconds, snapshot, nexusDirectory})
}
