package ansible

import (
	"bytes"
	"compress/zlib"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

//go:embed job_remote.py
var jobRemote string

//go:embed collections.py
var collectionInstaller string

//go:embed job_callback.py
var jobCallback string

func jobSource() string {
	callback, _ := json.Marshal(jobCallback)
	collections, _ := json.Marshal(collectionInstaller)
	return "CALLBACK=" + string(callback) + "\nCOLLECTIONS=" + string(collections) + "\n" + jobRemote
}
func jobCommand() string {
	// Only fixed embedded source is compressed. Preserve the supervisor's small
	// command limit rather than expanding its caller-controlled transport surface.
	var buffer bytes.Buffer
	writer := zlib.NewWriter(&buffer)
	_, _ = writer.Write([]byte(jobSource()))
	_ = writer.Close()
	code := fmt.Sprintf("import base64,zlib;exec(compile(zlib.decompress(base64.b64decode(%q)),\"nexus-ansible\",\"exec\"))", base64.StdEncoding.EncodeToString(buffer.Bytes()))
	return "exec /usr/bin/python3 -I -c '" + code + "'"
}
