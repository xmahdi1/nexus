package ansible

import (
	"encoding/json"
	"testing"
)

func TestTaskResultsRejectUnselectedTargetsPayloadsAndUnboundedValues(t *testing.T) {
	base := `{"state":"playbook_exited","version":"2.22.0","exitCode":0,"hosts":{"dev":{"ok":1,"changed":0,"failures":0,"unreachable":0,"skipped":0,"rescued":0,"ignored":0}},"tasks":[{"task":1,"serverId":"dev","status":"ok","startedMs":1,"durationMs":10}],"tasksTruncated":false}`
	targets := []Target{{ServerID: "dev"}}
	if result := ParseExecutionResult(base, targets); result == nil || len(result.Tasks) != 1 {
		t.Fatal("valid result rejected")
	}
	for _, mutate := range []func(map[string]any){
		func(v map[string]any) { v["output"] = "private" },
		func(v map[string]any) { v["tasks"].([]any)[0].(map[string]any)["serverId"] = "prod" },
		func(v map[string]any) { v["tasks"].([]any)[0].(map[string]any)["status"] = "private-task-name" },
		func(v map[string]any) { v["tasks"].([]any)[0].(map[string]any)["durationMs"] = 600001 },
		func(v map[string]any) { v["tasks"].([]any)[0].(map[string]any)["task"] = 0 },
		func(v map[string]any) { v["hosts"].(map[string]any)["prod"] = v["hosts"].(map[string]any)["dev"] },
		func(v map[string]any) { v["tasks"] = make([]any, 201) },
	} {
		var value map[string]any
		_ = json.Unmarshal([]byte(base), &value)
		mutate(value)
		data, _ := json.Marshal(value)
		if ParseExecutionResult(string(data), targets) != nil {
			t.Fatal("invalid task metadata admitted", string(data))
		}
	}
	if ParseExecutionResult(base+` {}`, targets) != nil {
		t.Fatal("trailing result admitted")
	}
	old := `{"state":"playbook_exited","version":"2.22.0","exitCode":0,"hosts":{}}`
	if ParseExecutionResult(old, targets) == nil {
		t.Fatal("old recap result unavailable")
	}
}
