package ansible

import (
	"encoding/json"
	"io"
	"strings"
)

type TaskResult struct {
	Task       int    `json:"task"`
	ServerID   string `json:"serverId"`
	Status     string `json:"status"`
	StartedMS  int    `json:"startedMs"`
	DurationMS int    `json:"durationMs"`
}

type ExecutionResult struct {
	Stage          string                    `json:"stage,omitempty"`
	State          string                    `json:"state"`
	ExitCode       int                       `json:"exitCode"`
	Hosts          map[string]map[string]int `json:"hosts"`
	Version        string                    `json:"version"`
	Tasks          []TaskResult              `json:"tasks"`
	TasksTruncated bool                      `json:"tasksTruncated"`
}

// ParseExecutionResult accepts only the fixed numeric result format and selected
// targets. Older numeric-only runs remain readable; arbitrary output is hidden.
func ParseExecutionResult(output string, targets []Target) *ExecutionResult {
	if len(output) > 65536 {
		return nil
	}
	var result ExecutionResult
	decoder := json.NewDecoder(strings.NewReader(output))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || result.ExitCode < 0 || result.ExitCode > 255 || len(result.Tasks) > 200 || len(result.Hosts) > 10 {
		return nil
	}
	if decoder.Decode(new(any)) != io.EOF {
		return nil
	}
	if result.State == "playbook_setup_or_process_failed" {
		stages := map[string]bool{"prerequisites": true, "managed_environment": true, "dedicated_account": true, "managed_environment_version": true, "collections_install": true, "playbook_process": true}
		if !stages[result.Stage] || len(result.Tasks) != 0 || len(result.Hosts) != 0 || result.Version != "" {
			return nil
		}
		return &ExecutionResult{State: result.State, Stage: result.Stage, Tasks: []TaskResult{}}
	}
	if result.State != "playbook_exited" || result.Version != "2.22.0" || result.Stage != "" {
		return nil
	}
	allowed := map[string]bool{}
	for _, target := range targets {
		allowed[target.ServerID] = true
	}
	fields := map[string]bool{"ok": true, "changed": true, "failures": true, "unreachable": true, "skipped": true, "rescued": true, "ignored": true}
	for id, counts := range result.Hosts {
		if !allowed[id] || len(counts) != len(fields) {
			return nil
		}
		for name, value := range counts {
			if !fields[name] || value < 0 || value > 1000000 {
				return nil
			}
		}
	}
	statuses := map[string]bool{"ok": true, "changed": true, "failed": true, "ignored": true, "unreachable": true, "skipped": true}
	for _, task := range result.Tasks {
		if !allowed[task.ServerID] || !statuses[task.Status] || task.Task < 1 || task.Task > 1000000 || task.StartedMS < 0 || task.StartedMS > 600000 || task.DurationMS < 0 || task.DurationMS > 600000 {
			return nil
		}
	}
	if result.Tasks == nil {
		result.Tasks = []TaskResult{}
	}
	return &result
}
