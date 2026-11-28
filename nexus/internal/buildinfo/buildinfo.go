package buildinfo

import (
	"runtime"
	"runtime/debug"
)

// Release builds set these fields at link time.
var (
	version = "dev"
	commit  = ""
	built   = ""
)

type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
	Built   string `json:"built,omitempty"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

func Current() Info {
	info := Info{Version: version, Commit: commit, Built: built, OS: runtime.GOOS, Arch: runtime.GOARCH}
	if info.Commit == "" {
		if vcs, ok := debug.ReadBuildInfo(); ok {
			for _, setting := range vcs.Settings {
				if setting.Key == "vcs.revision" {
					info.Commit = setting.Value
					break
				}
			}
		}
	}
	return info
}
