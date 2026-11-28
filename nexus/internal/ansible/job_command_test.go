package ansible

import (
	"os/exec"
	"strings"
	"testing"
)

func TestExecutionAdapterFitsAndParsesWithoutStartingProcesses(t *testing.T) {
	command := jobCommand()
	if len(command) > 16384 {
		t.Fatal("fixed adapter exceeds supervisor transport", len(command))
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python source check requires local Python; runtime fixtures validate it separately")
	}
	callback := exec.Command(python, "-I", "-c", "import sys;compile(sys.stdin.read(),'callback','exec')")
	callback.Stdin = strings.NewReader(jobCallback)
	if output, err := callback.CombinedOutput(); err != nil {
		t.Fatal("invalid callback source", string(output))
	}
	// Compile the complete embedded source as well as its compressed bootstrap.
	combined := exec.Command(python, "-I", "-c", "import sys;compile(sys.stdin.read(),'combined','exec')")
	combined.Stdin = strings.NewReader(jobSource())
	if output, err := combined.CombinedOutput(); err != nil {
		t.Fatal("invalid embedded source", string(output))
	}
	// Test the actual shell-escaped, combined callback/adapter command as source;
	// patch only its invocation to compile rather than execute any staging code.
	compile := strings.Replace(command, "exec /usr/bin/python3 -I -c '", "printf %s '", 1)
	shell := exec.Command("/bin/sh", "-c", compile)
	source, err := shell.Output()
	if err != nil {
		t.Fatal("invalid shell escaping", err)
	}
	probe := exec.Command(python, "-I", "-c", "import sys;compile(sys.stdin.read(),'adapter','exec')")
	probe.Stdin = strings.NewReader(string(source))
	if output, err := probe.CombinedOutput(); err != nil {
		t.Fatal("invalid combined adapter", string(output))
	}
}
