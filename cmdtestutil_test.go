//go:build !windows

package keyring

import (
	"fmt"
	"os/exec"
	"testing"
)

func runCmd(t *testing.T, cmds ...string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), cmds[0], cmds[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println(cmd)
		fmt.Println(string(out))
		t.Fatal(err)
	}
}
