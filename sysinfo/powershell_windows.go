//go:build windows
// +build windows

package sysinfo

import (
	"context"
	"encoding/json"
	"os/exec"
	"syscall"
	"time"
)

// runPowerShell runs a PowerShell command with a timeout and returns raw
// stdout bytes. The command is executed with -NoProfile and the window hidden.
func runPowerShell(cmd string, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	c := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", cmd)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := c.Output()
	return out, err
}

// runPowerShellJSON runs a PowerShell command expected to emit JSON and
// unmarshals it into v. It returns the raw bytes and any error.
func runPowerShellJSON(cmd string, timeout time.Duration, v interface{}) ([]byte, error) {
	out, err := runPowerShell(cmd, timeout)
	if err != nil {
		return nil, err
	}
	// Try to unmarshal; caller can ignore the unmarshaled result if needed.
	if v != nil {
		_ = json.Unmarshal(out, v)
	}
	return out, nil
}

// runPowerShellString runs PowerShell and returns trimmed stdout as string.
func runPowerShellString(cmd string, timeout time.Duration) (string, error) {
	out, err := runPowerShell(cmd, timeout)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
