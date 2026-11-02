//go:build linux

package awg

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	// resolveTimeout covers awg retrying a hostname: up to 15 retries, about two
	// minutes when the name server does not answer.
	resolveTimeout = 5 * time.Minute
	commandTimeout = 30 * time.Second
)

// CheckTools reports whether the tools are installed, so that a missing one fails at
// start instead of looking like a tunnel that keeps failing to come up.
func CheckTools() error {
	for _, tool := range []string{"awg-quick", "awg"} {
		if _, err := exec.LookPath(tool); err != nil {
			return err
		}
	}
	return nil
}

// Up brings the interface up. awg-quick uses the kernel module when the host has
// it and falls back to amneziawg-go otherwise.
func Up(confPath string) error {
	return run(resolveTimeout, "awg-quick", "up", confPath)
}

// Down removes the interface.
func Down(confPath string) error {
	return run(commandTimeout, "awg-quick", "down", confPath)
}

// InterfaceExists reports whether the AmneziaWG interface is present.
func InterfaceExists(iface string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	return exec.CommandContext(ctx, "awg", "show", iface).Run() == nil
}

// LatestHandshakes returns the last handshake time per peer public key.
func LatestHandshakes(iface string) (map[string]time.Time, error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "awg", "show", iface, "latest-handshakes")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("awg show %s: %w", iface, err)
	}
	return parseHandshakes(string(out))
}

// SetEndpoint sets the peer's endpoint, resolving a hostname anew.
func SetEndpoint(iface, publicKey, endpoint string) error {
	return run(resolveTimeout, "awg", "set", iface, "peer", publicKey, "endpoint", endpoint)
}

// run sends the output straight to the log rather than through a pipe. With LOG_LEVEL
// set, amneziawg-go stays in the background holding awg-quick's output for life, so
// reading a pipe would never end, and closing it would kill the daemon at its next
// log line.
func run(timeout time.Duration, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}
