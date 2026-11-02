//go:build linux

package awg

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Up brings the interface up. awg-quick uses the kernel module when the host has
// it and falls back to amneziawg-go otherwise.
func Up(confPath string) error {
	return run("awg-quick", "up", confPath)
}

// Down removes the interface.
func Down(confPath string) error {
	return run("awg-quick", "down", confPath)
}

// InterfaceExists reports whether the AmneziaWG interface is present.
func InterfaceExists(iface string) bool {
	return exec.Command("awg", "show", iface).Run() == nil
}

// LatestHandshakes returns the last handshake time per peer public key.
func LatestHandshakes(iface string) (map[string]time.Time, error) {
	out, err := exec.Command("awg", "show", iface, "latest-handshakes").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("awg show %s: %w: %s", iface, err, strings.TrimSpace(string(out)))
	}
	return parseHandshakes(string(out))
}

// SetEndpoint sets the peer's endpoint, resolving a hostname anew.
func SetEndpoint(iface, publicKey, endpoint string) error {
	return run("awg", "set", iface, "peer", publicKey, "endpoint", endpoint)
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
