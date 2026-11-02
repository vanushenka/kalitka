//go:build !linux

package awg

import (
	"errors"
	"runtime"
	"time"
)

// Everything except running a tunnel works on any OS. A port replaces this file
// with one that drives the platform's AmneziaWG tools.
var errUnsupported = errors.New("running a tunnel is not supported on " + runtime.GOOS + " yet")

// Up is not implemented on this OS.
func Up(string) error { return errUnsupported }

// Down is not implemented on this OS.
func Down(string) error { return errUnsupported }

// InterfaceExists is not implemented on this OS.
func InterfaceExists(string) bool { return false }

// LatestHandshakes is not implemented on this OS.
func LatestHandshakes(string) (map[string]time.Time, error) { return nil, errUnsupported }

// SetEndpoint is not implemented on this OS.
func SetEndpoint(string, string, string) error { return errUnsupported }
