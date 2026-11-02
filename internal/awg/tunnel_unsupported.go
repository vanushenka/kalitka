//go:build !linux

package awg

import (
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"runtime"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// Everything except running a tunnel works on any OS.
var errUnsupported = errors.New("running a tunnel is not supported on " + runtime.GOOS + " yet")

// CheckSystem fails: this OS cannot run a tunnel yet.
func CheckSystem() error { return errUnsupported }

func createInterface(string, int) (tun.Device, error) { return nil, errUnsupported }

func configureInterface(string, netip.Prefix) error { return errUnsupported }

func openControl(string, *device.Device, *slog.Logger) (io.Closer, error) {
	return nil, errUnsupported
}
