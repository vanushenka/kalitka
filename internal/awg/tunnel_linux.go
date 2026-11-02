//go:build linux

package awg

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/ipc"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

const (
	commandTimeout = 30 * time.Second
	capNetAdmin    = 12
)

// CheckSystem reports what retrying cannot cure, so that it fails at start instead of
// looking like a tunnel that keeps failing to come up.
func CheckSystem() error {
	if _, err := exec.LookPath("ip"); err != nil {
		return err
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		return err
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	allowed, err := hasNetAdmin(string(status))
	if err != nil {
		return err
	}
	if !allowed {
		return errors.New("creating a tunnel needs root, and in a container also NET_ADMIN")
	}
	return nil
}

// hasNetAdmin reads the effective capabilities from /proc/self/status, because root in
// a container may not have this one.
func hasNetAdmin(status string) (bool, error) {
	for _, line := range strings.Split(status, "\n") {
		if value, ok := strings.CutPrefix(line, "CapEff:"); ok {
			capabilities, err := strconv.ParseUint(strings.TrimSpace(value), 16, 64)
			if err != nil {
				return false, fmt.Errorf("unexpected capabilities %q: %w", value, err)
			}
			return capabilities&(1<<capNetAdmin) != 0, nil
		}
	}
	return false, errors.New("no effective capabilities in the process status")
}

// createInterface checks the name first: on a busy name tun.CreateTUN fails without
// closing what it has opened, and the supervisor retries for as long as we run. An
// interface of ours never outlives its process, so one that exists is someone else's.
func createInterface(name string, mtu int) (tun.Device, error) {
	if _, err := net.InterfaceByName(name); err == nil {
		return nil, errors.New("an interface with this name already exists: another program holds it")
	}
	return tun.CreateTUN(name, mtu)
}

func configureInterface(name string, address netip.Prefix) error {
	if err := runIP("-4", "address", "add", address.String(), "dev", name); err != nil {
		return err
	}
	return runIP("link", "set", "up", "dev", name)
}

func runIP(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	if output, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("ip %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

// openControl opens the socket the upstream tools talk to, so that `awg show` works on
// a running tunnel as it does with a standalone amneziawg-go. Only root can connect.
func openControl(name string, engine *device.Device, log *slog.Logger) (io.Closer, error) {
	file, err := ipc.UAPIOpen(name)
	if err != nil {
		return nil, err
	}
	// UAPIListen works on a copy of the descriptor.
	defer file.Close()
	listener, err := ipc.UAPIListen(name, file)
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					log.Warn("the control socket stopped, so awg show will not work", "error", err)
				}
				return
			}
			go engine.IpcHandle(connection)
		}
	}()
	return listener, nil
}
