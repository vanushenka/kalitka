package awg

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
)

const resolveTimeout = 30 * time.Second

// Tunnel is one AmneziaWG interface, with the engine running inside this process. Its
// methods must not be called concurrently.
type Tunnel struct {
	iface   string
	config  Config
	log     *slog.Logger
	engine  *device.Device // Nil while the tunnel is down.
	control io.Closer
}

// NewTunnel validates the config, so that a bad one fails here rather than on every
// attempt to bring the tunnel up. This is the only way a config reaches the engine, so
// state read from disk gets the same checks as an invite.
func NewTunnel(iface string, config Config, log *slog.Logger) (*Tunnel, error) {
	if !interfaceFormat.MatchString(iface) {
		return nil, fmt.Errorf("interface name %q is not valid", iface)
	}
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("%s config: %w", iface, err)
	}
	return &Tunnel{iface: iface, config: config, log: log}, nil
}

// Up creates the interface and starts the engine. A failed Up leaves nothing behind.
func (t *Tunnel) Up(ctx context.Context) error {
	resolved, err := t.resolved(ctx)
	if err != nil {
		return err
	}
	settings, err := resolved.engineConfig()
	if err != nil {
		return err
	}
	iface, err := createInterface(t.iface, t.config.MTU)
	if err != nil {
		return fmt.Errorf("create interface %s: %w", t.iface, err)
	}
	// The engine owns the interface from here, and closing the engine removes it.
	t.engine = device.NewDevice(iface, conn.NewDefaultBind(), t.engineLogger())
	if err := t.start(settings); err != nil {
		t.Down()
		return err
	}
	return nil
}

func (t *Tunnel) start(settings string) error {
	if err := t.engine.IpcSet(settings); err != nil {
		return fmt.Errorf("configure the engine: %w", err)
	}
	if err := t.engine.Up(); err != nil {
		return fmt.Errorf("start the engine: %w", err)
	}
	if err := configureInterface(t.iface, t.config.Address); err != nil {
		return fmt.Errorf("configure interface %s: %w", t.iface, err)
	}
	if t.debug() {
		control, err := openControl(t.iface, t.engine, t.log)
		if err != nil {
			// Only debugging needs the socket, so it must not cost a working tunnel.
			t.log.Warn("the control socket is not available, so awg show will not work", "error", err)
			return nil
		}
		t.control = control
	}
	return nil
}

// debug reports whether debug mode is on. It adds the engine's verbose log and the
// control socket for `awg show`. The socket is not opened otherwise, because a normal
// run does not need it and its path names the engine to whoever hosts a portal.
func (t *Tunnel) debug() bool {
	return t.log.Enabled(context.Background(), slog.LevelDebug)
}

// Down stops the engine and removes the interface. It does nothing if the tunnel is
// already down.
func (t *Tunnel) Down() {
	if t.control != nil {
		if err := t.control.Close(); err != nil {
			t.log.Warn("closing the control socket failed", "error", err)
		}
		t.control = nil
	}
	if t.engine != nil {
		t.engine.Close()
		t.engine = nil
	}
}

// LatestHandshakes returns the last handshake time per peer public key. It fails once
// the engine has stopped by itself, which it does when the interface disappears. The
// tunnel must be up.
func (t *Tunnel) LatestHandshakes() (map[string]time.Time, error) {
	select {
	case <-t.engine.Wait():
		return nil, errors.New("the engine has stopped, usually because the interface is gone")
	default:
	}
	state, err := t.engine.IpcGet()
	if err != nil {
		return nil, fmt.Errorf("read the engine's state: %w", err)
	}
	return parseHandshakes(state)
}

// SetEndpoint sets the peer's endpoint, resolving a hostname anew. The tunnel must be up.
func (t *Tunnel) SetEndpoint(ctx context.Context, publicKey, endpoint string) error {
	public, err := keyHex(publicKey)
	if err != nil {
		return fmt.Errorf("peer public key: %w", err)
	}
	address, err := resolveEndpoint(ctx, endpoint)
	if err != nil {
		return err
	}
	return t.engine.IpcSet(fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=%s\n", public, address))
}

// resolved returns the config with its endpoints as IPs.
func (t *Tunnel) resolved(ctx context.Context) (Config, error) {
	c := t.config
	c.Peers = slices.Clone(c.Peers)
	for i := range c.Peers {
		if c.Peers[i].Endpoint == "" {
			continue
		}
		address, err := resolveEndpoint(ctx, c.Peers[i].Endpoint)
		if err != nil {
			return Config{}, err
		}
		c.Peers[i].Endpoint = address
	}
	return c, nil
}

// resolveEndpoint turns host:port into ip:port. It takes the first address: the resolver
// sorts them by RFC 6724, which puts those this machine has a route to first.
func resolveEndpoint(ctx context.Context, endpoint string) (string, error) {
	if _, err := netip.ParseAddrPort(endpoint); err == nil {
		return endpoint, nil
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", fmt.Errorf("endpoint %q: %w", endpoint, err)
	}
	ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", host, err)
	}
	if len(addresses) == 0 {
		return "", fmt.Errorf("resolve %s: no addresses", host)
	}
	return net.JoinHostPort(addresses[0].Unmap().String(), port), nil
}

// engineLogger sends the engine's errors to our log. Its verbose lines, one per packet
// in places, are formatted only in debug mode.
func (t *Tunnel) engineLogger() *device.Logger {
	logger := &device.Logger{
		Verbosef: device.DiscardLogf,
		Errorf: func(format string, args ...any) {
			t.log.Warn("engine: " + fmt.Sprintf(format, args...))
		},
	}
	if t.debug() {
		logger.Verbosef = func(format string, args ...any) {
			t.log.Debug("engine: " + fmt.Sprintf(format, args...))
		}
	}
	return logger
}
