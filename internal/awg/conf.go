package awg

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	minMTU = 1280
	maxMTU = 1500
)

var (
	hostFormat = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)
	// interfaceFormat is what awg-quick accepts as a config's file name.
	interfaceFormat = regexp.MustCompile(`^[a-zA-Z0-9_=+.-]{1,15}$`)
)

// Config is one AmneziaWG interface in the form awg-quick reads.
type Config struct {
	PrivateKey string
	Address    netip.Prefix
	ListenPort int // 0: the interface picks a port and only dials out.
	MTU        int
	Params     Params
	Peers      []Peer
}

// Peer is the other end of a tunnel.
type Peer struct {
	PublicKey           string
	AllowedIPs          []netip.Prefix
	Endpoint            string // Empty: the peer dials in and its address is learned.
	PersistentKeepalive int
}

// Validate checks every value that Render writes, whichever source it came from.
func (c Config) Validate() error {
	if err := ValidateKey(c.PrivateKey); err != nil {
		return fmt.Errorf("private key: %w", err)
	}
	if !c.Address.IsValid() {
		return errors.New("no interface address")
	}
	if c.ListenPort < 0 || c.ListenPort > 65535 {
		return fmt.Errorf("listen port %d is not valid", c.ListenPort)
	}
	if c.MTU < minMTU || c.MTU > maxMTU {
		return fmt.Errorf("MTU %d is outside %d-%d", c.MTU, minMTU, maxMTU)
	}
	if err := c.Params.Validate(); err != nil {
		return fmt.Errorf("params: %w", err)
	}
	for _, peer := range c.Peers {
		if err := ValidateKey(peer.PublicKey); err != nil {
			return fmt.Errorf("peer public key: %w", err)
		}
		for _, prefix := range peer.AllowedIPs {
			if !prefix.IsValid() {
				return errors.New("peer has an invalid allowed IP")
			}
		}
		if peer.Endpoint != "" {
			if err := ValidateEndpoint(peer.Endpoint); err != nil {
				return err
			}
		}
		if peer.PersistentKeepalive < 0 || peer.PersistentKeepalive > 65535 {
			return fmt.Errorf("keepalive %d is not valid", peer.PersistentKeepalive)
		}
	}
	return nil
}

// ValidateEndpoint checks a host:port. A zone is refused because netip accepts any
// text after the % sign, line breaks included.
func ValidateEndpoint(endpoint string) error {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return fmt.Errorf("endpoint %q: %w", endpoint, err)
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return fmt.Errorf("endpoint %q has an address zone", endpoint)
		}
	} else if !hostFormat.MatchString(host) {
		return fmt.Errorf("endpoint %q has an invalid host", endpoint)
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return fmt.Errorf("endpoint %q has an invalid port", endpoint)
	}
	return nil
}

// Render returns the config file text. Table is off so that awg-quick adds no routes
// for the peers; the interface's own address still gets its connected route.
func (c Config) Render() string {
	var b strings.Builder
	line := func(key string, value any) { fmt.Fprintf(&b, "%s = %v\n", key, value) }

	b.WriteString("[Interface]\n")
	line("PrivateKey", c.PrivateKey)
	line("Address", c.Address)
	if c.ListenPort != 0 {
		line("ListenPort", c.ListenPort)
	}
	line("MTU", c.MTU)
	line("Table", "off")
	p := c.Params
	line("Jc", p.Jc)
	line("Jmin", p.Jmin)
	line("Jmax", p.Jmax)
	line("S1", p.S1)
	line("S2", p.S2)
	line("S3", p.S3)
	line("S4", p.S4)
	// With a header protection key the wire looks random for any H, so random ranges
	// hide nothing; the values must only not overlap.
	line("H1", 1)
	line("H2", 2)
	line("H3", 3)
	line("H4", 4)
	line("I1", p.I1)
	line("HeaderProtectionKey", p.HeaderProtectionKey)
	line("ContentPaddingAddition", "32-128")

	for _, peer := range c.Peers {
		b.WriteString("\n[Peer]\n")
		line("PublicKey", peer.PublicKey)
		allowed := make([]string, len(peer.AllowedIPs))
		for i, prefix := range peer.AllowedIPs {
			allowed[i] = prefix.String()
		}
		line("AllowedIPs", strings.Join(allowed, ", "))
		if peer.Endpoint != "" {
			line("Endpoint", peer.Endpoint)
		}
		if peer.PersistentKeepalive != 0 {
			line("PersistentKeepalive", peer.PersistentKeepalive)
		}
	}
	return b.String()
}

// WriteConf validates the config and writes it to dir/<iface>.conf, the name
// awg-quick derives the interface name from, and returns the path. This is the only
// way a config reaches awg-quick, which runs PostUp lines as commands, so state read
// from disk gets the same checks as an invite. The file holds private keys.
func WriteConf(dir, iface string, c Config) (string, error) {
	if !interfaceFormat.MatchString(iface) {
		return "", fmt.Errorf("interface name %q is not valid", iface)
	}
	if err := c.Validate(); err != nil {
		return "", fmt.Errorf("%s config: %w", iface, err)
	}
	path := filepath.Join(dir, iface+".conf")
	if err := os.WriteFile(path, []byte(c.Render()), 0o600); err != nil {
		return "", fmt.Errorf("write %s config: %w", iface, err)
	}
	return path, nil
}

// parseHandshakes reads the output of `awg show <iface> latest-handshakes`: one
// "<public key>\t<unix seconds>" line per peer, 0 when there was no handshake yet.
func parseHandshakes(output string) (map[string]time.Time, error) {
	handshakes := make(map[string]time.Time)
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line == "" {
			continue
		}
		key, seconds, ok := strings.Cut(line, "\t")
		if !ok {
			return nil, fmt.Errorf("unexpected latest-handshakes line %q", line)
		}
		unix, err := strconv.ParseInt(seconds, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("unexpected latest-handshakes line %q: %w", line, err)
		}
		handshakes[key] = time.Unix(unix, 0)
	}
	return handshakes, nil
}
