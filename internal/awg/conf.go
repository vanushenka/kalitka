package awg

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
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

// Render returns the config file text. Table is always off: Kalitka owns its
// routes, and the host's routing table is left alone.
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
	line("H1", p.H1)
	line("H2", p.H2)
	line("H3", p.H3)
	line("H4", p.H4)
	if p.I1 != "" {
		line("I1", p.I1)
	}
	line("HeaderProtectionKey", p.HeaderProtectionKey)
	line("ContentPaddingAddition", p.ContentPaddingAddition)

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

// WriteConf writes the config to dir/<iface>.conf, the name awg-quick derives the
// interface name from, and returns the path. The file holds private keys.
func WriteConf(dir, iface string, c Config) (string, error) {
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
