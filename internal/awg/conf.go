package awg

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
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
	// interfaceFormat fits the kernel's limit on interface names. The name also becomes
	// a file name for the control socket, so it must not be able to leave that folder.
	interfaceFormat = regexp.MustCompile(`^[a-zA-Z0-9_=+.-]{1,15}$`)
)

// Config is one AmneziaWG interface.
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

// Validate checks every value that engineConfig writes, whichever source it came from.
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
// text after the % sign, line breaks included. A port in any form but the plain number,
// such as +443, is refused because the engine would refuse it on every attempt.
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
	if err != nil || number < 1 || number > 65535 || strconv.Itoa(number) != port {
		return fmt.Errorf("endpoint %q has an invalid port", endpoint)
	}
	return nil
}

// engineConfig returns the settings in the engine's format, one key=value per line. A
// value holding a line break could add a setting, which Validate rules out. Endpoints
// must hold an IP by now: the engine does not resolve names.
func (c Config) engineConfig() (string, error) {
	var b strings.Builder
	line := func(key string, value any) { fmt.Fprintf(&b, "%s=%v\n", key, value) }

	private, err := keyHex(c.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("private key: %w", err)
	}
	line("private_key", private)
	if c.ListenPort != 0 {
		line("listen_port", c.ListenPort)
	}
	p := c.Params
	line("jc", p.Jc)
	line("jmin", p.Jmin)
	line("jmax", p.Jmax)
	line("s1", p.S1)
	line("s2", p.S2)
	line("s3", p.S3)
	line("s4", p.S4)
	// With a header protection key the wire looks random for any H, so random ranges
	// hide nothing; the values must only not overlap.
	line("h1", 1)
	line("h2", 2)
	line("h3", 3)
	line("h4", 4)
	line("i1", p.I1)
	protection, err := keyHex(p.HeaderProtectionKey)
	if err != nil {
		return "", fmt.Errorf("header protection key: %w", err)
	}
	line("header_protection_key", protection)
	line("content_padding_addition", "32-128")

	for _, peer := range c.Peers {
		public, err := keyHex(peer.PublicKey)
		if err != nil {
			return "", fmt.Errorf("peer public key: %w", err)
		}
		line("public_key", public)
		if peer.Endpoint != "" {
			line("endpoint", peer.Endpoint)
		}
		if peer.PersistentKeepalive != 0 {
			line("persistent_keepalive_interval", peer.PersistentKeepalive)
		}
		for _, prefix := range peer.AllowedIPs {
			line("allowed_ip", prefix)
		}
	}
	return b.String(), nil
}

// parseHandshakes reads the engine's state: a public_key line starts a peer, and its
// last_handshake_time_sec line follows. A time of 0 means no handshake yet.
func parseHandshakes(state string) (map[string]time.Time, error) {
	handshakes := make(map[string]time.Time)
	peer := ""
	for _, line := range strings.Split(state, "\n") {
		key, value, _ := strings.Cut(line, "=")
		switch key {
		case "public_key":
			raw, err := hex.DecodeString(value)
			if err != nil || len(raw) != keySize {
				return nil, fmt.Errorf("unexpected public key %q in the engine's state", value)
			}
			peer = keyEncoding.EncodeToString(raw)
		case "last_handshake_time_sec":
			if peer == "" {
				return nil, errors.New("a handshake time comes before any peer in the engine's state")
			}
			unix, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("unexpected handshake time %q in the engine's state: %w", value, err)
			}
			handshakes[peer] = time.Unix(unix, 0)
		}
	}
	return handshakes, nil
}
