package awg

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
)

func TestPublicKeyMatchesRFC7748(t *testing.T) {
	private, err := hex.DecodeString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	if err != nil {
		t.Fatal(err)
	}
	got, err := PublicKey(base64.StdEncoding.EncodeToString(private))
	if err != nil {
		t.Fatal(err)
	}
	if got != base64.StdEncoding.EncodeToString(want) {
		t.Errorf("PublicKey = %s, want %x", got, want)
	}
}

func TestGenerateKeyIsClamped(t *testing.T) {
	raw, err := base64.StdEncoding.DecodeString(GenerateKey())
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != keySize {
		t.Fatalf("key is %d bytes", len(raw))
	}
	if raw[0]&7 != 0 || raw[31]&128 != 0 || raw[31]&64 == 0 {
		t.Errorf("key %x is not clamped", raw)
	}
}

func TestValidateKeyRejects(t *testing.T) {
	valid := GenerateKey()
	for name, key := range map[string]string{
		"empty":      "",
		"short":      valid[:20],
		"line break": valid[:20] + "\n" + valid[21:],
		"trailing":   valid + "\n",
		"not base64": strings.Repeat("!", 43) + "=",
		// The upstream tools refuse non-zero trailing bits, and a client's app uses them;
		// a lax decoder would let through a key that a peer can never load.
		"non-canonical": strings.Repeat("A", 42) + "B=",
	} {
		if err := ValidateKey(key); err == nil {
			t.Errorf("%s: accepted %q", name, key)
		}
	}
}

func TestNewParamsHoldsTheProfile(t *testing.T) {
	i1 := regexp.MustCompile(`^<r 2><b 0x[0-9a-f]{22}><rc [0-9]{2}><b 0x([0-9a-f]{2})+>$`)
	for range 2000 {
		p := NewParams()
		if err := p.Validate(); err != nil {
			t.Fatalf("%+v: %v", p, err)
		}
		if p.Jc < 3 || p.Jc > 6 || p.Jmin < 40 || p.Jmin > 89 || p.Jmax < p.Jmin+50 || p.Jmax > p.Jmin+250 {
			t.Fatalf("junk settings out of range: %+v", p)
		}
		if p.S1 < 15 || p.S1 > 150 || p.S2 < 15 || p.S2 > 150 || p.S3 < 12 || p.S3 > 55 || p.S4 < 12 || p.S4 > 27 {
			t.Fatalf("paddings out of range: %+v", p)
		}
		if !i1.MatchString(p.I1) {
			t.Fatalf("I1 has the wrong shape: %s", p.I1)
		}
	}
}

func TestDataSizeCollides(t *testing.T) {
	for _, c := range []struct {
		name           string
		s1, s2, s3, s4 int
		want           bool
	}{
		{"no match", 16, 16, 16, 16, false},
		{"initiation", 15, 13, 13, 19, true},
		{"initiation at 128 is excluded", 24, 13, 13, 12, false},
		{"response", 13, 20, 13, 16, true},
		{"cookie", 13, 13, 30, 14, true},
	} {
		if got := dataSizeCollides(c.s1, c.s2, c.s3, c.s4); got != c.want {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
}

func TestParamsValidateRejects(t *testing.T) {
	for name, change := range map[string]func(*Params){
		"Jc too large":      func(p *Params) { p.Jc = junkCountRange.hi + 1 },
		"Jmax below Jmin":   func(p *Params) { p.Jmax = p.Jmin - 1 },
		"Jmax too far":      func(p *Params) { p.Jmax = p.Jmin + junkSpreadRange.hi + 1 },
		"S4 below nonce":    func(p *Params) { p.S4 = 4 },
		"S1 too large":      func(p *Params) { p.S1 = 1000 },
		"init and response": func(p *Params) { p.S1, p.S2 = 20, 76 },
		"response, cookie":  func(p *Params) { p.S2, p.S3 = 15, 43 },
		"data collision":    func(p *Params) { p.S1, p.S2, p.S3, p.S4 = 15, 15, 12, 19 },
		"I1 adds a line":    func(p *Params) { p.I1 += "\nallowed_ip=0.0.0.0/0" },
		"I1 huge lengths":   func(p *Params) { p.I1 = strings.Repeat("<r 9999>", 7) },
		"I1 kernel-only":    func(p *Params) { p.I1 = "<c>" },
		"I1 empty":          func(p *Params) { p.I1 = "" },
		"I1 odd hex":        func(p *Params) { p.I1 = "<r 2><b 0xabc>" },
		"short key":         func(p *Params) { p.HeaderProtectionKey = "short" },
		"zero key":          func(p *Params) { p.HeaderProtectionKey = zeroKey },
	} {
		p := NewParams()
		change(&p)
		if err := p.Validate(); err == nil {
			t.Errorf("%s: accepted %+v", name, p)
		}
	}
}

// base64Key turns a key in hex into the form Config holds.
func base64Key(t *testing.T, hexKey string) string {
	t.Helper()
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func TestEngineConfig(t *testing.T) {
	const (
		private    = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
		public     = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
		protection = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
	)
	config := Config{
		PrivateKey: base64Key(t, private),
		Address:    netip.MustParsePrefix("10.64.0.2/24"),
		MTU:        1280,
		Params: Params{
			Jc: 4, Jmin: 40, Jmax: 90, S1: 15, S2: 16, S3: 17, S4: 18,
			I1:                  "<r 2><t>",
			HeaderProtectionKey: base64Key(t, protection),
		},
		Peers: []Peer{{
			PublicKey: base64Key(t, public),
			AllowedIPs: []netip.Prefix{
				netip.MustParsePrefix("10.64.0.1/32"),
				netip.MustParsePrefix("10.64.0.3/32"),
			},
			Endpoint:            "203.0.113.10:39743",
			PersistentKeepalive: 25,
		}},
	}
	want := `private_key=` + private + `
jc=4
jmin=40
jmax=90
s1=15
s2=16
s3=17
s4=18
h1=1
h2=2
h3=3
h4=4
i1=<r 2><t>
header_protection_key=` + protection + `
content_padding_addition=32-128
public_key=` + public + `
endpoint=203.0.113.10:39743
persistent_keepalive_interval=25
allowed_ip=10.64.0.1/32
allowed_ip=10.64.0.3/32
`
	got, err := config.engineConfig()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("engineConfig:\n%s\nwant:\n%s", got, want)
	}
}

func TestEngineConfigListeningPeerHasNoEndpoint(t *testing.T) {
	config := validConfig()
	config.ListenPort = 39743
	config.Peers = []Peer{{PublicKey: GenerateKey()}}
	got, err := config.engineConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "listen_port=39743\n") {
		t.Errorf("no listen_port in:\n%s", got)
	}
	if strings.Contains(got, "endpoint") || strings.Contains(got, "persistent_keepalive") {
		t.Errorf("a peer that dials in must have no endpoint or keepalive:\n%s", got)
	}
}

func validConfig() Config {
	return Config{
		PrivateKey: GenerateKey(),
		Address:    netip.MustParsePrefix("10.64.0.2/24"),
		MTU:        1280,
		Params:     NewParams(),
		Peers: []Peer{{
			PublicKey:           GenerateKey(),
			AllowedIPs:          []netip.Prefix{netip.MustParsePrefix("10.64.0.1/32")},
			Endpoint:            "203.0.113.10:39743",
			PersistentKeepalive: 25,
		}},
	}
}

// The real engine, on a fake interface, must take every setting it is given and report
// it back. A misspelled key or a value in the wrong form fails here, with no root needed.
// A listen_port is left to the end-to-end test: it would bind a real port.
func TestEngineTakesEverySetting(t *testing.T) {
	config := validConfig()
	// The engine starts dialling at once, so it dials the loopback's discard port.
	config.Peers[0].Endpoint = "127.0.0.1:9"
	settings, err := config.engineConfig()
	if err != nil {
		t.Fatal(err)
	}
	engine := device.NewDevice(tuntest.NewChannelTUN().TUN(), conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer engine.Close()
	if err := engine.IpcSet(settings); err != nil {
		t.Fatalf("the engine refused the config: %v\n%s", err, settings)
	}
	state, err := engine.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	reported := make(map[string]bool)
	for _, line := range strings.Split(state, "\n") {
		reported[line] = true
	}
	for _, line := range strings.Split(strings.TrimSpace(settings), "\n") {
		if !reported[line] {
			key, _, _ := strings.Cut(line, "=")
			t.Errorf("the engine did not report the setting %s", key)
		}
	}
	handshakes, err := parseHandshakes(state)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := handshakes[config.Peers[0].PublicKey]; !ok || !got.Equal(time.Unix(0, 0)) {
		t.Errorf("handshakes %v: want the peer with no handshake yet", handshakes)
	}
}

// State read from disk reaches the engine through NewTunnel alone, so it must refuse
// whatever could add a line to the config.
func TestNewTunnelRejects(t *testing.T) {
	const line = "\nallowed_ip=0.0.0.0/0"
	for name, change := range map[string]func(*Config){
		"private key":   func(c *Config) { c.PrivateKey += line },
		"no address":    func(c *Config) { c.Address = netip.Prefix{} },
		"listen port":   func(c *Config) { c.ListenPort = 70000 },
		"MTU too small": func(c *Config) { c.MTU = minMTU - 1 },
		"MTU too large": func(c *Config) { c.MTU = maxMTU + 1 },
		"params":        func(c *Config) { c.Params.I1 += line },
		"peer key":      func(c *Config) { c.Peers[0].PublicKey += line },
		"allowed IP":    func(c *Config) { c.Peers[0].AllowedIPs = []netip.Prefix{{}} },
		"endpoint":      func(c *Config) { c.Peers[0].Endpoint += line },
		"keepalive":     func(c *Config) { c.Peers[0].PersistentKeepalive = -1 },
	} {
		config := validConfig()
		change(&config)
		if _, err := NewTunnel("trunk0", config, slog.Default()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, iface := range []string{"", "../trunk0", "trunk0\nline", "a-name-of-16-chr"} {
		if _, err := NewTunnel(iface, validConfig(), slog.Default()); err == nil {
			t.Errorf("accepted interface name %q", iface)
		}
	}
	if _, err := NewTunnel("trunk0", validConfig(), slog.Default()); err != nil {
		t.Errorf("refused a valid config: %v", err)
	}
}

func TestResolveEndpoint(t *testing.T) {
	for endpoint, want := range map[string]string{
		"203.0.113.10:39743": "203.0.113.10:39743",
		"[2001:db8::1]:443":  "[2001:db8::1]:443",
	} {
		got, err := resolveEndpoint(context.Background(), endpoint)
		if err != nil {
			t.Errorf("%s: %v", endpoint, err)
		}
		if got != want {
			t.Errorf("%s: got %s, want %s", endpoint, got, want)
		}
	}
	// The engine takes only an IP, so a name must come back as one. The order of the two
	// loopback addresses depends on the machine.
	got, err := resolveEndpoint(context.Background(), "localhost:443")
	if err != nil {
		t.Fatal(err)
	}
	address, err := netip.ParseAddrPort(got)
	if err != nil || !address.Addr().IsLoopback() || address.Port() != 443 {
		t.Errorf("localhost:443: got %q, %v", got, err)
	}
	if _, err := resolveEndpoint(context.Background(), "no-port"); err == nil {
		t.Error("accepted an endpoint without a port")
	}
}

func TestValidateEndpoint(t *testing.T) {
	for endpoint, valid := range map[string]bool{
		"203.0.113.10:39743":               true,
		"[2001:db8::1]:443":                true,
		"portal.example:443":               true,
		"203.0.113.10":                     false,
		"203.0.113.10:0":                   false,
		"203.0.113.10:+443":                false,
		"203.0.113.10:0443":                false,
		"203.0.113.10:70000":               false,
		"bad host:443":                     false,
		"example.com/a:443":                false,
		"[fe80::1%eth0]:443":               false,
		"[fe80::1%a\nallowed_ip=0/0]:443":  false,
		"203.0.113.10\nallowed_ip=0/0:443": false,
		"203.0.113.10:443\nallowed_ip=0/0": false,
	} {
		if err := ValidateEndpoint(endpoint); (err == nil) != valid {
			t.Errorf("%q: got %v, want valid=%v", endpoint, err, valid)
		}
	}
}

func TestParseHandshakes(t *testing.T) {
	first, second := strings.Repeat("01", keySize), strings.Repeat("02", keySize)
	state := "private_key=" + strings.Repeat("aa", keySize) + "\nlisten_port=0\n" +
		"public_key=" + first + "\nlast_handshake_time_sec=1700000000\nlast_handshake_time_nsec=5\nallowed_ip=10.64.0.1/32\n" +
		"public_key=" + second + "\nlast_handshake_time_sec=0\nlast_handshake_time_nsec=0\n"
	got, err := parseHandshakes(state)
	if err != nil {
		t.Fatal(err)
	}
	firstKey, secondKey := base64Key(t, first), base64Key(t, second)
	if !got[firstKey].Equal(time.Unix(1700000000, 0)) || !got[secondKey].Equal(time.Unix(0, 0)) || len(got) != 2 {
		t.Errorf("got %v", got)
	}
	if got, err := parseHandshakes("listen_port=0\n"); err != nil || len(got) != 0 {
		t.Errorf("no peers: got %v, %v", got, err)
	}
	for _, bad := range []string{
		"public_key=not-hex\n",
		"public_key=0102\n",
		"public_key=" + first + "\nlast_handshake_time_sec=soon\n",
		"last_handshake_time_sec=1700000000\n",
	} {
		if _, err := parseHandshakes(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
