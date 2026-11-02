package awg

import (
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"
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
		if p.S2 == p.S1+56 || p.S3 == p.S2+28 {
			t.Fatalf("handshake sizes match: %+v", p)
		}
		if dataSizeCollides(p.S1, p.S2, p.S3, p.S4) {
			t.Fatalf("data size collides: %+v", p)
		}
		if p.H1 != "1" || p.H2 != "2" || p.H3 != "3" || p.H4 != "4" || p.ContentPaddingAddition != "32-128" {
			t.Fatalf("not the 3.1 profile: %+v", p)
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
		"Jc too large":        func(p *Params) { p.Jc = maxJunkCount + 1 },
		"Jmax below Jmin":     func(p *Params) { p.Jmax = p.Jmin - 1 },
		"S4 below the nonce":  func(p *Params) { p.S4 = minPadding - 1 },
		"handshake sizes":     func(p *Params) { p.S1, p.S2 = 20, 76 },
		"H1 adds a line":      func(p *Params) { p.H1 = "1\nPostUp = id" },
		"I1 adds a line":      func(p *Params) { p.I1 = "<t>\nPostUp = id" },
		"I1 kernel-only tag":  func(p *Params) { p.I1 = "<c>" },
		"I1 odd hex":          func(p *Params) { p.I1 = "<b 0xabc>" },
		"padding adds a line": func(p *Params) { p.ContentPaddingAddition = "32\nPostUp = id" },
		"protection key":      func(p *Params) { p.HeaderProtectionKey = "short" },
	} {
		p := NewParams()
		change(&p)
		if err := p.Validate(); err == nil {
			t.Errorf("%s: accepted %+v", name, p)
		}
	}
}

func TestRender(t *testing.T) {
	config := Config{
		PrivateKey: "PRIVATE",
		Address:    netip.MustParsePrefix("10.64.0.2/24"),
		MTU:        1280,
		Params: Params{
			Jc: 4, Jmin: 40, Jmax: 90, S1: 15, S2: 16, S3: 17, S4: 18,
			H1: "1", H2: "2", H3: "3", H4: "4",
			I1:                     "<r 2><t>",
			HeaderProtectionKey:    "PROTECTION",
			ContentPaddingAddition: "32-128",
		},
		Peers: []Peer{{
			PublicKey:           "PUBLIC",
			AllowedIPs:          []netip.Prefix{netip.MustParsePrefix("10.64.0.1/32")},
			Endpoint:            "203.0.113.10:39743",
			PersistentKeepalive: 25,
		}},
	}
	want := `[Interface]
PrivateKey = PRIVATE
Address = 10.64.0.2/24
MTU = 1280
Table = off
Jc = 4
Jmin = 40
Jmax = 90
S1 = 15
S2 = 16
S3 = 17
S4 = 18
H1 = 1
H2 = 2
H3 = 3
H4 = 4
I1 = <r 2><t>
HeaderProtectionKey = PROTECTION
ContentPaddingAddition = 32-128

[Peer]
PublicKey = PUBLIC
AllowedIPs = 10.64.0.1/32
Endpoint = 203.0.113.10:39743
PersistentKeepalive = 25
`
	if got := config.Render(); got != want {
		t.Errorf("Render:\n%s\nwant:\n%s", got, want)
	}
}

func TestRenderListeningPeerHasNoEndpoint(t *testing.T) {
	got := Config{
		ListenPort: 39743,
		Peers:      []Peer{{PublicKey: "PUBLIC"}},
	}.Render()
	if !strings.Contains(got, "ListenPort = 39743\n") {
		t.Errorf("no ListenPort in:\n%s", got)
	}
	if strings.Contains(got, "Endpoint") || strings.Contains(got, "PersistentKeepalive") {
		t.Errorf("a peer that dials in must have no Endpoint or keepalive:\n%s", got)
	}
}

func TestParseHandshakes(t *testing.T) {
	got, err := parseHandshakes("KEY1\t1700000000\nKEY2\t0\n")
	if err != nil {
		t.Fatal(err)
	}
	if !got["KEY1"].Equal(time.Unix(1700000000, 0)) || !got["KEY2"].Equal(time.Unix(0, 0)) || len(got) != 2 {
		t.Errorf("got %v", got)
	}
	if got, err := parseHandshakes(""); err != nil || len(got) != 0 {
		t.Errorf("no peers: got %v, %v", got, err)
	}
	for _, bad := range []string{"KEY1 1700000000", "KEY1\tsoon"} {
		if _, err := parseHandshakes(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
