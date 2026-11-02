package trunk

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"kalitka/internal/awg"
)

func newPortal(t *testing.T) *Portal {
	t.Helper()
	portal, err := NewPortal("msk", "203.0.113.10", 39743)
	if err != nil {
		t.Fatal(err)
	}
	return portal
}

func newInvite(t *testing.T) Invite {
	t.Helper()
	invite, err := newPortal(t).Invite("home")
	if err != nil {
		t.Fatal(err)
	}
	return invite
}

func TestNewPortalRejects(t *testing.T) {
	for _, c := range []struct {
		name, host string
		port       int
	}{
		{"bad name!", "203.0.113.10", 39743},
		{"msk", "bad host", 39743},
		{"msk", "203.0.113.10\nPostUp = id", 39743},
		{"msk", "203.0.113.10", 0},
		{"msk", "203.0.113.10", 70000},
	} {
		if _, err := NewPortal(c.name, c.host, c.port); err == nil {
			t.Errorf("accepted %+v", c)
		}
	}
}

func TestInviteRoundTrip(t *testing.T) {
	invite := newInvite(t)
	encoded, err := invite.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(encoded, " \n") {
		t.Errorf("not a single word: %q", encoded)
	}
	decoded, err := DecodeInvite("  " + encoded + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, invite) {
		t.Errorf("got %+v, want %+v", decoded, invite)
	}
}

func TestDecodeInviteRejectsMalformed(t *testing.T) {
	for _, bad := range []string{"", "kalitka2.e30", "kalitka1.", "kalitka1.!!!", "kalitka1.e30", "kalitka1.eyJvdGhlciI6MX0"} {
		if _, err := DecodeInvite(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// A portal is not trusted, and awg-quick runs PostUp lines as commands, so no field
// of an invite may be able to add a line to the gateway's config.
func TestDecodeInviteRejectsHostileFields(t *testing.T) {
	const line = "\nPostUp = id"
	for name, change := range map[string]func(*Invite){
		"name":               func(i *Invite) { i.Portal += line },
		"endpoint":           func(i *Invite) { i.Endpoint = "203.0.113.10" + line + ":39743" },
		"endpoint zone":      func(i *Invite) { i.Endpoint = "[fe80::1%a" + line + "]:39743" },
		"endpoint port":      func(i *Invite) { i.Endpoint = "203.0.113.10:39743" + line },
		"portal key":         func(i *Invite) { i.PortalPublicKey += line },
		"private key":        func(i *Invite) { i.PrivateKey += line },
		"I1":                 func(i *Invite) { i.Params.I1 += line },
		"H1":                 func(i *Invite) { i.Params.H1 += line },
		"public subnet":      func(i *Invite) { i.Subnet = netip.MustParsePrefix("8.8.8.0/24") },
		"unmasked subnet":    func(i *Invite) { i.Subnet = netip.PrefixFrom(i.Address, 24) },
		"address outside":    func(i *Invite) { i.Address = netip.MustParseAddr("192.168.1.2") },
		"portal's address":   func(i *Invite) { i.Address = portalAddress(i.Subnet) },
		"MTU too small":      func(i *Invite) { i.MTU = minMTU - 1 },
		"padding below 12":   func(i *Invite) { i.Params.S4 = 4 },
		"no protection key":  func(i *Invite) { i.Params.HeaderProtectionKey = "" },
		"bad endpoint port":  func(i *Invite) { i.Endpoint = "203.0.113.10:0" },
		"endpoint with path": func(i *Invite) { i.Endpoint = "example.com/a:39743" },
	} {
		invite := newInvite(t)
		change(&invite)
		encoded, err := invite.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeInvite(encoded); err == nil {
			t.Errorf("%s: accepted", name)
		}
		var gateway Gateway
		if err := gateway.Join(invite); err == nil {
			t.Errorf("%s: Join accepted", name)
		}
	}
}

func TestPortalInviteAllocates(t *testing.T) {
	portal := newPortal(t)
	base := portal.Subnet.Addr().As4()
	for i, name := range []string{"one", "two"} {
		invite, err := portal.Invite(name)
		if err != nil {
			t.Fatal(err)
		}
		want := base
		want[3] = byte(i + 2)
		if invite.Address != netip.AddrFrom4(want) {
			t.Errorf("%s: address %v", name, invite.Address)
		}
		if err := invite.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := portal.Invite("one"); err == nil {
		t.Error("accepted a duplicate gateway name")
	}
	if _, err := portal.Invite("bad name!"); err == nil {
		t.Error("accepted an invalid gateway name")
	}
}

func TestPortalInviteRunsOutOfAddresses(t *testing.T) {
	portal := newPortal(t)
	for i := range 253 {
		if _, err := portal.Invite(fmt.Sprintf("gateway%d", i)); err != nil {
			t.Fatalf("invite %d: %v", i, err)
		}
	}
	if _, err := portal.Invite("onemore"); err == nil {
		t.Error("the 254th gateway got an address")
	}
}

func TestRandomSubnetStaysInRange(t *testing.T) {
	allowed := netip.MustParsePrefix("10.64.0.0/10")
	for range 1000 {
		subnet := randomSubnet()
		if !allowed.Contains(subnet.Addr()) || subnet.Bits() != subnetBits || subnet != subnet.Masked() {
			t.Fatalf("subnet %v", subnet)
		}
	}
}

// The two ends never exchange anything but the invite, so their configs must agree
// on the keys, the parameters and each other's addresses.
func TestBothEndsOfATrunkAgree(t *testing.T) {
	portal := newPortal(t)
	invite, err := portal.Invite("home")
	if err != nil {
		t.Fatal(err)
	}
	var gateway Gateway
	if err := gateway.Join(invite); err != nil {
		t.Fatal(err)
	}
	portalEnd := portal.Tunnels()[0].Config
	gatewayEnd := gateway.Tunnels()[0].Config

	portalPublic, err := awg.PublicKey(portalEnd.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if gatewayEnd.Peers[0].PublicKey != portalPublic {
		t.Error("the gateway does not know the portal's public key")
	}
	gatewayPublic, err := awg.PublicKey(gatewayEnd.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if portalEnd.Peers[0].PublicKey != gatewayPublic {
		t.Error("the portal does not know the gateway's public key")
	}
	if portalEnd.Params != gatewayEnd.Params {
		t.Errorf("params differ: %+v and %+v", portalEnd.Params, gatewayEnd.Params)
	}
	if portalEnd.MTU != gatewayEnd.MTU {
		t.Errorf("MTU differs: %d and %d", portalEnd.MTU, gatewayEnd.MTU)
	}
	if !gatewayEnd.Peers[0].AllowedIPs[0].Contains(portalEnd.Address.Addr()) {
		t.Error("the gateway would drop the portal's packets")
	}
	if !portalEnd.Peers[0].AllowedIPs[0].Contains(gatewayEnd.Address.Addr()) {
		t.Error("the portal would drop the gateway's packets")
	}
}

func TestDirections(t *testing.T) {
	portal := newPortal(t)
	invite, err := portal.Invite("home")
	if err != nil {
		t.Fatal(err)
	}
	var gateway Gateway
	if err := gateway.Join(invite); err != nil {
		t.Fatal(err)
	}
	portalEnd := portal.Tunnels()[0].Config
	gatewayEnd := gateway.Tunnels()[0].Config

	if portalEnd.ListenPort != 39743 || portalEnd.Peers[0].Endpoint != "" || portalEnd.Peers[0].PersistentKeepalive != 0 {
		t.Errorf("the portal must listen and wait: %+v", portalEnd)
	}
	if gatewayEnd.ListenPort != 0 || gatewayEnd.Peers[0].Endpoint != "203.0.113.10:39743" || gatewayEnd.Peers[0].PersistentKeepalive != keepalive {
		t.Errorf("the gateway must dial and keep the NAT mapping open: %+v", gatewayEnd)
	}
}

func TestGatewayJoin(t *testing.T) {
	first := newInvite(t)
	second := newInvite(t)
	second.Subnet = netip.MustParsePrefix("10.65.0.0/24")
	second.Address = netip.MustParseAddr("10.65.0.2")
	first.Subnet = netip.MustParsePrefix("10.64.0.0/24")
	first.Address = netip.MustParseAddr("10.64.0.2")

	var gateway Gateway
	if err := gateway.Join(first); err != nil {
		t.Fatal(err)
	}
	if err := gateway.Join(first); err == nil {
		t.Error("joined the same portal twice")
	}
	overlapping := newInvite(t)
	overlapping.Subnet = first.Subnet
	overlapping.Address = netip.MustParseAddr("10.64.0.3")
	if err := gateway.Join(overlapping); err == nil {
		t.Error("joined a portal with an overlapping subnet")
	}
	if err := gateway.Join(second); err != nil {
		t.Fatal(err)
	}
	tunnels := gateway.Tunnels()
	if len(tunnels) != 2 || tunnels[0].Interface != "trunk0" || tunnels[1].Interface != "trunk1" {
		t.Errorf("interfaces: %+v", tunnels)
	}
}

func TestStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "portal.json")
	portal := newPortal(t)
	if _, err := portal.Invite("home"); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, portal); err != nil {
		t.Fatal(err)
	}
	var loaded Portal
	if err := Load(path, &loaded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(&loaded, portal) {
		t.Errorf("got %+v, want %+v", loaded, *portal)
	}

	invite := newInvite(t)
	var gateway Gateway
	if err := gateway.Join(invite); err != nil {
		t.Fatal(err)
	}
	gatewayPath := filepath.Join(t.TempDir(), "gateway.json")
	if err := Save(gatewayPath, &gateway); err != nil {
		t.Fatal(err)
	}
	var loadedGateway Gateway
	if err := Load(gatewayPath, &loadedGateway); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loadedGateway, gateway) {
		t.Errorf("got %+v, want %+v", loadedGateway, gateway)
	}
}

func TestIsAlive(t *testing.T) {
	now := time.Unix(1700000000, 0)
	for _, c := range []struct {
		handshake time.Time
		want      bool
	}{
		{now.Add(-time.Minute), true},
		{now.Add(-staleAfter), false},
		{time.Unix(0, 0), false},
		{time.Time{}, false},
	} {
		if got := isAlive(c.handshake, now); got != c.want {
			t.Errorf("handshake %v: got %v", c.handshake, got)
		}
	}
}

func TestEndpointNeedsResolving(t *testing.T) {
	for endpoint, want := range map[string]bool{
		"":                   false,
		"203.0.113.10:39743": false,
		"[2001:db8::1]:443":  false,
		"portal.example:443": true,
	} {
		if got := endpointNeedsResolving(endpoint); got != want {
			t.Errorf("%q: got %v", endpoint, got)
		}
	}
}
