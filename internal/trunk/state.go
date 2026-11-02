// Package trunk is the tunnel between a gateway and a portal. The gateway always
// opens it, so the gateway can sit behind NAT and needs no open ports.
package trunk

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"

	"kalitka/internal/awg"
)

const (
	// defaultMTU is what the installer's cascade measured with double encapsulation.
	defaultMTU = 1280
	// keepalive holds the NAT mapping open on the gateway's side. Home routers can
	// drop an idle UDP mapping after 30 seconds.
	keepalive = 25
	// subnetBits leaves room for 253 gateways on one portal.
	subnetBits = 24
)

// Tunnel is one interface to bring up.
type Tunnel struct {
	Interface string
	Config    awg.Config
}

// Portal is the state of a machine with a public IP that clients connect to.
type Portal struct {
	Name       string        `json:"name"`
	Host       string        `json:"host"`
	Port       int           `json:"port"`
	Subnet     netip.Prefix  `json:"subnet"`
	PrivateKey string        `json:"private_key"`
	MTU        int           `json:"mtu"`
	Params     awg.Params    `json:"params"`
	Gateways   []GatewayPeer `json:"gateways"`
}

// GatewayPeer is a gateway invited to a portal.
type GatewayPeer struct {
	Name      string     `json:"name"`
	PublicKey string     `json:"public_key"`
	Address   netip.Addr `json:"address"`
}

// NewPortal creates the state of a portal reachable at host:port.
func NewPortal(name, host string, port int) (*Portal, error) {
	if !nameFormat.MatchString(name) {
		return nil, fmt.Errorf("portal name %q is not valid", name)
	}
	if err := validateEndpoint(net.JoinHostPort(host, fmt.Sprint(port))); err != nil {
		return nil, err
	}
	return &Portal{
		Name:       name,
		Host:       host,
		Port:       port,
		Subnet:     randomSubnet(),
		PrivateKey: awg.GenerateKey(),
		MTU:        defaultMTU,
		Params:     awg.NewParams(),
	}, nil
}

// Invite registers a new gateway and returns the invite for it. The gateway's
// private key is not kept here, so the invite cannot be issued twice.
func (p *Portal) Invite(gatewayName string) (Invite, error) {
	if !nameFormat.MatchString(gatewayName) {
		return Invite{}, fmt.Errorf("gateway name %q is not valid", gatewayName)
	}
	used := map[netip.Addr]bool{portalAddress(p.Subnet): true}
	for _, gateway := range p.Gateways {
		if gateway.Name == gatewayName {
			return Invite{}, fmt.Errorf("gateway %q is already invited", gatewayName)
		}
		used[gateway.Address] = true
	}
	address, err := freeAddress(p.Subnet, used)
	if err != nil {
		return Invite{}, err
	}
	portalPublic, err := awg.PublicKey(p.PrivateKey)
	if err != nil {
		return Invite{}, fmt.Errorf("portal key: %w", err)
	}
	gatewayPrivate := awg.GenerateKey()
	gatewayPublic, err := awg.PublicKey(gatewayPrivate)
	if err != nil {
		return Invite{}, fmt.Errorf("gateway key: %w", err)
	}
	p.Gateways = append(p.Gateways, GatewayPeer{Name: gatewayName, PublicKey: gatewayPublic, Address: address})
	return Invite{
		Portal:          p.Name,
		Endpoint:        net.JoinHostPort(p.Host, fmt.Sprint(p.Port)),
		PortalPublicKey: portalPublic,
		Subnet:          p.Subnet,
		Address:         address,
		PrivateKey:      gatewayPrivate,
		MTU:             p.MTU,
		Params:          p.Params,
	}, nil
}

// Tunnels returns the portal's single interface. Peers have no endpoint: gateways
// dial in and the portal learns where they are from their packets.
func (p *Portal) Tunnels() []Tunnel {
	peers := make([]awg.Peer, len(p.Gateways))
	for i, gateway := range p.Gateways {
		peers[i] = awg.Peer{
			PublicKey:  gateway.PublicKey,
			AllowedIPs: []netip.Prefix{netip.PrefixFrom(gateway.Address, gateway.Address.BitLen())},
		}
	}
	return []Tunnel{{
		Interface: "trunk0",
		Config: awg.Config{
			PrivateKey: p.PrivateKey,
			Address:    netip.PrefixFrom(portalAddress(p.Subnet), p.Subnet.Bits()),
			ListenPort: p.Port,
			MTU:        p.MTU,
			Params:     p.Params,
			Peers:      peers,
		},
	}}
}

// Gateway is the state of a machine behind NAT that releases traffic to the
// internet. It keeps one trunk per portal.
type Gateway struct {
	Portals []PortalLink `json:"portals"`
}

// PortalLink is a portal the gateway has joined.
type PortalLink struct {
	Interface string `json:"interface"`
	Invite
}

// Join adds a portal to the gateway's list.
func (g *Gateway) Join(invite Invite) error {
	if err := invite.Validate(); err != nil {
		return fmt.Errorf("invalid invite: %w", err)
	}
	used := make(map[string]bool)
	for _, link := range g.Portals {
		if link.PortalPublicKey == invite.PortalPublicKey {
			return fmt.Errorf("portal %q is already joined as %q", invite.Portal, link.Portal)
		}
		// The address spaces of all trunks share one routing table on the gateway.
		if link.Subnet.Overlaps(invite.Subnet) {
			return fmt.Errorf("subnet %v of portal %q overlaps %v of portal %q; initialise the new portal again to get another subnet",
				invite.Subnet, invite.Portal, link.Subnet, link.Portal)
		}
		used[link.Interface] = true
	}
	for i := 0; ; i++ {
		name := fmt.Sprintf("trunk%d", i)
		if !used[name] {
			g.Portals = append(g.Portals, PortalLink{Interface: name, Invite: invite})
			return nil
		}
	}
}

// Tunnels returns one interface per portal. Each has its own keys and parameters,
// so a blocked or compromised portal affects no other trunk.
func (g *Gateway) Tunnels() []Tunnel {
	tunnels := make([]Tunnel, len(g.Portals))
	for i, link := range g.Portals {
		portal := portalAddress(link.Subnet)
		tunnels[i] = Tunnel{
			Interface: link.Interface,
			Config: awg.Config{
				PrivateKey: link.PrivateKey,
				Address:    netip.PrefixFrom(link.Address, link.Subnet.Bits()),
				MTU:        link.MTU,
				Params:     link.Params,
				Peers: []awg.Peer{{
					PublicKey:           link.PortalPublicKey,
					AllowedIPs:          []netip.Prefix{netip.PrefixFrom(portal, portal.BitLen())},
					Endpoint:            link.Endpoint,
					PersistentKeepalive: keepalive,
				}},
			},
		}
	}
	return tunnels
}

// Load reads state saved by Save.
func Load(path string, state any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, state); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}

// Save writes state atomically, so a crash cannot leave a half-written file with
// the keys in it. The file holds private keys.
func Save(path string, state any) (err error) {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			os.Remove(file.Name())
		}
	}()
	if _, err := file.Write(append(data, '\n')); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

// portalAddress is the portal's own address: the first host of the trunk subnet.
func portalAddress(subnet netip.Prefix) netip.Addr {
	return subnet.Masked().Addr().Next()
}

// freeAddress returns the lowest host address not in use.
func freeAddress(subnet netip.Prefix, used map[netip.Addr]bool) (netip.Addr, error) {
	base := subnet.Masked().Addr()
	for address := base.Next(); subnet.Contains(address.Next()); address = address.Next() {
		if !used[address] {
			return address, nil
		}
	}
	return netip.Addr{}, errors.New("no free gateway address left on this portal")
}

// randomSubnet picks a /24 in 10.64.0.0/10. A gateway joins several portals that
// know nothing of each other, and the wide range keeps their subnets apart;
// Gateway.Join refuses the rare overlap.
func randomSubnet() netip.Prefix {
	var b [2]byte
	rand.Read(b[:]) // Never returns an error: it crashes the program instead.
	return netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 64 + b[0]%64, b[1], 0}), subnetBits)
}
