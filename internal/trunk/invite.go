package trunk

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"kalitka/internal/awg"
)

const invitePrefix = "kalitka1."

var nameFormat = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,31}$`)

// Invite is everything a gateway needs to dial a portal. It holds the gateway's
// private key for this one trunk, so there is no second step sending a key back,
// and the portal knowing that key gains it nothing: the trunk ends at the portal
// anyway. Treat the encoded invite as a secret.
type Invite struct {
	Portal          string       `json:"portal"`
	Endpoint        string       `json:"endpoint"`
	PortalPublicKey string       `json:"portal_public_key"`
	Subnet          netip.Prefix `json:"subnet"`
	Address         netip.Addr   `json:"address"`
	PrivateKey      string       `json:"private_key"`
	MTU             int          `json:"mtu"`
	Params          awg.Params   `json:"params"`
}

// Encode returns the invite as a single line that is safe to copy and paste.
func (i Invite) Encode() (string, error) {
	data, err := json.Marshal(i)
	if err != nil {
		return "", fmt.Errorf("encode invite: %w", err)
	}
	return invitePrefix + base64.RawURLEncoding.EncodeToString(data), nil
}

// DecodeInvite parses and validates an invite.
func DecodeInvite(s string) (Invite, error) {
	encoded, ok := strings.CutPrefix(strings.TrimSpace(s), invitePrefix)
	if !ok {
		return Invite{}, fmt.Errorf("an invite starts with %q", invitePrefix)
	}
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return Invite{}, fmt.Errorf("decode invite: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var invite Invite
	if err := decoder.Decode(&invite); err != nil {
		return Invite{}, fmt.Errorf("decode invite: %w", err)
	}
	if err := invite.Validate(); err != nil {
		return Invite{}, fmt.Errorf("invalid invite: %w", err)
	}
	return invite, nil
}

// Validate accepts only what a portal generates. The invite is written by a portal,
// which Kalitka does not trust, and its values reach a config on the gateway that
// awg-quick parses and whose PostUp lines it runs as commands. A compromised portal
// must not be able to run anything on the gateway through an invite, or to pick
// subnets that would capture the gateway's traffic to other portals.
func (i Invite) Validate() error {
	if !nameFormat.MatchString(i.Portal) {
		return fmt.Errorf("portal name %q is not valid", i.Portal)
	}
	if i.Endpoint == "" {
		return errors.New("no endpoint")
	}
	if i.Subnet.Bits() != subnetBits || !subnetRange.Contains(i.Subnet.Addr()) || i.Subnet != i.Subnet.Masked() {
		return fmt.Errorf("subnet %v is not a /%d in %v", i.Subnet, subnetBits, subnetRange)
	}
	if !i.Subnet.Contains(i.Address) {
		return fmt.Errorf("address %v is not in %v", i.Address, i.Subnet)
	}
	// .1 is the portal's own address; .0 and .255 are not host addresses.
	if host := i.Address.As4()[3]; host < 2 || host == 255 {
		return fmt.Errorf("address %v is not a gateway address", i.Address)
	}
	return i.config().Validate()
}

// config is the gateway's end of the trunk this invite describes.
func (i Invite) config() awg.Config {
	portal := portalAddress(i.Subnet)
	return awg.Config{
		PrivateKey: i.PrivateKey,
		Address:    netip.PrefixFrom(i.Address, i.Subnet.Bits()),
		MTU:        i.MTU,
		Params:     i.Params,
		Peers: []awg.Peer{{
			PublicKey:           i.PortalPublicKey,
			AllowedIPs:          []netip.Prefix{netip.PrefixFrom(portal, portal.BitLen())},
			Endpoint:            i.Endpoint,
			PersistentKeepalive: keepalive,
		}},
	}
}
