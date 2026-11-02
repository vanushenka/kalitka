package trunk

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"kalitka/internal/awg"
)

const (
	invitePrefix = "kalitka1."
	minMTU       = 1280
	maxMTU       = 1500
)

var (
	nameFormat = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,31}$`)
	hostFormat = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)
)

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

// Validate checks every field strictly. The invite is written by a portal, which
// Kalitka does not trust, and its values reach a config on the gateway that
// awg-quick parses and whose PostUp lines it runs as commands. A compromised portal
// must not be able to run anything on the gateway through an invite.
func (i Invite) Validate() error {
	if !nameFormat.MatchString(i.Portal) {
		return fmt.Errorf("portal name %q is not valid", i.Portal)
	}
	if err := validateEndpoint(i.Endpoint); err != nil {
		return err
	}
	if err := awg.ValidateKey(i.PortalPublicKey); err != nil {
		return fmt.Errorf("portal public key: %w", err)
	}
	if err := awg.ValidateKey(i.PrivateKey); err != nil {
		return fmt.Errorf("private key: %w", err)
	}
	if !i.Subnet.IsValid() || !i.Subnet.Addr().Is4() || !i.Subnet.Addr().IsPrivate() || i.Subnet != i.Subnet.Masked() {
		return fmt.Errorf("subnet %v is not a private IPv4 network", i.Subnet)
	}
	if !i.Subnet.Contains(i.Address) || i.Address == portalAddress(i.Subnet) {
		return fmt.Errorf("address %v is not a gateway address in %v", i.Address, i.Subnet)
	}
	if i.MTU < minMTU || i.MTU > maxMTU {
		return fmt.Errorf("MTU %d is outside %d-%d", i.MTU, minMTU, maxMTU)
	}
	if err := i.Params.Validate(); err != nil {
		return fmt.Errorf("params: %w", err)
	}
	return nil
}

// validateEndpoint checks a host:port. A zone is refused because netip accepts any
// text after the % sign, line breaks included.
func validateEndpoint(endpoint string) error {
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
