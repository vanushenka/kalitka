// Command kalitka deploys a gateway behind NAT and the portals it dials.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"kalitka/internal/trunk"
)

const usage = `Usage:
  kalitka portal init --host HOST --port PORT [--name NAME]
  kalitka portal invite --gateway NAME
  kalitka portal run
  kalitka gateway join INVITE
  kalitka gateway run

A running portal or gateway loads its state at start: restart it after
"portal invite" or "gateway join".

State lives in $KALITKA_STATE (default /var/lib/kalitka) and holds private keys.
`

func main() {
	if err := dispatch(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "kalitka:", err)
		os.Exit(1)
	}
}

func dispatch(args []string) error {
	if len(args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		return errors.New("a role and a command are required")
	}
	role, command, rest := args[0], args[1], args[2:]
	switch role + " " + command {
	case "portal init":
		return portalInit(rest)
	case "portal invite":
		return portalInvite(rest)
	case "portal run":
		return portalRun()
	case "gateway join":
		return gatewayJoin(rest)
	case "gateway run":
		return gatewayRun()
	}
	fmt.Fprint(os.Stderr, usage)
	return fmt.Errorf("unknown command %q", role+" "+command)
}

func portalInit(args []string) error {
	flags := flag.NewFlagSet("portal init", flag.ContinueOnError)
	name := flags.String("name", "portal", "a name for this portal")
	host := flags.String("host", "", "public IP or hostname gateways dial")
	port := flags.Int("port", 0, "UDP port gateways dial")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *host == "" || *port == 0 {
		return errors.New("--host and --port are required")
	}
	path := statePath("portal.json")
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists: this portal is initialised, and a new one would cut off its gateways", path)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	portal, err := trunk.NewPortal(*name, *host, *port)
	if err != nil {
		return err
	}
	return trunk.Save(path, portal)
}

func portalInvite(args []string) error {
	flags := flag.NewFlagSet("portal invite", flag.ContinueOnError)
	gateway := flags.String("gateway", "", "a name for the gateway")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *gateway == "" {
		return errors.New("--gateway is required")
	}
	path := statePath("portal.json")
	var portal trunk.Portal
	if err := trunk.Load(path, &portal); err != nil {
		return err
	}
	invite, err := portal.Invite(*gateway)
	if err != nil {
		return err
	}
	encoded, err := invite.Encode()
	if err != nil {
		return err
	}
	if err := trunk.Save(path, &portal); err != nil {
		return err
	}
	fmt.Println(encoded)
	return nil
}

func portalRun() error {
	var portal trunk.Portal
	if err := trunk.Load(statePath("portal.json"), &portal); err != nil {
		return err
	}
	return runTunnels(portal.Tunnels())
}

func gatewayJoin(args []string) error {
	if len(args) != 1 {
		return errors.New("exactly one invite is required")
	}
	invite, err := trunk.DecodeInvite(args[0])
	if err != nil {
		return err
	}
	path := statePath("gateway.json")
	var gateway trunk.Gateway
	if err := trunk.Load(path, &gateway); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := gateway.Join(invite); err != nil {
		return err
	}
	return trunk.Save(path, &gateway)
}

func gatewayRun() error {
	var gateway trunk.Gateway
	if err := trunk.Load(statePath("gateway.json"), &gateway); err != nil {
		return err
	}
	return runTunnels(gateway.Tunnels())
}

func runTunnels(tunnels []trunk.Tunnel) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return trunk.Run(ctx, statePath("run"), tunnels, slog.Default())
}

func statePath(name string) string {
	dir := os.Getenv("KALITKA_STATE")
	if dir == "" {
		dir = "/var/lib/kalitka"
	}
	return filepath.Join(dir, name)
}
