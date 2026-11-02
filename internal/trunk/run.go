package trunk

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"sync"
	"time"

	"kalitka/internal/awg"
)

const (
	checkInterval = 15 * time.Second
	// staleAfter is WireGuard's reject-after-time. With a keepalive running a healthy
	// peer completes a handshake about every two minutes.
	staleAfter = 3 * time.Minute
)

// Run keeps the tunnels up until ctx ends, then removes them. A portal that cannot
// be reached is a normal state, so Run keeps trying and never gives up on it.
func Run(ctx context.Context, runDir string, tunnels []Tunnel, log *slog.Logger) error {
	if len(tunnels) == 0 {
		return errors.New("nothing to run: no trunks are configured")
	}
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", runDir, err)
	}
	paths := make([]string, len(tunnels))
	for i, tunnel := range tunnels {
		path, err := awg.WriteConf(runDir, tunnel.Interface, tunnel.Config)
		if err != nil {
			return err
		}
		paths[i] = path
	}
	var group sync.WaitGroup
	for i, tunnel := range tunnels {
		group.Go(func() {
			supervise(ctx, tunnel, paths[i], log.With("interface", tunnel.Interface))
		})
	}
	group.Wait()
	return nil
}

func supervise(ctx context.Context, tunnel Tunnel, confPath string, log *slog.Logger) {
	up := false
	connected := make(map[string]bool)
	for {
		if !up {
			up = bringUp(tunnel.Interface, confPath, log)
			clear(connected)
		}
		if up {
			if err := check(tunnel, connected, time.Now(), log); err != nil {
				// The interface is gone, for example amneziawg-go has exited.
				log.Error("tunnel lost, bringing it up again", "error", err)
				up = false
			}
		}
		select {
		case <-ctx.Done():
			if up {
				if err := awg.Down(confPath); err != nil {
					log.Error("removing the tunnel failed", "error", err)
				}
			}
			return
		case <-time.After(checkInterval):
		}
	}
}

func bringUp(iface, confPath string, log *slog.Logger) bool {
	if awg.InterfaceExists(iface) {
		log.Warn("removing an interface left from an earlier run")
		if err := awg.Down(confPath); err != nil {
			log.Error("removing the old interface failed", "error", err)
			return false
		}
	}
	if err := awg.Up(confPath); err != nil {
		log.Error("bringing the tunnel up failed, will retry", "error", err)
		return false
	}
	log.Info("tunnel is up, waiting for a handshake")
	return true
}

func check(tunnel Tunnel, connected map[string]bool, now time.Time, log *slog.Logger) error {
	handshakes, err := awg.LatestHandshakes(tunnel.Interface)
	if err != nil {
		return err
	}
	for _, peer := range tunnel.Config.Peers {
		alive := isAlive(handshakes[peer.PublicKey], now)
		if alive != connected[peer.PublicKey] {
			connected[peer.PublicKey] = alive
			if alive {
				log.Info("trunk connected", "peer", peer.PublicKey)
			} else {
				log.Warn("trunk lost", "peer", peer.PublicKey)
			}
		}
		if !alive && endpointNeedsResolving(peer.Endpoint) {
			// A portal on a dynamic IP may have moved; awg-quick resolved its name only once.
			if err := awg.SetEndpoint(tunnel.Interface, peer.PublicKey, peer.Endpoint); err != nil {
				log.Warn("resolving the portal again failed", "endpoint", peer.Endpoint, "error", err)
			}
		}
	}
	return nil
}

func isAlive(handshake, now time.Time) bool {
	return now.Sub(handshake) < staleAfter
}

// endpointNeedsResolving is true for an endpoint with a hostname. An endpoint with
// an IP and a peer without an endpoint have nothing to resolve.
func endpointNeedsResolving(endpoint string) bool {
	if endpoint == "" {
		return false
	}
	_, err := netip.ParseAddrPort(endpoint)
	return err != nil
}
