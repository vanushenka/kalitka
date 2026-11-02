package trunk

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
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
// be reached is a normal state, so Run keeps trying and never gives up on it. What
// retrying cannot cure, a system that cannot run a tunnel or an invalid config, fails
// here at the start.
func Run(ctx context.Context, tunnels []Tunnel, log *slog.Logger) error {
	if len(tunnels) == 0 {
		return errors.New("nothing to run: no trunks are configured")
	}
	if err := awg.CheckSystem(); err != nil {
		return err
	}
	engines := make([]*awg.Tunnel, len(tunnels))
	for i, tunnel := range tunnels {
		engine, err := awg.NewTunnel(tunnel.Interface, tunnel.Config, log.With("interface", tunnel.Interface))
		if err != nil {
			return err
		}
		engines[i] = engine
	}
	var group sync.WaitGroup
	for i, tunnel := range tunnels {
		group.Go(func() {
			supervise(ctx, tunnel, engines[i], log.With("interface", tunnel.Interface))
		})
	}
	group.Wait()
	return nil
}

func supervise(ctx context.Context, tunnel Tunnel, engine *awg.Tunnel, log *slog.Logger) {
	up := false
	connected := make(map[string]bool)
	for {
		if !up {
			up = bringUp(ctx, engine, log)
			clear(connected)
		}
		if up {
			if err := check(ctx, tunnel, engine, connected, time.Now(), log); err != nil {
				log.Error("tunnel lost, bringing it up again", "error", err)
				engine.Down()
				up = false
			}
		}
		select {
		case <-ctx.Done():
			engine.Down()
			return
		case <-time.After(checkInterval):
		}
	}
}

func bringUp(ctx context.Context, engine *awg.Tunnel, log *slog.Logger) bool {
	if err := engine.Up(ctx); err != nil {
		log.Error("bringing the tunnel up failed, will retry", "error", err)
		return false
	}
	log.Info("tunnel is up, waiting for a handshake")
	return true
}

func check(ctx context.Context, tunnel Tunnel, engine *awg.Tunnel, connected map[string]bool, now time.Time, log *slog.Logger) error {
	handshakes, err := engine.LatestHandshakes()
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
			// A portal on a dynamic IP may have moved since its name was last resolved.
			if err := engine.SetEndpoint(ctx, peer.PublicKey, peer.Endpoint); err != nil {
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
