# Architecture

## Terms

Use these words in code, docs and conversation. Words like "entry", "exit" and "node"
are avoided on purpose: the connection opens in the opposite direction to the
traffic, so they mislead.

| Term | Code | What it is |
|---|---|---|
| Gateway | `gateway` | The machine behind NAT, through which traffic leaves for the internet. Dials every portal on its list. Needs no public IP. |
| Portal | `portal` | A machine with a public IP that clients connect to: a rented VPS or a home PC. |
| Client | `client` | The phone, laptop or router bypassing blocks. Runs an ordinary VPN app and none of our software. |
| Trunk | `trunk` | The tunnel between a gateway and a portal. Always opened by the gateway. |

The gateway is never called a client, even though AmneziaWG sees it as one.

```
client ───► portal ◄═══ trunk ═══ gateway ───► internet
```

## Principles

**We do not write protocols.** The engine is `amneziawg-go`, later also `xray-core`.
Kalitka generates their configs and keys, connects machines with an invite, watches the
tunnels and keeps them up. The engine runs inside the `kalitka` process as a Go library,
so a machine needs no other VPN software. Its version is pinned in `go.mod` and checked
by `go.sum`, because AmneziaWG generations do not interoperate.

**Docker is not part of the product.** It would add a large dependency and nothing that
one file and a service unit cannot do, and it does not exist on a Windows gateway. Only
the end-to-end test uses it, to build a NAT and networks on one machine.

**A portal is not trusted.** A rented VPS can be inspected or seized by its host. The
invite comes from a portal and its values reach the engine's line-based config on the
gateway, where an added line could widen a peer's `allowed_ip` and take over the
gateway's traffic. So `Invite.Validate` accepts only what a portal generates, rather
than whatever the engine might take, and `TestDecodeInviteRejectsHostileFields` covers
the fields that exist today. A new invite field needs its own check and test case.
`awg.NewTunnel` validates every config too, so state read from disk gets the same
checks. Each trunk has its own keys and parameters, so one compromised portal gains
nothing on the others.

The invite holds a private key, so `gateway join` reads it from standard input: an
argument would stay in the shell history and show in the process list.

**One tunnel per portal, one list on the gateway.** The gateway does not care what a
portal is. A portal that cannot be reached is a normal state: the gateway keeps
trying, and the other trunks are unaffected. All trunks live in one process, so a crash
of the engine stops them all and it is the service manager that restarts them.

**A trunk touches little on its machine.** On Linux it needs root, `/dev/net/tun` and
the `ip` command. It adds one interface with one address, which brings one connected
route, and adds no firewall rules. The interface lives as long as the process. No kernel
module is used, even if the host has one, so every machine runs the pinned engine.

`KALITKA_DEBUG=1` adds the engine's verbose log and the control socket of a standalone
`amneziawg-go`, so that the upstream `awg show` works. The end-to-end test relies on it
to check the engine's settings with something other than our own code. A normal run has
no such socket, whose path would name the engine to whoever hosts a portal.

**OS-specific code stays in build-tagged files.** `internal/awg/tunnel_linux.go` is what
touches the system. `tunnel_unsupported.go` makes everything else build on any OS and
fails loudly when asked to run a tunnel.

## Layout

| Path | Contents |
|---|---|
| `cmd/kalitka` | The command line |
| `internal/awg` | Keys, the AmneziaWG 3.1 parameter profile, the engine's config, running the engine |
| `internal/trunk` | Portal and gateway state, invites, keeping tunnels up |
| `test/trunk` | The end-to-end test through a simulated NAT, with its image |

## The AmneziaWG profile

`awg.NewParams` follows `generate_awg_params` from
[bivlked/amneziawg-installer](https://github.com/bivlked/amneziawg-installer) (MIT), to
stay within what that project has tried on real networks. `H1`-`H4` and
`ContentPaddingAddition` are the same for every tunnel, so they are constants in
`Config.engineConfig` and an invite cannot carry them. Only tags that both the kernel
module and `amneziawg-go` understand are used, because a client's app may use either.
`RandomTrailers` stays off: the installer's docs report a sharp drop in speed with it.

Both ends use the same values. Junk packets and `I1` are only sent by the side that
starts a handshake, normally the gateway.

## Where the client VPN ends

Two options, and both are wanted eventually:

- **A:** the client VPN ends on the gateway, and the portal only forwards encrypted
  traffic into the trunk.
- **B:** the client VPN ends on the portal, and the traffic goes on over the trunk.

Which one comes first is not decided yet. To keep both possible, this will be a
per-portal setting, with these rules:

1. A protocol module does not know where it runs. It takes a port, a list of clients
   and a route for the traffic, and returns a config and client profiles.
2. The gateway owns the list of clients and tells a portal over the trunk what to do.
3. Only the code that decides where a protocol runs reads the setting.

## How a gateway will release traffic

Not written yet: this is the plan for stages 3 and 4, and why. Two ways, chosen by
platform. Measured with a throwaway tool on the pinned engine, MTU 1280, speeds in
Mbit/s from gateway to portal, the direction of a client's downloads:

| Conditions | OS tunnel | In-process network stack |
|---|---|---|
| Two containers, 2 CPUs each, no other limit | 7800 | 985 |
| The same, 0.5 CPU each | 1750 | 300 |
| 60 ms round trip, 0.1% loss each way | 183 | 9-16 |
| 60 ms round trip, 1% reordered | 17-38 | 2-3 |
| 60 ms round trip, 50 Mbit/s bottleneck | 43 | 16-42, unstable |

- **Linux will use an OS tunnel:** an interface and the kernel's NAT. The CPU is not the
  limit on a home channel, and the kernel's TCP holds up on a long lossy path.
- **A Windows gateway will use the engine's in-process stack (gVisor):** no driver, no
  admin rights and no network settings, so it can be handed over as one file. It is the
  weaker one on a long lossy path, so its speed says little about a Linux gateway. The
  cause of that gap is not known: Reno, cubic and RACK settings did not close it.

What the stack needs, each measured:

- **A precise clock on Windows.** Go's monotonic clock steps by 0.5 ms there, which makes
  RACK report false losses: a third of the packets went out twice and the speed fell
  below 10 Mbit/s on a real channel of 94. A clock on `QueryPerformanceCounter`
  fixes it, and `stack.Options.Clock` is the way to set one. `netstack.CreateNetTUN` does
  not expose it, so the gateway will need its own device on the stack.
- **No stack on the other end of a TCP flow.** Two of them on one flow collapse at a
  bottleneck, to 1-11 Mbit/s. So a portal must not terminate a flow in a stack.

Uploads through the stack stalled for over 15 seconds 3 times in 96, and never through
an OS tunnel. The cause is not known yet.

## Stages

1. **Trunk.** Invites, tunnels, reconnecting, the engine inside `kalitka`. Passes the
   end-to-end test through a simulated NAT in containers on one machine.
2. **A trunk on real machines.** A portal on a VPS and a gateway on a PC: a real port,
   restarts, a night of work, a service unit.
3. **AmneziaWG clients on Linux.** The gateway releases traffic to the internet, and
   clients connect through a portal. Needs the A or B decision.
4. **A gateway on Windows,** with the in-process stack. The stalls above are investigated
   here.
5. **A check on real networks.** A real gateway abroad, a VPS and SIM cards: speed,
   latency and how a trunk holds up over a day or two. It comes before the rest because
   whether dialling from abroad helps at all is still unknown, and they depend on that.
6. **Keeping the gateway reachable.** A signed portal list fetched from external URLs,
   a management path through the trunk, a watchdog. Without this a gateway whose
   portals have all died cannot be reached at all, so this stage must be finished
   before a gateway is shipped abroad.
7. **VLESS + XHTTP + Reality** for clients on networks that cut UDP.
8. **A spare trunk** over VLESS reverse, for when UDP between gateway and portal dies.
9. **The other option** of A and B.
10. **Later:** Hysteria2.

## Open questions

- **Trunk MTU under option A.** A client's encrypted packets travel inside the trunk,
  so a client's MTU has to be lower than the trunk's. The current 1280 comes from a
  cascade of type B. Measure this at stage 3 and raise the trunk MTU if needed.
- **The engine's speed on ARM.** Not measured, and the installer has not measured
  AmneziaWG 3.1 on ARM either.
- **UDP over VLESS reverse.** The official example only shows TCP, which decides whether
  AmneziaWG clients can use the spare trunk.
