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

**We do not write protocols.** The engines are `amneziawg-go` and `amneziawg-tools`,
later `xray-core`. Kalitka generates their configs and keys, connects machines with an
invite, watches the tunnels and keeps them up. Engine versions are pinned to a tag and
its commit in `deploy/Dockerfile`, because AmneziaWG generations do not interoperate.

**A portal is not trusted.** A rented VPS can be inspected or seized by its host. The
invite comes from a portal and its values reach a config on the gateway, where
`awg-quick` runs `PostUp` lines as commands. So `Invite.Validate` accepts only what a
portal generates, rather than whatever the engines might take, and
`TestDecodeInviteRejectsHostileFields` covers the fields that exist today. A new invite
field needs its own check and test case. `awg.WriteConf` validates every config too, so
state read from disk gets the same checks. Each trunk has its own keys and parameters,
so one compromised portal gains nothing on the others.

The invite holds a private key, so `gateway join` reads it from standard input: an
argument would stay in the shell history and show in the process list.

**One tunnel per portal, one list on the gateway.** The gateway does not care what a
portal is. A portal that cannot be reached is a normal state: the gateway keeps
trying, and the other trunks are unaffected.

**Everything lives inside the container.** Interfaces and routes stay in the
container's network namespace, and `Table = off` keeps `awg-quick` from adding routes
for the peers. That is what lets a portal or gateway run on any Docker host. Containers
need `NET_ADMIN` and `/dev/net/tun`, and no kernel module: `awg-quick` uses the module
if the host has one and falls back to `amneziawg-go`.

**OS-specific code stays in build-tagged files.** Only `internal/awg/tunnel_linux.go`
touches the system. `tunnel_unsupported.go` makes everything else build on any OS and
fails loudly when asked to run a tunnel.

## Layout

| Path | Contents |
|---|---|
| `cmd/kalitka` | The command line |
| `internal/awg` | Keys, the AmneziaWG 3.1 parameter profile, config rendering, driving the tools |
| `internal/trunk` | Portal and gateway state, invites, keeping tunnels up |
| `deploy` | The image and the compose files |
| `test/trunk` | The end-to-end test through a simulated NAT |

## The AmneziaWG profile

`awg.NewParams` follows `generate_awg_params` from
[bivlked/amneziawg-installer](https://github.com/bivlked/amneziawg-installer) (MIT), to
stay within what that project has tried on real networks. `H1`-`H4` and
`ContentPaddingAddition` are the same for every tunnel, so they are constants in
`Config.Render` and an invite cannot carry them. Only tags that both the kernel module
and `amneziawg-go` understand are used. `RandomTrailers` stays off: the installer's docs
report a sharp drop in speed with it.

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

## Stages

1. **Trunk.** Invites, tunnels, reconnecting. Passes the end-to-end test through a
   simulated NAT in containers on one machine; publishing a port on a real portal is
   not covered by that test.
2. **AmneziaWG clients.** The gateway releases traffic to the internet, and clients
   connect through a portal. Needs the A or B decision.
3. **A check on real networks.** A real mini PC, VPS and SIM cards: speed, latency and
   how a trunk holds up over a day or two. It comes early because whether dialling
   from abroad helps at all is still unknown, and the later stages depend on that.
4. **Keeping the gateway reachable.** A signed portal list fetched from external URLs,
   a management path through the trunk, a watchdog. Without this a gateway whose
   portals have all died cannot be reached at all, so this stage must be finished
   before a gateway is shipped abroad.
5. **VLESS + XHTTP + Reality** for clients on networks that cut UDP.
6. **A spare trunk** over VLESS reverse, for when UDP between gateway and portal dies.
7. **The other option** of A and B.
8. **Later:** Hysteria2; a gateway on Windows without Docker, which needs the
   AmneziaWG Windows tools in place of `awg-quick` and Windows NAT in place of
   `iptables`.

## Open questions

- **A kernel module on the host.** `awg-quick` prefers it over the pinned `amneziawg-go`,
  and an older module may refuse a 3.1 config, in which case the tunnel fails on every
  retry with the error in the log. Not tried yet: the module's source was not checked,
  and every run so far was on `amneziawg-go`.
- **Trunk MTU under option A.** A client's encrypted packets travel inside the trunk,
  so a client's MTU has to be lower than the trunk's. The current 1280 comes from a
  cascade of type B. Measure this at stage 2 and raise the trunk MTU if needed.
- **`amneziawg-go` speed** against the kernel module, on x86-64 and on ARM. No measured
  numbers yet, and the installer has not measured AmneziaWG 3.1 on ARM either.
- **UDP over VLESS reverse.** The official example only shows TCP, which decides whether
  AmneziaWG clients can use the spare trunk.
