# Kalitka

A gateway behind NAT dials portals with public IPs, and clients reach the internet
through a portal and the gateway. We orchestrate existing VPN engines and write no
protocols.

| Read | When |
|---|---|
| `docs/architecture.md`, section Stages | Before starting work: what is done, what comes next |
| `docs/architecture.md`, section Principles | Before changing `internal/` |
| `docs/architecture.md`, section How a gateway will release traffic | Before changing how traffic leaves a gateway: what was measured and why |
| `docs/architecture.md`, section Open questions | Before settling trunk MTU, engine speed or the spare trunk |
| `README.md`, section Develop | For the build and test commands |

## Words

Say **gateway**, **portal**, **client** and **trunk**, as defined in the section Terms
of `docs/architecture.md`. Do not say entry, exit or node, and never call the gateway a
client: the connection opens against the direction of the traffic, so those words
mislead.

## Must keep

- **A portal is not trusted.** An invite comes from a portal, and its values reach the
  engine's line-based config on the gateway. A new invite field gets strict validation
  in `Invite.Validate` and a case in `TestDecodeInviteRejectsHostileFields`.
- **An unreachable portal is a normal state.** The gateway keeps trying, and one portal
  never affects another trunk.
- **The AmneziaWG profile is measured, not designed.** `awg.NewParams` follows the
  upstream installer; values that look odd are deliberate. Change them only with a
  measurement behind the change.
- **All ends run one AmneziaWG generation.** The engine's version is pinned in `go.mod`,
  because generations do not interoperate and a gateway abroad may be impossible to
  reach after a bad upgrade. The `awg` tool pinned in `test/trunk/Dockerfile` is only a
  witness for the test.
- **Docker is not part of the product.** It stays in `test/`. A complex dependency has to
  give a real benefit: being already installed on a machine is no reason.
- **Names stay neutral.** Process and interface names carry no "vpn", "proxy" or
  "bypass": they are visible to whoever hosts a portal.
- **The repository is public.** No real addresses, locations, keys or names of the
  machines in use, in code, docs, tests or commit messages. Examples use `203.0.113.0/24`
  and `.example` hostnames.
- **The engine is the only Go dependency.** A new one needs a stated reason.

## Testing

- Run `test/trunk/run.sh` after changing `internal/` or the engine's version. Unit tests
  do not prove that a tunnel comes up.
- A pass means a trunk works in containers on one machine. It says nothing about real
  networks or filtering, and it does not cover publishing a port on a real portal.
- From Windows, run both in WSL. `wsl.exe` expands `$VAR` in its arguments before Linux
  sees them, so use `wsl --exec bash -c '...'`.

## Ask first

Where the client VPN ends (options A and B in `docs/architecture.md`) has not been
decided, and stage 3 needs that decision. Do not choose it on your own.

## Docs

- Code, comments, docs and commit messages are in English.
- These docs are not checked against the code automatically. Where they disagree, the
  code wins, and the doc is corrected in the same change.
- One fact lives in one place and others point to it. Docs describe the current state:
  git keeps the history.
- Source comments state the fact itself and name no internal doc.
