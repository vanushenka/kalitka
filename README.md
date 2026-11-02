# Kalitka

Reach the open internet through a machine behind NAT abroad. That machine, the
gateway, dials portals with public IPs itself, so it needs no open ports and no
public address. Clients connect to a portal with an ordinary VPN app.

```
client ───► portal ◄═══ trunk ═══ gateway ───► internet
            VPS or a PC           mini PC behind NAT
            with a public IP
```

The arrow of the trunk shows who dials, not where traffic goes: traffic flows both
ways. See [docs/architecture.md](docs/architecture.md) for the terms and the design.

**Status:** early. The trunk passes its end-to-end test in containers on one machine
and has not been tried on real networks. Clients cannot connect yet. See the stages in
the architecture document.

## Deploy the trunk

Requires Docker and `/dev/net/tun` on Linux, x86-64 or ARM64.

On the portal, pick a UDP port and open it in the firewall:

```sh
export KALITKA_TRUNK_PORT=39743
docker compose -f deploy/compose.portal.yaml run --rm portal portal init --host 203.0.113.10 --port "$KALITKA_TRUNK_PORT"
docker compose -f deploy/compose.portal.yaml run --rm portal portal invite --gateway home
docker compose -f deploy/compose.portal.yaml up -d
```

The second command prints an invite. It holds a private key, so send it over a
private channel. On the gateway, run the first command below and paste the invite when
it asks:

```sh
docker compose -f deploy/compose.gateway.yaml run --rm gateway gateway join
docker compose -f deploy/compose.gateway.yaml up -d
```

Repeat the invite and the join for every further portal, and restart the container
afterwards: a running portal or gateway loads its state at start.

Check the trunk on either side:

```sh
docker compose -f deploy/compose.gateway.yaml exec gateway awg show
```

## Develop

Go is not required on the host:

```sh
docker run --rm -v "$PWD:/src:ro" -w /src golang:1.25.12 sh -c 'gofmt -l .; go vet ./... && go test ./...'
```

`gofmt -l` prints nothing when the formatting is clean.

The end-to-end test builds the image and runs a real trunk through a simulated NAT:

```sh
test/trunk/run.sh
```
