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

One file holds the program and the VPN engine. On Linux, x86-64 or ARM64, it needs root,
`/dev/net/tun` and the `ip` command.

Build it for the machine with Go 1.25, then copy it there:

```sh
CGO_ENABLED=0 GOARCH=amd64 go build -o kalitka ./cmd/kalitka
```

On the portal, pick a UDP port and open it in the firewall:

```sh
sudo ./kalitka portal init --host 203.0.113.10 --port 39743
sudo ./kalitka portal invite --gateway home
sudo ./kalitka portal run
```

The second command prints an invite. It holds a private key, so send it over a
private channel. On the gateway, run the first command below and paste the invite when
it asks:

```sh
sudo ./kalitka gateway join
sudo ./kalitka gateway run
```

Repeat the invite and the join for every further portal, and restart `kalitka`
afterwards: a running portal or gateway loads its state at start.

These commands run in the foreground, and nothing restarts them yet after a logout, a
crash or a reboot. A service unit comes with the next stage.

To look inside, run with `KALITKA_DEBUG=1`: the log shows what the engine does, and the
upstream `awg show` works if that tool is installed.

## Develop

Go is not required on the host:

```sh
docker run --rm -v "$PWD:/src:ro" -w /src golang:1.25.12 sh -c 'gofmt -l .; go vet ./... && go test ./...'
```

`gofmt -l` prints nothing when the formatting is clean.

The end-to-end test builds an image and runs real trunks through a simulated NAT:

```sh
test/trunk/run.sh
```
