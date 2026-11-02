#!/usr/bin/env bash
# End-to-end check of the trunk with the real engines in containers. It proves that
# a gateway behind NAT
#   - keeps dialling a portal that is down, and connects once the portal appears;
#   - reaches the portal through the NAT, with no way in from the portal's side;
#   - carries traffic both ways, so the portal can send to the gateway;
#   - reconnects by itself after the portal restarts.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

readonly NAT_PUBLIC_IP=172.30.0.2
readonly HANDSHAKE_TIMEOUT=120

compose() { docker compose -f compose.yaml "$@"; }

cleanup() {
	local status=$?
	if [ "$status" -ne 0 ]; then
		echo "--- FAILED, logs:"
		compose logs --no-color --tail 40 || true
	fi
	compose down --volumes --timeout 5 >/dev/null 2>&1 || true
	exit "$status"
}
trap cleanup EXIT

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

latest_handshake() {
	compose exec -T portal awg show trunk0 latest-handshakes 2>/dev/null | cut -f2 | head -n 1
}

# Waits until the portal reports a handshake newer than the given unix time.
wait_for_handshake_after() {
	local after=$1 deadline=$((SECONDS + HANDSHAKE_TIMEOUT)) latest
	while [ "$SECONDS" -lt "$deadline" ]; do
		latest=$(latest_handshake || true)
		if [ -n "$latest" ] && [ "$latest" -gt "$after" ]; then
			return 0
		fi
		sleep 2
	done
	fail "no handshake within ${HANDSHAKE_TIMEOUT}s"
}

trunk_address() {
	compose exec -T "$1" ip -4 -o addr show dev trunk0 | sed -E 's/.* inet ([0-9.]+).*/\1/'
}

echo "--- building the image"
docker build --quiet -t kalitka:test -f ../../deploy/Dockerfile ../.. >/dev/null

echo "--- creating the portal and joining the gateway to it"
compose run -T --rm --no-deps portal portal init --name test --host 172.30.0.10 --port 39743
invite=$(compose run -T --rm --no-deps portal portal invite --gateway home)
compose run -T --rm --no-deps --entrypoint kalitka gateway gateway join "$invite"

echo "--- starting the gateway while the portal is down"
compose up -d nat gateway
sleep 10
[ "$(compose ps --status running --services | grep -c '^gateway$')" -eq 1 ] || fail "the gateway did not survive a missing portal"

echo "--- starting the portal"
compose up -d portal
wait_for_handshake_after 0
echo "ok: the gateway connected once the portal appeared"

endpoint=$(compose exec -T portal awg show trunk0 endpoints | cut -f2)
case "$endpoint" in
"$NAT_PUBLIC_IP":*) echo "ok: the portal sees the gateway at the NAT address ($endpoint)" ;;
*) fail "the gateway did not come through the NAT: the portal sees $endpoint" ;;
esac

if compose exec -T portal ping -c 1 -W 2 172.30.1.10 >/dev/null 2>&1; then
	fail "the portal reached the gateway directly, so the test network is not behind NAT"
fi
echo "ok: the portal has no direct way to the gateway"

portal_address=$(trunk_address portal)
gateway_address=$(trunk_address gateway)
compose exec -T gateway ping -c 3 -W 2 "$portal_address" >/dev/null || fail "gateway to portal over the trunk"
compose exec -T portal ping -c 3 -W 2 "$gateway_address" >/dev/null || fail "portal to gateway over the trunk"
echo "ok: traffic flows both ways over the trunk ($gateway_address, $portal_address)"

# 1200 bytes of data make a 1228-byte IP packet, close to the trunk's 1280 MTU.
compose exec -T portal ping -c 3 -W 2 -s 1200 "$gateway_address" >/dev/null || fail "large packets over the trunk"
echo "ok: packets close to the MTU pass"

echo "--- restarting the portal"
before=$(date +%s)
compose restart portal
wait_for_handshake_after "$before"
compose exec -T portal ping -c 3 -W 2 "$gateway_address" >/dev/null || fail "portal to gateway after the restart"
echo "ok: the gateway reconnected by itself"

echo "PASS"
