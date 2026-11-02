#!/usr/bin/env bash
# End-to-end check of the trunk with the real engine in containers. It proves that
# a gateway behind NAT
#   - keeps dialling a portal that is down, past the point where WireGuard gives up on
#     a handshake, and connects once the portal appears;
#   - reaches the portal through the NAT, with no way in from the portal's side;
#   - runs with the same obfuscation settings as the portal on the device itself;
#   - carries traffic both ways, up to the trunk's MTU;
#   - reconnects by itself after the portal restarts;
#   - brings its tunnel back when the interface disappears, and does not leak doing so;
#   - keeps its trunks apart inside one process: one portal being down or one interface
#     disappearing does not touch the other trunk.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

readonly NAT_PUBLIC_IP=172.30.0.2
readonly HANDSHAKE_TIMEOUT=120
readonly TRUNK_MTU=1280
# WireGuard gives up on a handshake after about 90 seconds, so a shorter outage would
# not show that the gateway keeps dialling.
readonly OUTAGE=130
readonly LEAK_CYCLES=3

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
	compose exec -T "$1" awg show trunk0 latest-handshakes 2>/dev/null | cut -f2 | head -n 1
}

# Waits until a portal reports a handshake newer than the given unix time.
wait_for_handshake_after() {
	local portal=$1 after=$2 deadline=$((SECONDS + HANDSHAKE_TIMEOUT)) latest
	while [ "$SECONDS" -lt "$deadline" ]; do
		latest=$(latest_handshake "$portal" || true)
		if [ -n "$latest" ] && [ "$latest" -gt "$after" ]; then
			return 0
		fi
		sleep 2
	done
	fail "no handshake on $portal within ${HANDSHAKE_TIMEOUT}s"
}

gateway_descriptors() {
	compose exec -T gateway sh -c 'ls /proc/$(pidof kalitka)/fd | wc -l' | tr -d '[:space:]'
}

trunk_address() {
	compose exec -T "$1" ip -4 -o addr show dev trunk0 | sed -E 's/.* inet ([0-9.]+).*/\1/'
}

bytes_sent_by_gateway() {
	compose exec -T gateway awg show "$1" transfer | cut -f3
}

device_settings() {
	compose exec -T "$1" awg showconf trunk0 | grep -E '^(Jc|Jmin|Jmax|S[1-4]|H[1-4]|I1|HeaderProtectionKey|ContentPaddingAddition) ='
}

# Reads the whole log first. In a pipe, grep -q would stop at the first match and the
# writer would die of SIGPIPE, which pipefail reports as a failure.
gateway_logged() {
	grep -q "$1" <<<"$(compose logs --no-color gateway)"
}

echo "--- building the image"
docker build --quiet -t kalitka:test -f Dockerfile ../.. >/dev/null

echo "--- creating two portals and joining the gateway to them"
compose run -T --rm --no-deps portal portal init --name test --host portal.example --port 39743
compose run -T --rm --no-deps portal2 portal init --name test2 --host 172.30.0.11 --port 39743
for portal in portal portal2; do
	invite=$(compose run -T --rm --no-deps "$portal" portal invite --gateway home)
	printf '%s\n' "$invite" | compose run -T --rm --no-deps --entrypoint kalitka gateway gateway join
done

echo "--- starting the gateway while the portals are down, for ${OUTAGE}s"
compose up -d nat gateway
sleep "$OUTAGE"
gateway_logged 'tunnel is up' || fail "the gateway never finished bringing its tunnel up"
sent_before=$(bytes_sent_by_gateway trunk0)
sleep 40
sent_after=$(bytes_sent_by_gateway trunk0)
[ "$sent_after" -gt "$sent_before" ] || fail "the gateway stopped dialling: $sent_before bytes sent, then $sent_after"
echo "ok: the gateway is still dialling after the handshake timeout ($sent_before, then $sent_after bytes)"

echo "--- starting the first portal, the second stays down"
compose up -d portal
wait_for_handshake_after portal 0
echo "ok: the gateway connected once the portal appeared"

endpoint=$(compose exec -T portal awg show trunk0 endpoints | cut -f2)
case "$endpoint" in
"$NAT_PUBLIC_IP":*) echo "ok: the portal sees the gateway at the NAT address ($endpoint)" ;;
*) fail "the gateway did not come through the NAT: the portal sees $endpoint" ;;
esac

# The control: without it, any failure of the command below would read as "no way".
compose exec -T portal ping -c 1 -W 2 "$NAT_PUBLIC_IP" >/dev/null || fail "control: the portal cannot ping the NAT"
if compose exec -T portal ping -c 1 -W 2 172.30.1.10 >/dev/null 2>&1; then
	fail "the portal reached the gateway directly, so the test network is not behind NAT"
fi
echo "ok: the portal has no direct way to the gateway"

portal_settings=$(device_settings portal)
gateway_settings=$(device_settings gateway)
[ "$portal_settings" = "$gateway_settings" ] || fail "the two ends run different obfuscation settings"
for setting in HeaderProtectionKey ContentPaddingAddition I1 S4 H4; do
	grep -q "^$setting = " <<<"$gateway_settings" || fail "$setting did not reach the device"
done
echo "ok: both ends run the same obfuscation settings, header protection included"

portal_address=$(trunk_address portal)
gateway_address=$(trunk_address gateway)
compose exec -T gateway ping -c 3 -W 2 "$portal_address" >/dev/null || fail "gateway to portal over the trunk"
compose exec -T portal ping -c 3 -W 2 "$gateway_address" >/dev/null || fail "portal to gateway over the trunk"
echo "ok: traffic flows both ways over the trunk ($gateway_address, $portal_address)"
echo "ok: a second portal being down does not touch this trunk"

for side in portal gateway; do
	mtu=$(compose exec -T "$side" cat /sys/class/net/trunk0/mtu)
	[ "$mtu" -eq "$TRUNK_MTU" ] || fail "$side has MTU $mtu on the trunk, expected $TRUNK_MTU"
done
# With the 8-byte ICMP header and the 20-byte IP header this fills the MTU exactly.
compose exec -T portal ping -c 3 -W 2 -s $((TRUNK_MTU - 28)) "$gateway_address" >/dev/null || fail "packets of the full MTU over the trunk"
echo "ok: packets of the full MTU pass"

echo "--- starting the second portal"
compose up -d portal2
wait_for_handshake_after portal2 0
portal2_address=$(trunk_address portal2)
compose exec -T gateway ping -c 3 -W 2 "$portal2_address" >/dev/null || fail "gateway to the second portal"
echo "ok: the gateway holds a second trunk in the same process ($portal2_address)"

echo "--- restarting the portal"
before=$(date +%s)
compose restart portal
wait_for_handshake_after portal "$before"
compose exec -T portal ping -c 3 -W 2 "$gateway_address" >/dev/null || fail "portal to gateway after the restart"
echo "ok: the gateway reconnected by itself"

echo "--- removing the gateway's interface"
before=$(date +%s)
compose exec -T gateway ip link delete trunk0
compose exec -T gateway ping -c 3 -W 2 "$portal2_address" >/dev/null || fail "the second trunk suffered when the first interface disappeared"
echo "ok: losing one interface does not touch the other trunk"
wait_for_handshake_after portal "$before"
gateway_logged 'tunnel lost' || fail "the gateway did not notice the lost tunnel"
compose exec -T portal ping -c 3 -W 2 "$gateway_address" >/dev/null || fail "portal to gateway after the interface came back"
echo "ok: the gateway brought its tunnel back"

echo "--- removing it ${LEAK_CYCLES} more times"
descriptors_before=$(gateway_descriptors)
for ((cycle = 1; cycle <= LEAK_CYCLES; cycle++)); do
	before=$(date +%s)
	compose exec -T gateway ip link delete trunk0
	sleep 1
	wait_for_handshake_after portal "$before"
done
descriptors_after=$(gateway_descriptors)
# A socket closed by the garbage collector may linger, so a small growth is no leak.
[ "$descriptors_after" -le $((descriptors_before + LEAK_CYCLES * 2)) ] ||
	fail "the gateway leaks descriptors: $descriptors_before, then $descriptors_after after $LEAK_CYCLES restarts"
echo "ok: no leak over $LEAK_CYCLES restarts of a tunnel ($descriptors_before, then $descriptors_after descriptors)"

echo "PASS"
