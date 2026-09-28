#!/bin/sh
# cfprobe in Docker: runs the prober every hour, IPv4 then IPv6, like the systemd timer and the
# OpenWrt cron job that install.sh sets up. Configuration by environment:
#   CFHUB_TOKEN          your token from https://cfhub.1molchuan.top/join (or CFHUB_TOKEN_FILE, a file
#                        holding it, e.g. a Docker secret)
#   CFPROBE_AUTO_UPDATE  1 (default): install newer releases signed by the maintainer's offline key
#                        (see echprobe/selfupdate.go) into /data; 0: keep this image's binary until
#                        you pull a newer image
#   CFPROBE_INTERVAL     seconds between runs, default 3600 (at least 1200)
#   CFPROBE_DIRECT       "auto" or an interface name: bind the prober's traffic to the host's physical
#                        interface, past a proxy's TUN device on the host (needs --network host)
#   CFHUB_URL            another cfhub (self-hosted), default https://cfhub.1molchuan.top
# The prober runs as nobody, opens no ports and keeps its state in /data.
set -eu
HUB=${CFHUB_URL:-https://cfhub.1molchuan.top}
DATA=/data
IMAGE_BIN=/opt/cfprobe/cfprobe

if [ -z "${CFHUB_TOKEN:-}" ] && [ -n "${CFHUB_TOKEN_FILE:-}" ]; then
  CFHUB_TOKEN=$(cat "$CFHUB_TOKEN_FILE")
fi
case "${CFHUB_TOKEN:-}" in
  cfp_????????????????????*) ;;
  *) echo "cfprobe: set CFHUB_TOKEN to your token (get one at $HUB/join)" >&2; exit 1 ;;
esac
export CFHUB_TOKEN
interval=${CFPROBE_INTERVAL:-3600}
[ "$interval" -ge 1200 ] 2>/dev/null || interval=3600
DIRECT=""
if [ -n "${CFPROBE_DIRECT:-}" ]; then
  case "$CFPROBE_DIRECT" in
    *[!A-Za-z0-9._@-]*) echo "cfprobe: CFPROBE_DIRECT takes \"auto\" or an interface name" >&2; exit 1 ;;
  esac
  DIRECT="-direct $CFPROBE_DIRECT"
fi

mkdir -p "$DATA"
BIN=$IMAGE_BIN
UPDATE="-no-update"
if [ "${CFPROBE_AUTO_UPDATE:-1}" != 0 ]; then
  # An update replaces the prober's own file, so it runs from the volume. A new image (a different
  # built-in binary) starts over from its own copy.
  sum=$(sha256sum "$IMAGE_BIN" | cut -d' ' -f1)
  if [ ! -x "$DATA/cfprobe" ] || [ "$(cat "$DATA/.image-sha256" 2>/dev/null)" != "$sum" ]; then
    cp "$IMAGE_BIN" "$DATA/.cfprobe.new"
    mv -f "$DATA/.cfprobe.new" "$DATA/cfprobe"
    echo "$sum" > "$DATA/.image-sha256"
  fi
  BIN=$DATA/cfprobe
  UPDATE=""
fi

AS=""
if [ "$(id -u)" = 0 ]; then
  chown -R nobody:nobody "$DATA"
  AS="setuidgid nobody"
fi

# Run in the background and wait, so `docker stop` ends the container at once.
child=""
trap '[ -n "$child" ] && kill "$child" 2>/dev/null; exit 0' TERM INT
fg() {
  "$@" &
  child=$!
  wait "$child"
}

echo "cfprobe: reporting to $HUB every $((interval / 60)) min$([ -n "$UPDATE" ] && echo ", auto-update off")"
while :; do
  fg $AS timeout 1200 "$BIN" -hub "$HUB" -history "$DATA/history4.json" $UPDATE $DIRECT || echo "cfprobe: IPv4 run failed (exit $?)"
  # IPv6 is optional (a Docker bridge network usually has none): without it this run just fails.
  fg $AS timeout 1200 "$BIN" -hub "$HUB" -history "$DATA/history6.json" -family 6 $UPDATE $DIRECT || echo "cfprobe: IPv6 run failed or no IPv6 (exit $?)"
  fg sleep $((interval + RANDOM % 600))
done
