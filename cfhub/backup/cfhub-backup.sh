#!/usr/bin/env bash
# cfhub 备份（在 cfhub 服务器上由 cfhub-backup.timer 每天运行）：
#   数据库在线快照（先做完整性检查）+ /etc/cfhub/env → tar.gz → age 加密给站长的公钥
#   → 本机留最近 7 份 → 推给每个异地接收端（receiver.sh 装的 cfhub-backup 账号，命令 put）。
# 解密用的私钥只在站长自己的电脑上，服务器和接收端都只有密文。
#
# /etc/cfhub-backup/recipient   age 公钥（age1...）
# /etc/cfhub-backup/id_ed25519  推送用的 SSH 私钥（接收端只允许它 put/list/get）
# /etc/cfhub-backup/known_hosts 接收端的主机公钥（固定，不自动信任）
# /etc/cfhub-backup/targets     每行一个接收端：user@host[:port]
set -euo pipefail

CONF=/etc/cfhub-backup
DB=/var/lib/cfhub/hub.db
LOCAL=/var/backups/cfhub
KEEP_LOCAL=7

recipient=$(cat "$CONF/recipient")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
chown cfhub: "$work"

# Snapshot as the cfhub user, so a stopped hub never finds root-owned -wal/-shm files afterwards.
runuser -u cfhub -- python3 - "$DB" "$work/hub.db" <<'EOF'
import sqlite3, sys
src = sqlite3.connect(sys.argv[1])
dst = sqlite3.connect(sys.argv[2])
src.backup(dst)
src.close()
check = dst.execute("PRAGMA integrity_check").fetchone()[0]
counts = {t: dst.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in ("users", "reports", "prober_uptime")}
dst.close()
if check != "ok":
    sys.exit("integrity check failed: " + check)
print("snapshot ok", counts)
EOF
cp /etc/cfhub/env "$work/env"
{
	echo "created: $(date -u +%FT%TZ)"
	echo "host: $(hostname)"
	echo "cfhub: $(sha256sum /opt/cfhub/cfhub | cut -d' ' -f1)"
} > "$work/MANIFEST"

name=cfhub-$(date -u +%Y%m%dT%H%M%SZ).tar.gz.age
tar -C "$work" -czf - MANIFEST hub.db env | age -r "$recipient" -o "$work/$name"
install -d -m 700 "$LOCAL"
install -m 600 "$work/$name" "$LOCAL/$name"
ls -1t "$LOCAL"/*.age | tail -n +$((KEEP_LOCAL + 1)) | xargs -r rm -f --
echo "local copy $LOCAL/$name ($(stat -c %s "$work/$name") bytes)"

ok=0 failed=0
while read -r target; do
	target=${target%%#*}
	target=$(echo "$target" | tr -d '[:space:]')
	[ -n "$target" ] || continue
	host=${target%:*} port=22
	[ "$host" != "$target" ] && port=${target##*:}
	if ssh -i "$CONF/id_ed25519" -p "$port" -o BatchMode=yes -o ConnectTimeout=20 -o ServerAliveInterval=15 \
		-o StrictHostKeyChecking=yes -o UserKnownHostsFile="$CONF/known_hosts" -o IdentitiesOnly=yes \
		"$host" put < "$work/$name"; then
		ok=$((ok + 1))
	else
		echo "push to $target failed" >&2
		failed=$((failed + 1))
	fi
done < <(cat "$CONF/targets" 2>/dev/null || true)
echo "pushed to $ok target(s), $failed failed"
[ "$failed" = 0 ]
