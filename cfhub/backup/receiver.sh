#!/usr/bin/env bash
# cfhub 异地备份接收端。在愿意帮忙存备份的机器上，以 root 运行一次：
#
#   curl -fsSL <本文件地址> | sudo bash -s -- '<cfhub 服务器的公钥>' ['<站长恢复用的公钥>']
#   卸载（连同已存的备份一起删除）：curl -fsSL <本文件地址> | sudo bash -s -- --uninstall
#
# 它只做这些事：
# - 建一个没有密码的系统用户 cfhub-backup，家目录 /home/cfhub-backup；
# - 只允许给定的公钥登录，而且登录后只能执行 put（上传一份备份）、list（列出）、get（取回）；
#   没有 shell、不能端口转发，也碰不到 /home/cfhub-backup/data 以外的文件；
# - 只接受 age 加密过的文件（检查文件头），所以这台机器上存的都是密文，机器主人也看不到内容；
# - 最多保留 30 份、总共不超过 1GB，50 分钟内最多收一份。
# 不改 sshd 配置，不开端口，不装任何软件，也没有后台服务。
set -euo pipefail

USER_NAME=cfhub-backup
HOME_DIR=/home/$USER_NAME
HELPER_DIR=/usr/local/lib/cfhub-backup
HELPER=$HELPER_DIR/receive

die() { echo "错误：$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "请用 root 运行（sudo bash -s -- ...）"

if [ "${1:-}" = "--uninstall" ]; then
	if id "$USER_NAME" >/dev/null 2>&1; then
		pkill -u "$USER_NAME" 2>/dev/null || true
		userdel -r "$USER_NAME" 2>/dev/null || { userdel "$USER_NAME"; rm -rf "$HOME_DIR"; }
	fi
	rm -rf "$HELPER_DIR"
	echo "已卸载：用户 $USER_NAME 和其中的备份都已删除。"
	exit 0
fi

[ $# -ge 1 ] || die "用法：bash -s -- '<cfhub 服务器的公钥>' ['<恢复用公钥>']"
for key in "$@"; do
	[[ "$key" =~ ^(ssh-ed25519|ecdsa-sha2-nistp256|ssh-rsa)\ [A-Za-z0-9+/]+={0,2}(\ [^\"]*)?$ ]] || die "不像一个 SSH 公钥：$key"
done
command -v sshd >/dev/null 2>&1 || [ -x /usr/sbin/sshd ] || die "这台机器没有 sshd"
SSHD=$(command -v sshd || echo /usr/sbin/sshd)

# The command every key is forced into.
mkdir -p "$HELPER_DIR"
cat > "$HELPER.tmp" <<'EOF'
#!/usr/bin/env bash
# Forced command for the cfhub-backup key: put | list | get <name>|latest. Nothing else is possible.
set -euo pipefail
DATA=/home/cfhub-backup/data
KEEP=30
MAX_BYTES=$((200 * 1024 * 1024))
QUOTA=$((1024 * 1024 * 1024))
MIN_GAP=3000
umask 077
cd "$DATA"
newest() { ls -1t -- *.age 2>/dev/null | head -n 1 || true; }
read -r -a args <<< "${SSH_ORIGINAL_COMMAND:-}" || true
set -- "${args[@]}"
case "${1:-}" in
put)
	last=$(newest)
	if [ -n "$last" ] && [ $(( $(date +%s) - $(stat -c %Y "$last") )) -lt $MIN_GAP ]; then
		echo "refused: the last backup ($last) is less than $MIN_GAP seconds old" >&2
		exit 3
	fi
	tmp=.incoming.$$
	trap 'rm -f "$tmp"' EXIT
	head -c $((MAX_BYTES + 1)) > "$tmp"
	size=$(stat -c %s "$tmp")
	[ "$size" -le "$MAX_BYTES" ] || { echo "refused: larger than $MAX_BYTES bytes" >&2; exit 4; }
	[ "$(head -c 21 "$tmp")" = "age-encryption.org/v1" ] || { echo "refused: not an age-encrypted file" >&2; exit 5; }
	name=cfhub-$(date -u +%Y%m%dT%H%M%SZ).age
	mv "$tmp" "$name"
	trap - EXIT
	ls -1t -- *.age | tail -n +$((KEEP + 1)) | xargs -r rm -f --
	while [ "$(ls -1 -- *.age | wc -l)" -gt 1 ] && [ "$(cat -- *.age | wc -c)" -gt $QUOTA ]; do
		rm -f -- "$(ls -1t -- *.age | tail -n 1)"
	done
	echo "stored $name ($size bytes)"
	;;
list)
	for f in $(ls -1t -- *.age 2>/dev/null); do echo "$f $(stat -c %s "$f")"; done
	;;
get)
	name=${2:-}
	[ "$name" = latest ] && name=$(newest)
	[[ "$name" =~ ^cfhub-[0-9]{8}T[0-9]{6}Z\.age$ ]] && [ -f "$name" ] || { echo "no such backup: ${2:-}" >&2; exit 6; }
	cat -- "$name"
	;;
*)
	echo "usage: put < file | list | get <name>|latest" >&2
	exit 2
	;;
esac
EOF
chmod 755 "$HELPER.tmp"
mv "$HELPER.tmp" "$HELPER"

if ! id "$USER_NAME" >/dev/null 2>&1; then
	useradd --system --create-home --home-dir "$HOME_DIR" --shell /bin/sh "$USER_NAME"
fi
# "*" rather than a "!" lock: no password can ever match, and sshd still accepts the key without PAM.
usermod -p '*' "$USER_NAME"
mkdir -p "$HOME_DIR/data"
chown "$USER_NAME:" "$HOME_DIR" "$HOME_DIR/data"
chmod 750 "$HOME_DIR"
chmod 700 "$HOME_DIR/data"

# Where sshd looks for this user's keys (normally ~/.ssh/authorized_keys). The file is root's, so the
# account cannot change it.
akf=$("$SSHD" -T -C "user=$USER_NAME,host=localhost,addr=127.0.0.1" 2>/dev/null | awk '$1 == "authorizedkeysfile" { print $2; exit }')
akf=${akf:-.ssh/authorized_keys}
akf=${akf//%h/$HOME_DIR}
akf=${akf//%u/$USER_NAME}
akf=${akf//%%/%}
[ "${akf#/}" != "$akf" ] || akf=$HOME_DIR/$akf
mkdir -p "$(dirname "$akf")"
if [ "$(dirname "$akf")" = "$HOME_DIR/.ssh" ]; then
	chown root:root "$HOME_DIR/.ssh"
	chmod 755 "$HOME_DIR/.ssh"
fi
{
	for key in "$@"; do
		echo "restrict,command=\"$HELPER\" $key"
	done
} > "$akf.tmp"
chown root:root "$akf.tmp"
chmod 644 "$akf.tmp"
mv "$akf.tmp" "$akf"
command -v restorecon >/dev/null 2>&1 && restorecon -R "$HOME_DIR" "$HELPER_DIR" 2>/dev/null || true

port=$("$SSHD" -T 2>/dev/null | awk '$1 == "port" { print $2; exit }')
if "$SSHD" -T -C "user=$USER_NAME,host=localhost,addr=127.0.0.1" 2>/dev/null | grep -qiE '^(allowusers|allowgroups) '; then
	echo "注意：sshd 配置里有 AllowUsers/AllowGroups，需要把 $USER_NAME 加进去，否则连不上。" >&2
fi
ip=$(curl -fsS -m 10 https://api.ipify.org 2>/dev/null || echo "<这台机器的公网 IP>")

echo
echo "安装完成。请把下面几行原样发给站长（都不是密码，可以公开）："
echo "----"
echo "host: $ip"
echo "port: ${port:-22}"
echo "user: $USER_NAME"
for f in /etc/ssh/ssh_host_ed25519_key.pub /etc/ssh/ssh_host_ecdsa_key.pub; do
	[ -f "$f" ] && echo "hostkey: $(cut -d' ' -f1,2 "$f")" && break
done
echo "----"
echo "备份存在 $HOME_DIR/data，都是加密文件。不想继续帮忙时，用 --uninstall 卸载。"
