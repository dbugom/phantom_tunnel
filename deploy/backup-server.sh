#!/usr/bin/env bash
#
# Phantom Tunnel — Server decommission backup (READ-ONLY)
# ------------------------------------------------------
# Run this ON THE SERVER (46.225.106.10) as root BEFORE you power it off.
# It only READS state — it never stops the service or modifies anything.
#
# It captures everything that is NOT reproducible from the git repo:
#   - the server's Noise private key + real config.toml   (IRREPLACEABLE)
#   - the live Caddyfile, systemd units, decoy backend
#   - Let's Encrypt account + certs (so renewal keeps working elsewhere)
#   - firewall / sysctl / TCP tuning, deployed binary + version
#   - which git branch/commit is actually deployed
#
# Output: /root/phantom-decommission-<host>-<date>.tar.gz
# Then pull it to your laptop:
#   scp root@46.225.106.10:/root/phantom-decommission-*.tar.gz .
#
# WARNING: the tarball contains PRIVATE KEYS. Keep it secret; store encrypted.

set -u
umask 077

STAMP="$(date +%Y%m%d-%H%M%S 2>/dev/null || echo manual)"
HOST="$(hostname 2>/dev/null || echo server)"
OUT="/root/phantom-decommission-${HOST}-${STAMP}"
mkdir -p "$OUT"

log()  { printf '  [+] %s\n' "$*"; }
warn() { printf '  [!] %s\n' "$*"; }
copy() { # copy() SRC DESTSUBDIR  — copy if exists, note if not
  if [ -e "$1" ]; then mkdir -p "$OUT/$2"; cp -a "$1" "$OUT/$2/" 2>/dev/null && log "saved $1"; else warn "missing: $1"; fi
}

echo "=== Phantom Tunnel server backup → $OUT ==="

# 1. Find phantom config(s) — the server private key lives here.
log "searching for phantom config + keys..."
mkdir -p "$OUT/config"
for d in /etc/phantom_tunnel /etc/phantom /opt/phantom* /root /home/* /srv/phantom*; do
  [ -d "$d" ] || continue
  find "$d" -maxdepth 3 -type f -name '*.toml' 2>/dev/null | while read -r f; do
    if grep -qiE '\[server\]|private_key|allowed_clients|decoy' "$f" 2>/dev/null; then
      dest="$OUT/config$(dirname "$f")"; mkdir -p "$dest"; cp -a "$f" "$dest/" && log "saved config $f"
    fi
  done
done

# 2. Reverse proxy / decoy (this deployment uses nginx on :80; Caddy kept for older setups).
copy /etc/caddy/Caddyfile              caddy
copy /root/Caddyfile                   caddy
copy /etc/nginx                        nginx-full
copy /var/www                          decoy-webroot

# 3. systemd units for phantom + caddy.
mkdir -p "$OUT/systemd"
for u in /etc/systemd/system/phantom*.service /etc/systemd/system/caddy*.service \
         /lib/systemd/system/caddy*.service; do
  [ -e "$u" ] && cp -a "$u" "$OUT/systemd/" && log "saved unit $(basename "$u")"
done
systemctl list-units --type=service --all 2>/dev/null | grep -iE 'phantom|caddy' > "$OUT/systemd/status.txt" 2>/dev/null
for s in phantom-tunnel phantom-server phantom caddy; do
  systemctl status "$s" --no-pager -l >> "$OUT/systemd/status.txt" 2>/dev/null
done

# 4. Docker (in case phantom runs as a container).
if command -v docker >/dev/null 2>&1; then
  mkdir -p "$OUT/docker"
  docker ps -a          > "$OUT/docker/ps.txt"      2>/dev/null && log "saved docker ps"
  docker images         > "$OUT/docker/images.txt"  2>/dev/null
  for c in $(docker ps -aq 2>/dev/null); do
    docker inspect "$c" >> "$OUT/docker/inspect.json" 2>/dev/null
  done
  find / -maxdepth 4 -name 'docker-compose*.y*ml' 2>/dev/null | while read -r f; do
    dest="$OUT/docker$(dirname "$f")"; mkdir -p "$dest"; cp -a "$f" "$dest/"; log "saved $f"
  done
fi

# 5. Let's Encrypt — scope to THIS tunnel's domain so we don't sweep in unrelated
#    certs + private keys (derive the domain from the server config's tls_cert path).
LE_DOMAIN=""
PH_CFG="$(find "$OUT/config" -name config.toml -path '*phantom_tunnel*' ! -path '*example*' 2>/dev/null | head -1 || true)"
[ -n "$PH_CFG" ] && LE_DOMAIN="$(grep -oE '/etc/letsencrypt/live/[^/]+/' "$PH_CFG" 2>/dev/null | head -1 | awk -F/ '{print $5}')"
if [ -n "$LE_DOMAIN" ]; then
  log "scoping Let's Encrypt capture to $LE_DOMAIN"
  copy "/etc/letsencrypt/live/$LE_DOMAIN"        letsencrypt/live
  copy "/etc/letsencrypt/archive/$LE_DOMAIN"     letsencrypt/archive
  copy "/etc/letsencrypt/renewal/$LE_DOMAIN.conf" letsencrypt/renewal
else
  warn "could not determine tunnel TLS domain — capturing ALL letsencrypt (may include unrelated certs/keys)"
  copy /etc/letsencrypt/live    letsencrypt
  copy /etc/letsencrypt/archive letsencrypt
  copy /etc/letsencrypt/renewal letsencrypt
fi
copy /etc/letsencrypt/accounts       letsencrypt   # shared ACME account (no per-domain data)
copy /etc/letsencrypt/renewal-hooks  letsencrypt   # pre/deploy/post renewal automation
copy /etc/letsencrypt/cli.ini        letsencrypt

# 6. Deployed source: which branch/commit is actually running?
log "locating deployed git checkout..."
for d in /root/phantom_tunnel /opt/phantom_tunnel /srv/phantom_tunnel /home/*/phantom_tunnel; do
  [ -d "$d/.git" ] || continue
  {
    echo "repo: $d"
    git -C "$d" rev-parse HEAD 2>/dev/null
    git -C "$d" status -sb 2>/dev/null
    git -C "$d" log --oneline -5 2>/dev/null
    git -C "$d" remote -v 2>/dev/null
  } > "$OUT/deployed-git-ref.txt" 2>/dev/null && log "deployed ref recorded from $d"
  # Self-contained code capture so redeploy does NOT depend on GitHub / a mutable branch.
  git -C "$d" bundle create "$OUT/phantom_tunnel.gitbundle" --all >/dev/null 2>&1 \
    && log "git bundle saved (all refs — GitHub-independent)"
  [ -f "$d/Cargo.lock" ] && cp -a "$d/Cargo.lock" "$OUT/Cargo.lock" && log "saved Cargo.lock"
done

# 7. Installed binary: path, version, checksum.
log "locating phantom-server binary..."
{
  echo "== toolchain =="
  ( rustc --version 2>/dev/null || "$HOME/.cargo/bin/rustc" --version 2>/dev/null || echo "rustc: unknown" )
  ( cargo --version 2>/dev/null || "$HOME/.cargo/bin/cargo" --version 2>/dev/null || echo "cargo: unknown" )
  echo
  for b in $(command -v phantom-server 2>/dev/null) /usr/local/bin/phantom-server \
           /usr/bin/phantom-server /root/phantom_tunnel/target/release/phantom-server \
           /opt/phantom_tunnel/target/release/phantom-server; do
    [ -x "$b" ] || continue
    echo "== $b =="; file "$b" 2>/dev/null; sha256sum "$b" 2>/dev/null
    "$b" --version 2>&1 | head -3; "$b" --help 2>&1 | head -20; echo
  done
} > "$OUT/binary-info.txt" 2>/dev/null

# 8. Firewall + network + TCP tuning.
mkdir -p "$OUT/network"
ufw status verbose            > "$OUT/network/ufw.txt"        2>/dev/null
iptables-save                 > "$OUT/network/iptables.txt"   2>/dev/null
ss -tlnp                      > "$OUT/network/listening.txt"  2>/dev/null
sysctl -a 2>/dev/null | grep -E 'tcp_congestion|somaxconn|rmem|wmem|backlog|tcp_fin|keepalive' > "$OUT/network/sysctl-tuning.txt"
copy /etc/sysctl.conf                network
for f in /etc/sysctl.d/*phantom* /etc/sysctl.d/*tcp* /etc/security/limits.d/*phantom*; do
  [ -e "$f" ] && cp -a "$f" "$OUT/network/" 2>/dev/null && log "saved $f"
done

# 9. Recent logs (context, not required).
mkdir -p "$OUT/logs"
for s in phantom-tunnel phantom-server phantom caddy; do
  journalctl -u "$s" --no-pager -n 300 >> "$OUT/logs/journal.txt" 2>/dev/null
done

# 10. Manifest + system facts.
{
  echo "Phantom Tunnel decommission backup"
  echo "host:    $HOST"
  echo "when:    $(date 2>/dev/null)"
  echo "ip:      $(hostname -I 2>/dev/null || hostname -i 2>/dev/null)"
  echo "os:      $(. /etc/os-release 2>/dev/null; echo "$PRETTY_NAME")"
  echo "kernel:  $(uname -a)"
  echo
  echo "=== files captured ==="
  ( cd "$OUT" && find . -type f | sort )
} > "$OUT/MANIFEST.txt" 2>/dev/null

# 11. Tar it up.
TARBALL="${OUT}.tar.gz"
tar -czf "$TARBALL" -C "$(dirname "$OUT")" "$(basename "$OUT")" 2>/dev/null
rm -rf "$OUT"

echo
echo "=== DONE ==="
echo "Backup written to: $TARBALL"
echo "Size: $(du -h "$TARBALL" 2>/dev/null | cut -f1)"
echo
echo "Pull it to your laptop (run this LOCALLY):"
echo "  scp root@46.225.106.10:$TARBALL ."
echo
echo "!!  This tarball contains PRIVATE KEYS. Keep it secret / encrypted.  !!"
echo
echo "AFTER you have pulled + verified it, remove the on-box copy:"
echo "  shred -u $TARBALL   # best-effort on a VPS (see docs/DECOMMISSION.md)"
echo "Before RELEASING the VPS, wipe the live secrets too (they persist on disk):"
echo "  shred -u /etc/phantom_tunnel/config.toml"
echo "  rm -rf /etc/letsencrypt/{archive,live,keys,accounts}   # then let the provider reimage"
