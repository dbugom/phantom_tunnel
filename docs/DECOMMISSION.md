# Phantom Tunnel — Decommission & Redeploy Runbook

How to **safely shut down** the production server and **redeploy** it later
(identically, or fresh). Reflects the *actual* deployment as of the last backup —
not the generic template in `DEPLOYMENT.md`.

---

## 1. As-built record (server being decommissioned)

| | |
|---|---|
| Host / IP | `phantom` @ `46.225.106.10` |
| OS | Ubuntu 24.04.1 LTS (kernel 6.8) |
| Deploy branch / commit | `release/stable-v2` @ **`79b50d1`** (automated `setup.sh`) |
| Source dir | `/opt/phantom_tunnel` (clean, in sync with GitHub) |
| Binary | `/opt/phantom_tunnel/target/release/phantom-server` v0.1.0 (sha256 `eb66a0d1…`) |
| Service | `phantom-tunnel.service` (systemd, hardened) → binds `0.0.0.0:443` |
| Config | `/etc/phantom_tunnel/config.toml` |
| Decoy | nginx **stock** default page on `:80` (no `decoy_backend` in config) |
| TLS (phantom.yfy.ae) | certbot **standalone**, ECDSA — cert valid **until Aug 12 2026** |
| TLS (tender.yfi.ae) | certbot **nginx** authenticator — *unrelated* second domain on same box |
| Kernel tuning | `/etc/sysctl.d/99-phantom-tunnel.conf` (BBR, 16 MB buffers, TFO) |
| Firewall | ufw **inactive** |
| Server public key | `u4KUA0/Gog3DrpXdd1Xuh1jIUoxSTPriq8v8v3/FuxI=` |

### Client roster — `allowed_clients` (fill in the unknowns!)
Clients connect by **raw IP** (`server = "46.225.106.10:443"`), not DNS, so **any
server-IP change requires hand-editing every client's `server=` line.** You can
only do that for devices you can identify — complete this table and keep it with
the backup:

| # | Client public key | Device / owner | Config location |
|---|---|---|---|
| 1 | `72kzuQrMmxv9jHUzLE0nhe6GFvGDyQkVJPR2+8mdlWY=` | macOS (this laptop) | `~/phantom_tunnel/client.toml` |
| 2 | `WTkwo2taGRd+Qm5CDGpjqAmAEIaVUMwKaU4ocn85EH4=` | **UNKNOWN — identify** | ? |
| 3 | `wRKwx8hGDF8yohlyeOXuAu8RxpH9XFpx7yTPwNQUaC8=` | **UNKNOWN — identify** (MikroTik RB5009?) | ? |
| 4 | `dNiKMrDgtaF/7EzezezmKB5HYJyu1lj9/Yi/SWY/sVQ=` | **UNKNOWN — identify** | ? |

### Domain / DNS control plane (record this — it is NOT in the backup)
Identity-preserving redeploy (§5 Option A) needs the DNS A record pointed at the
new box and an ACME http-01 challenge to reissue the cert. If domain control
lapses, redeploy is impossible. Document and store **alongside** (not inside) the
secret backup:

| Domain | Registrar | DNS provider | Login / 2FA custodian | Renewal owner |
|---|---|---|---|---|
| `yfy.ae` (phantom) | **fill in** | | | |
| `yfi.ae` (tender + admin email `abc@yfi.ae`) | **fill in** | | | |

### Other things on the box (decide separately)
- **RustDesk** — `docker-compose` at `/opt/containers/rustdesk/` (unrelated to the tunnel).
- **`tender.yfi.ae`** — second, unrelated domain/cert (nginx-authenticator).

---

## 2. What was backed up

`deploy/backup-server.sh` was run on the server; the tarball lives **in this repo**
(gitignored):

```
~/phantom_tunnel/server-backup/phantom-decommission-phantom-<date>.tar.gz   (~270 KB)
```

Contents:
- real `config.toml` (server **private key** + all 4 authorized clients)
- **`phantom_tunnel.gitbundle`** — all git refs incl. the deployed commit `79b50d1`,
  so redeploy does **not** depend on GitHub or the branch staying put
- `Cargo.lock` + toolchain versions (build reproducibility)
- `phantom-tunnel.service`, full `/etc/nginx`, decoy webroot, sysctl tuning
- Let's Encrypt for **phantom.yfy.ae only** (cert chain, ACME account,
  `renewal-hooks/`, `cli.ini`) — the unrelated `tender.yfi.ae` key is **not** captured

> ⚠️ **The tarball contains PRIVATE KEYS.** Keep a **second, offsite, encrypted** copy.

### Verification (done)
- Server public key **cryptographically derived** from the backed-up private key
  == `u4KUA0…` == every client's `server_public_key`. ✓
- `git bundle verify` OK and contains `79b50d1`. ✓
- Deployed `/opt/phantom_tunnel` had **no uncommitted changes**. ✓

---

## 3. Pre-shutdown checklist (go / no-go)

- [x] All local git branches pushed to GitHub.
- [x] `client.toml` + `server-backup/` gitignored (secrets can't leak on commit).
- [x] Backup captured to `server-backup/`, verified (key match + valid git bundle).
- [ ] Backup tarball copied to a **second offsite/encrypted** location.
- [ ] Client roster (§1) completed — every `allowed_clients` key mapped to a device.
- [ ] Domain/DNS control plane (§1) documented; **A-record TTL lowered to 300s**
      a day before cutover to minimize redeploy downtime.
- [ ] Fate of **RustDesk** and **`tender.yfi.ae`** decided (they die with the box too).

## 4. Disabling the server

Once the checklist is green, on the server:

```bash
systemctl stop phantom-tunnel && systemctl disable phantom-tunnel   # cuts the tunnel
```

**Wipe secrets before releasing the VM** (the disk may be reclaimed without a secure
wipe; on a censorship-circumvention box the key is sensitive):

```bash
shred -u /root/phantom-decommission-*.tar.gz        # the on-box backup copy
shred -u /etc/phantom_tunnel/config.toml            # the Noise private key
rm -rf /etc/letsencrypt/{archive,live,keys,accounts}
```

> `shred` is **best-effort** on a VPS (virtual/SSD/COW storage). The reliable control
> is a **provider-side disk destroy / re-image**. If the hardware leaves your control
> and you cannot guarantee that, treat the server key as exposed and plan to rotate it
> (fresh keypair — §5 Option B) rather than reuse it.

Then destroy/stop the VPS from your provider's console (a manual action —
intentionally not scripted). If you're not redeploying soon, remove the
`phantom.yfy.ae` A record so it doesn't point at a stranger's future IP.

---

## 5. Redeploy later

### Option A — Identity-preserving (existing clients keep working) ✅ recommended
Reuses the same server keypair and rebuilds the **exact** commit `79b50d1`, so
clients need no change except the `server` IP if it moved.

```bash
# on a fresh Ubuntu 24.04 box, as root, with phantom.yfy.ae DNS → this box:
git clone https://github.com/dbugom/phantom_tunnel.git /opt/phantom_tunnel   # (or use the bundle)
cd /opt/phantom_tunnel && git checkout release/stable-v2
./deploy/restore-server.sh \
    --backup /path/to/phantom-decommission-phantom-<date>.tar.gz \
    --domain phantom.yfy.ae
```

`restore-server.sh` rebuilds from the backup: same private key, same
`allowed_clients`, the pinned commit (from the bundle — works even if GitHub is
gone), re-issued TLS cert (`--cert restore` reuses the old one unless it's <30 days
from expiry), sysctl tuning, systemd unit (ExecStart rewritten to the real path),
and **renewal hooks that stop/start nginx** so certbot renewal actually succeeds.

**If the server IP changed**, update only `server = "<newIP>:443"` in each client
(`client.toml` on macOS; env/config on the MikroTik container). `tls_sni` and
`server_public_key` stay the same.

### Option B — Fresh identity (new keypair)
Clean-slate server with a brand-new keypair (all clients must be re-issued):

```bash
./setup.sh server --domain phantom.yfy.ae
# then add each client's public key to allowed_clients, and distribute the NEW
# server public key it prints to every client.
```

---

## 6. Gotchas learned from the live box
- **Prod uses nginx, not Caddy.** `deploy/Caddyfile` in the repo is stale/unused.
- **certbot standalone vs nginx both want `:80`.** phantom.yfy.ae renews via
  `authenticator = standalone`, which needs `:80` free — but nginx holds `:80`. The
  live box had **only** a post-hook (`restart phantom-tunnel`, which binds `:443` and
  does *not* free `:80`), so its automatic renewal was in fact latently broken and
  would have failed at the next attempt (~30 days before the Aug 12 expiry).
  `restore-server.sh` fixes this by installing a **pre-hook `systemctl stop nginx`**
  and a **post-hook `start nginx` + `restart phantom-tunnel`**.
- **`setup.sh server` generates a NEW keypair every run** — use `restore-server.sh`
  (Option A) to keep existing client trust.
- **`--cert restore` can ship a near-expired cert**; the script now checks expiry and
  reissues if <30 days remain.
- phantom-server reads its TLS cert **only at startup** — anything that renews the
  cert must restart the service (the renewal post-hook does).
