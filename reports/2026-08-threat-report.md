# WebSpeare + Cowrie — Threat Report, August 2026 (FULL MONTH)

**Reporting window:** 2026-08-01 → 2026-08-31 (finalized 2026-09-11; supersedes the mid-month MTD draft)
**Sensors:** Cowrie SSH/Telnet (`do-us/new-york`) + 2× WebSpeare web nodes (`192.168.67.2/.3`)
**Maintainer:** Oak Atsume (DC801) · **Source:** Graylog (GELF feed)

---

## Executive summary

- **The month is dominated by a single-day, single-source event.** On **Aug 24** one host — **`194.180.49.37` (MEVSPACE sp. z o.o., PL/BG)** — fired **~1.32M web requests in one day**, throwing the entire exploit catalog at the honeypot. That one IP is ~1.3M of the month's ~2.6M web events and single-handedly pushed **Bulgaria to the #1 origin country**.
- **Two "new" exploit signatures appeared — but only from that one scanner.** **Log4Shell / JNDI-in-headers (44,140)** and **Server-Side Template Injection (12,433)** fired **exclusively on Aug 24** from `194.180.49.37`. They represent one actor's toolkit, not broad campaign adoption.
- **Our WAF upgrades went live and are working.** The **config-secrets decoy is engaging attackers** — 4,777 canaried `.env` serves — and the new App-Config rule (983) plus PHPInfo decoy broadening are all firing. The July/August gap work is deployed.
- **No LinkFlow / CVE-2026-5027 traffic** has reached these sensors (searched full-text + raw path/body/URL, ~75 days). The **only CVE the sensors tag by number remains CVE-2026-24061** (telnet arg-injection, 70 hits).
- **September is escalating hard** (166K–337K events/day vs August's ~70K baseline) — flagged here as a forward-looking warning; it will be the September report's focus.

---

## 1. Data quality & caveats

- **Aug 1–6:** tail end of the collection outage (relay tunnel drop + lost Asian-ISP data — confirmed by maintainer, **no compromise**). Volumes ~1.5K/day.
- **Aug 25–26, 29–30:** **zero events** — further collection gaps (tunnel/pipeline down), not quiet periods.
- **Aug 31:** near-zero (378).
- **The Aug 24 mega-spike is real, not a logging artifact** — it's one host's exploit blast (see §3), but it badly skews every month-total aggregate. **Read August rule/geo totals as "baseline + one Aug-24 blast," not steady state.**

---

## 2. Volume timeline (daily, all sensors)

```
Aug04 ▏ 1.1     Aug13 ██ 56.8      Aug22 ██ 76.8
Aug05 ▏ 1.5     Aug14 ████ 127.9   Aug23 ███ 108.7
Aug06 ▏ 7.5     Aug15 ██ 63.9      Aug24 ████████████████████████ 1,425.5  ← single-host blast
Aug07 ██ 76.5   Aug16 █ 44.0       Aug25   0   (outage)
Aug08 ██ 72.9   Aug17 ██ 73.3      Aug26   0   (outage)
Aug09 █ 55.7    Aug18 █ 54.3       Aug27 ██ 63.2
Aug10 ██ 75.7   Aug19 ██ 75.9      Aug28 █ 32.7
Aug11 ██ 76.3   Aug20 ███ 98.1     Aug29 0 / Aug30 0 (outage)
Aug12 ██ 77.1   Aug21 ██ 61.7      Aug31 ▏ 0.4
```
(values in thousands; Aug 24 bar truncated — it is ~10× the next-highest day)

---

## 3. The Aug 24 event — single-host mass exploitation  *(headline)*

| | |
|---|---|
| **Source** | `194.180.49.37` — **1,321,702** web requests (99.96% of the day's web traffic) |
| **ASN / geo** | **MEVSPACE sp. z o.o.** (Polish low-cost/bulletproof VPS), geo-tagged Bulgaria |
| **User-Agent** | *none* (blank) — automated tooling, no browser pretense |
| **Window** | concentrated burst on 2026-08-24 |

**What it threw (all on Aug 24):**
| Signature | Hits |
|---|---|
| Directory Traversal Attempt | 441,941 |
| Cloud Metadata SSRF — IMDS Credential Theft | 281,122 |
| Log4Shell — JNDI Injection in Headers | 44,140 *(first appearance)* |
| Server-Side Template Injection (SSTI) | 12,433 *(first appearance)* |
| + Secret File Enum, LFI, PHP stream-wrapper injection, etc. | remainder |

**Read:** a single rented host running an all-in-one web-vuln scanner (traversal → cloud-cred theft → Log4Shell → SSTI) at very high rate. High volume, low sophistication, no evasion. The IMDS-SSRF focus shows the operator is specifically hunting **cloud credentials**. Worth an abuse report to MEVSPACE and a firewall drop for the IP/ASN.

---

## 4. New CVEs / exploit signatures observed

- **Requested — LinkFlow / CVE-2026-5027: NOT PRESENT.** Full-text and raw path/body/URL searches over ~75 days returned nothing. (If it targets an endpoint whose URI doesn't contain "linkflow", it could be sitting unlabeled — provide the path/param signature and we'll re-sweep.)
- **Only numeric-CVE tag in the data:** `CVE-2026-24061` (telnet `USER -f root` arg-injection) — 70 hits, low-and-slow, rotating sources; ongoing from June.
- **CVE-relevant *signatures* seen (by rule name):** Log4Shell/JNDI = **CVE-2021-44228** (Aug 24 only), SSTI, Cloud-Metadata SSRF (IMDS theft), WordPress GravitySMTP probe (366), Hikvision **CVE-2021-36260** (1,027), RedTail **CVE-2024-4577** (578), PHPUnit **CVE-2017-9841** (decoy, 4,924).
- **Takeaway on "newer CVEs":** attackers here are not leading with fresh 2026 CVEs — the volume is old, reliable, high-yield bugs (Log4Shell, traversal, IMDS SSRF) plus commodity credential harvesting. The newest thing observed is the telnet CVE-2026-24061, still marginal.

---

## 5. Geography (⚠️ skewed by the Aug 24 host)

Bulgaria (1.52M) — **almost entirely `194.180.49.37`**; strip that and the real leaders are US (486K), Netherlands (414K), UK (243K), Vietnam (154K), France (147K), Indonesia (134K), Brazil (123K), India (96K). Infrastructure remains cheap/bulletproof VPS (MEVSPACE, Pfcloud, Bullet Group, DigitalOcean).

---

## 6. SSH / Cowrie highlights

- **Top credential-stuffer:** `176.53.159.196` — **1,127 successful logins** (dominant brute source).
- **Persistent brute infra:** `91.92.40.x`, `193.32.162.x`, `195.178.110.x`.
- **Malware loaders pulled post-login** (carryover + new):
  - **new:** `213.232.114.14/handshakebins.sh`; `103.77.246.150:8081/run.sh`
  - **continuing:** "iran" (`165.22.69.214/iran.{x86_64,aarch64,m68k,mips,mipsel}`), Exodus (`176.65.139.228:6677`), `83.168.69.141/armv7l`
- **RedTail** still active via HTTP client (1,262) and its scp/SSH-key delivery (see August MTD notes).

---

## 7. WAF status — upgrades confirmed live ✅

The redeploy landed. Now firing in production:
- **Decoy-Config/Secret Harvest** — 4,777 canaried `.env` serves (the `185.177.72/24` secret-harvest actor is now eating fake creds). *Reminder: refresh the canary tokens as planned.*
- **App Config & Secret File Disclosure** rule — 983.
- **Decoy-PHPInfo** — 1,014 (broadened matcher working across prefixes).
- New coverage also live: Log4Shell/JNDI, SSTI, LFI/RFI PHP stream-wrapper, IMDS SSRF, GravitySMTP.

**Still open (minor):** GravitySMTP rule misses the `?rest_route=/gravitysmtp/...` permalink-off form (and the same evasion applies to other `/wp-json/*` rules). Tightening proposed previously; not yet applied.

---

## 8. IOC appendix (August)

**Mass web exploitation**
- `194.180.49.37` (MEVSPACE) — 1.32M-req single-day multi-exploit blast; IMDS-cred focus → **recommend drop + abuse report**

**Malware distribution**
- `213.232.114.14` (handshakebins.sh) · `103.77.246.150(:8081)` · `165.22.69.214` (iran) · `176.65.139.228:6677` (Exodus) · `83.168.69.141`

**SSH brute**
- `176.53.159.196` (1,127 successful logins) · `91.92.40.x` · `193.32.162.x` · `195.178.110.x`

**Persistent web actor**
- `185.177.72.0/24` (secret-harvest; now engaging the config-secrets decoy) · `130.12.180.77`

**CVE/exploit signatures**
- CVE-2021-44228 (Log4Shell) · CVE-2021-36260 (Hikvision) · CVE-2024-4577 (RedTail) · CVE-2017-9841 (PHPUnit) · CVE-2026-24061 (telnet) · GravitySMTP · IMDS SSRF · SSTI

---

## 9. Recommendations

1. **Drop `194.180.49.37` / rate-limit the MEVSPACE ASN**, and file an abuse report — one host produced half the month's traffic.
2. **Refresh the canary tokens** in the config-secrets decoy (planned) — it's actively being harvested, so live canarytokens would start yielding phone-home attribution.
3. **Apply the GravitySMTP `?rest_route=` hardening** across `/wp-json/*` rules.
4. **Watch September closely** — daily volume is already 2–5× August baseline; the next report should lead with it.
5. **LinkFlow/CVE-2026-5027:** if you have the endpoint/param signature, send it and we'll sweep the untagged bucket and add a rule if it's landing here.
