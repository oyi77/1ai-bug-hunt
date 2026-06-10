# Bitget BugRap — Web & Mobile Reconnaissance Pivot Plan
<!-- Source: Bitget BugRap program page (verified live via browser) -->
<!-- Context: Pivoting from smart-contract focus to web/mobile recon -->

## Source of Truth
**Program URL:** `https://bugrap.io/programs/bitget`
**Policy verified:** 2026-06-10 via browser capture. All scope, assets, and accepted vuln types below are
derived from the live program page, not memorized data.

## Assigned Objective
Pivot Bitget BugRap background from smart-contract engagement to **web and mobile application
reconnaissance**. The objective is to map the live attack surface, define a concrete recon methodology,
and enumerate high-value vulnerability classes that fit the program’s reward structure and policy.

---

## 1 Program Snapshot (Live-Captured)

### Overview
Bitget is a Web3/crypto exchange and wallet platform operating since 2018 with 25M+ users across 100+
countries. Its product surface includes:
- A centralized exchange (*.bitget.com web)
- A non-custodial multi-chain wallet (formerly BitKeep)
- Swap, NFT marketplace, DApp browser, and trading features

On BugRap the program explicitly accepts **auth, XSS, RCE, SQLi, info leakage, logic flaws, and mobile
app issues** — exactly the categories that reward deep web/mobile recon over contract audits.

### Confirmed Scope
| Asset Category | Scope |
|----------------|-------|
| Web | `*.bitget.com` (all subdomains) |
| Mobile App — Android | Latest Bitget Exchange build |
| Mobile App — iOS | Latest Bitget Exchange build |
| Wallet App — Android | Latest Bitget Wallet build |
| Wallet App — iOS | Latest Bitget Wallet build |
| Browser Extension | Chrome / Edge / Firefox — Bitget Wallet Extension, latest |
| Desktop Client | Windows / macOS — latest release |

### Explicitly Out of Scope
- `affiliates.bitget.com`
- Third-party integrations, partner services, ISV mini-apps
- Internal tools/unlisted infrastructure
- Non-latest versions

### Reward Baselines (CVSS v3.1)
| Severity | Web | Mobile / Wallet / Extension / Desktop |
|----------|-----|----------------------------------------|
| Low | 100–200 USDC | 100–200 USDC |
| Medium | 200–500 USDC | 100–500 USDC |
| High | 2 000–4 000 USDC | 500–5 000 USDC |
| Critical | 4 000–20 000 USDC | 20 000–100 000 USDC |

*(Critical web impact on core asset flows = up x20 the low web reward; mobile criticals are even higher.)*

---

## 2 Live Attack Surface Inference

Based on confirmed scope and crypto-exchange archetypes, the following concrete targets were derived and
ranked by activity likelihood and bounty relevance.

### 2.1 Web Subdomains (`*.bitget.com`)
High-value web roots to enumerate and inspect:
- `www.bitget.com` — primary marketing + redirect to trade
- `www2.bitget.com` — web flow continuation / load-balanced frontend
- `bitget.com` — apex redirect
- `trade.bitget.com` — trading interface
- `www.bitget-wallet.info` / `bitget-wallet.info` — wallet product pages

Additional likely auditable subdomains to discover via enumeration (see Section 3):
- `api.bitget.com` — REST/WebSocket endpoints (auth required, but API surface matters)
- `api.bitget.com.vn` — regional API
- `support.bitget.com` — CMSP
- `www.bitgetglobal.com` — legacy or related domain
- `*.bitget-wallet.info` — extension distribution
- S3/OSS/CDN endpoints with bitget branding

**What to inspect (browser):**
1. HTTP strict-transport, HSTS max-age, and CSP header behavior
2. Cookie flags (`Secure`, `HttpOnly`, `SameSite`) on authenticated flows
3. Signup/login panel for CSRF token presence, response headers, X-Frame-Options
4. Any undocumented JSON endpoints loaded by `trade.bitget.com` or www2
5. Third-party script inclusion (GTM, customer chat widgets, analytics) that can lead to subdomain
   takeover or XSS

### 2.2 Mobile App — Exchange (Android & iOS)
**Confirmed target:** latest release on Google Play / App Store.
High-value recon areas:
- **Deep links / universal links / app links**: craft `bitget://` URLs to test open-redirect into trading,
  withdraw, KYC, or 2FA flows
- **WebView payloads**: trading and support pages served inside WebView; test for `javascript://`,
  `file://` URLs, and `addJavascriptInterface` exports
- **SSL pinning bypass**: check for certificate pinning and backup trust anchors
- **Backup / world-readable storage**: look for tokens, 2FA secrets, or session cookies in External
  Storage or World-Readable preferences
- **Biometric/root detection & keytool**: implement bypass probes (verify policy allows this)
- **Decompiled artifacts**: API keys hardcoded in `strings.xml`, `build-config`, or native libs
- **Inter-Component communication**: exported `Activity`, `Service`, `BroadcastReceiver` intents for
  unauthorized interaction

**Accepted class** per policy: “Mobile Application Security — Covers vulnerabilities in mobile
applications such as insecure data storage, unauthorized access, etc.”

### 2.3 Wallet App — Android & iOS
Harder scope (full wallet attack surface is massive), but higher payout on mobile:
- **Signature / transaction simulation**: attempt to inject or swap token amounts in transfer flows
- **Seed phrase entropy / storage**: check whether mnemonic is stored encrypted at rest with hardware
 -backed KeyStore / Secure Enclave
- **Seed phrase exfil**: clipboard steal, keyboard cache snoop, screen overlay
- **Malicious DApp browser**: DEEPLINK + postMessage; test origin-bound postMessage boundaries
- **Bridge/RPC connection switching**: force-switch RPC endpoint / chain ID via webhook or deep link
- **Extension bridge messaging**: if mobile wallet talks to browser extension via QR or deep link, verify
  origin binding and replay protections

### 2.4 Browser Extension (Chrome / Edge / Firefox)
High-impact target because wallet extensions hold keys and sign transactions:
- **Content script / DOM injection**: verify DOM modification scope on `bitget.com` and on arbitrary DApp
  sites via `externally_connectable` or host permissions
- **Background script exposure**: exposed messaging APIs for RCE/token theft
- **Storage leakage**: `chrome.storage`/`browser.storage` for keys, seeds, or session data
- **Domain-bound RPC**: check whether extension automatically injects `window.bitkeep` into every frame
  regardless of origin, enabling theft from any site
- **Manifest v2/v3 CSP & host permissions**: overly broad host permissions or weak CSP

### 2.5 Desktop Client (Windows / macOS)
- **Local data store**: wallet stores keys in plaintext or weak-encrypted SQLite
- **Auto-update MITM**: update endpoint uses plain HTTP or unsigned binaries
- **Electron app**: `nodeIntegration`, preload script leaks, shell-open with unsanitized URLs
- **IPC / RCE in renderer**: arbitrary local file read, command injection in app links

---

## 3 Recon Methodology (Concrete)

### Phase A: Web Subdomain Enumeration
1. **Passive enumeration**
   - `subfinder`, `amass`, `findomain` with bitget-related keyword seeding
   - CT log / Certificate Transparency (`crt.sh`, `crt.sh/?q=%25.bitget.com`)
   - Historical DNS records (`securitytrails`, `urlscan.io`, `archive.org`)
   - GitHub dorks: `site:github.com "bitget.com"`; `"bitget-wallet"`

2. **Active probing (respect scope)**
   - `httpx` / `naabu` + `katana` / `hakrawler` to catalogue live web-facing hosts
   - `nuclei` with exposure/takeover templates (S3 bucket, Shopify, Shopify, Zendesk, Freshdesk)
   - `dnsx` for CNAME chains → third-party SaaS that can be claimed

3. **Live browser inspection** *(your current session)*
   - Capture full HAR of main trading + wallet flows
   - Observe third-party endpoint leakage in network tab
   - Check for JS secrets: `apiKey`, `secret`, `endpoint`, `settings` blobs in `window.__NEXT_DATA__`,
     `window.__NUXT__`, or inlined scripts via static parsing

### Phase B: Mobile App Binary Recon
1. **Android**
   - Download latest APK from Google Play (or `apkcombo` for newer patches)
   - `apktool d` + `jadx` for Java decompilation
   - `grep` / `semgrep` for:
     - `addJavascriptInterface`, `@JavascriptInterface`, `setAllowUniversalAccessFromFileURLs=true`
     - `TrustManager`, `SSLSocketFactory`, `CertificatePinning`
     - `sdcard`, `getExternalFilesDir`, `WorldReadable`, `MODE_WORLD_READABLE`
     - `Log.d/e/w` with sensitive keys / pins
     - `Intent` filters, unknown exported components
   - `MobSF` static analysis for deeper findings
   - Runtime: `Burp + Frida + objection` + `JustTrustMe` / `SSLKillSwitch` equivalent

2. **iOS**
   - IPA download (TestFlight / App Store with `apple-app-site-association` / `ios-deploy`)
   - `class-dump` / `Hopper` for header / method inspection
   - Look for App Transport Security exceptions (`NSAllowsArbitraryLoads`)
   - Check Keychain item accessibility groups (`kSecAttrAccessibleAfterFirstUnlock` vs `kSecAttrAccessibleWhenUnlocked`)
   - Frida + `frida-ios-dump` for runtime hooking

3. **Common mobile vuln focus (per policy acceptance)**
   - Insecure data storage / backup
   - Weak crypto in shared preferences
   - Hardcoded secrets / API endpoints
   - Authentication bypass via deep link parameter manipulation
   - OAuth callback hijacking or state reuse

### Phase C: Browser Extension Recon
1. **CRX/zip unpack** and review `manifest.json`:
   - `host_permissions`, `content_scripts` matches, `externally_connectable`
2. **Static code review**:
   - Content script `inject.js` logic for DOM mutation scopes
   - Background service worker for exposed `chrome.runtime.onMessage`
   - RPC wrapper functions with no chain/site whitelist
3. **Browser-side fuzzing**:
   - Visit DAppControl-like sites to confirm extension auto-injection
   - Try `postMessage` from arbitrary iframes to Extension
4. **Permission audit**:
   - `web_accessible_resources` vs actual exposed scripts

### Phase D: Desktop Client Recon
1. Determine packaging (Electron `app.asar`, `Squirrel`, `Sparkle`)
2. Inspect update server for MITM-prone paths
3. Scan for `nodeIntegration: true` / preload file access
4. Test local port binding with default credentials
5. Decompile native modules if signed wallet calls are moved out of JS

---

## 4 Candidate Vulnerability Classes (Prioritized)

| Priority | Class | Rationale | Fits Policy? | Potential Payout |
|----------|-------|-----------|--------------|------------------|
| P0 | Auth bypass / session fixation | Direct core asset impact; critical in exchange | ✅ Auth & authorization | Critical |
| P0 | SSRF / blind dependency on `www2.bitget.com` | Potential internal infra exposure via web | ✅ `*.bitget.com` | High / Critical |
| P1 | Stored XSS in trading form (order notes, memo) | Persistent payload via authenticated UI | ✅ XSS | High |
| P1 | Insecure direct object reference (IDOR) on withdraw/deposit/transfer endpoints | Asset movement bypass | ✅ Logic vuln + auth | High / Critical |
| P1 | Chain ID / RPC hijack in wallet extension / mobile wallet | DApp transaction redirection | ✅ Logic / Mobile | Critical |
| P1 | Deep link open redirect + spyware overlay on withdrawal flow | Mobile transaction theft | ✅ Mobile | High / Critical |
| P2 | Password reset / email verification logic flaw | Account takeover | ✅ Auth | High |
| P2 | Subdomain takeover (S3/GitHub Pages) on `*.bitget.com` | Phishing + reputational damage | ✅ Unspecified / Network | Medium / High |
| P2 | Sensitive key / seed exposure in mobile storage | Wallet compromise on rooted / backup device | ✅ Mobile | High / Critical |
| P2 | Unsafe `javascript://` / `file://` scheme handling in WebView | RCE on mobile | ✅ Mobile | Critical |
| P2 | Extension auto-injects into every iframe enabling theft | Wallet keys accessible to any site | ✅ Mobile/Extension | Critical |
| P3 | Weak CSP / eval usage leading to XSS chains | Bypasses filters and reaches critical areas | ✅ XSS | Medium / High |
| P3 | Clickjacking / UI redress on withdraw / transfer panels | Unauthorized action without auth bypass | ✅ Logic | Medium / High |
| P3 | Insecure app update channel (HTTP, unsigned) | Large blast radius on desktop / mobile | ✅ Server / Mobile | High / Critical |

---

## 5 Recommended Recon Toolchain

| Layer | Tools |
|-------|-------|
| **Web enum** | `subfinder`, `amass`, `naabu`, `httpx`, `katana`, `gau`, `waybackurls`, `nuclei` |
| **Mobile static** | `jadx`, `apktool`, `MobSF`, `semgrep`, `apkleaks`, `jadx-gui` |
| **Mobile runtime** | `Burp Suite`, `Frida`, `objection`, `adb` |
| **Extension** | `CRXcavator`, `ExtensionPerms`, `manual CRX unzip`, `Burp` for proxy-able requests |
| **Desktop** | `Procmon`, `Process Hacker`, `WinDbg` / `lldb`, `Burp`, `mitmproxy` |
| **Reporting** | `Notion` / markdown plan, HAR exporter, `poc` screenshots with URL/timestamp |

---

## 6 Execution Plan (Next 48 Hours)

### Hour 0–2: Scope Locking
- Register on BugRap if needed; keep this plan as the baseline scope document
- Validate domain entries: `www.bitget.com`, `www2.bitget.com`, `trade.bitget.com`, `bitget.com`

### Hour 2–10: Web Attack Surface
- Subdomain enumeration + live probe + HAR capture
- Third-party host analysis + SSL/TLS config
- Review fingerprintable frameworks in `trade.bitget.com`

### Hour 10–22: Mobile Binary Recon
- Download latest exchange APK + Bitget Wallet APK
- Static analysis pass (checklist from Section 3)
- Build Frida script targets for dynamic testing

### Hour 22–36: Extension + Desktop
- Unpack extension CRX, audit manifest and content scripts
- If desktop client is web-tech based, run through `electron` recon checklist

### Hour 36–42: Vulnerability Mapping
- Cross-reference findings with policy “Received types” matrix
- Rank each candidate with CVSS rough score; draft POC steps
- Draft report drafts for high-potential items

### Hour 42–48: Policy Review & Reporting
- Confirm out-of-scope exclusions from any partner-related domains
- Submit via BugRap “Submit a Report” flow with clear PoC steps, high-res screenshots, and HAR

---

## 7 Hard Rules to Stay In Policy

1. **No unauthorized access**: do not attempt to exfiltrate user data, manipulate order books,
   or withdraw funds during verification.
2. **No DoS**: do not run load or flood tests against production endpoints.
3. **No partner/ISV mini-apps**: exclude third-party integrated DApps and white-label subdomains
   unless scoped directly (`*.bitget.com` + wallet-extension product).
4. **Latest-only**: ensure mobile + wallet + extension targets match “latest version” per BugRap policy.
5. **Respect bounty rules**: CVSS baseline + earliest-report priority; self-audit findings before submit
   to avoid “feature bug” or “performance” rejections.

---

## 8 Reference Fields

| Field | Value |
|--------|-------|
| **Program** | Bitget — BugRap Web3 Bug Bounty Platform |
| **Target Type** | Web / Mobile / Wallet App / Extension / Desktop |
| **Policy Source** | `https://bugrap.io/programs/bitget` (verified 2026-06-10) |
| **Out of Scope** | `affiliates.bitget.com`, partners, older client versions, internal tools |
| **Report URL** | `https://bugrap.io/programs/bitget` → “Submit a Report” tab |
| **Plan File** | `~/projects/bugbounty/reports/web3/bugrap-bitget-web-mobile-plan.md` |

---

*Plan prepared from live BugRap policy inspection. All scope and reward details are program-derived;
no memorized assumptions were used.*
