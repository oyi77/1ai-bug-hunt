# Safeheron Day 1 Recon — Attack Surface Report

**Scope:** BugRap (Day 1) — Repo-level reconnaissance only. No secrets logged.
**Target domain:** *.safeheron.com
**Core attack perimeter:** TEE/MPC subsystem

---

## 1. Repo Inventory

All repos cloned into `/home/openclaw/repos/safeheron/`.

| Repo | Language | Path |
|------|----------|------|
| multi-party-sig-cpp | C++ | `multi-party-sig-cpp/` |
| ssgx | C++ / SGX | `ssgx/` |
| safeheron-crypto-suites-cpp | C++ | `safeheron-crypto-suites-cpp/` |
| mpc-wasm-sdk | TypeScript / WASM | `mpc-wasm-sdk/` |
| mpc-snap-wasm | C++ / WASM (build) | `mpc-snap-wasm/` |
| multi-mpc-snap-monorepo | TypeScript / Snap | `multi-mpc-snap-monorepo/` |
| safeheron-api-sdk-js | TypeScript | `safeheron-api-sdk-js/` |
| safeheron-api-sdk-python | Python | `safeheron-api-sdk-python/` |
| safeheron-api-sdk-go | Go | `safeheron-api-sdk-go/` |
| safeheron-api-sdk-java | Java/Maven | `safeheron-api-sdk-java/` |
| hardhat-safeheron | TypeScript | `hardhat-safeheron/` |
| truffle-safeheron | JavaScript | `truffle-safeheron/` |

---

## 2. Repo-by-Repo Attack Surface

### 2.1 multi-party-sig-cpp
- **Language:** C++ (protobuf, OpenSSL, GoogleTest)
- **Purpose:** Core MPC library implementing {t,n}-threshold ECDSA (GG18, GG20, CMP, Lindell17). Produces key shards, key refresh, and threshold signatures. Built for Intel SGX enclave deployment.
- **Attack Surface (HIGH — core MPC engine):**
  - **ECALL/OCALL enclave boundary:** SGX builds use `ssgx_add_trusted_library` — all ECALL entry points validate input buffers and lengths; untrusted OCALLs to host filesystem, config, and HTTP piped through EDL.
  - **Key shard transport:** MPC round messages serialized via protobuf. Round-state corruption or re-ordering can bias signature or leak shares.
  - **Attestation flow:** Relies on `ssgx` -> `ssgx_attestation_t` remote attestation; enclave quote validation is host-pinned — spoofed IAS/PCCS responses break integrity.
  - **Sealed storage:** Key shares sealed to MRENCLAVE identity — sealed blob theft is recoverable only if same enclave build is recreated (anti-rollback not visible in this repo).
  - **Crypto primitive backends:** Paillier and zero-knowledge protocols implemented over big-number math — nonce reuse, range-check bypass, or bad randomness are likely break points.

---

### 2.2 ssgx
- **Language:** C++ (Intel SGX SDK, mbedtls-SGX, Poco, protobuf, nlohmann/json)
- **Purpose:** Safeheron's native SGX TEE framework. CMake build system, OOP wrappers for SGX APIs, remote attestation, secure sealing, HTTP client/server inside enclave, filesystem OCALLs, logging, TOML/JSON parsing.
- **Attack Surface (HIGH — TEE foundation):**
  - **Enclave <-> Host (ECALL/OCALL):** EDL files in `common/include/` define all trusted/untrusted transitions. Examples of interest:
    - `ssgx_filesystem_t.edl` — path traversal via host OCALLs (`get_file_status`, `get_symlink_file_status`).
    - `ssgx_http_t.edl` — HTTP server & client running inside enclave (network edge in TEE).
    - `ssgx_config_t.edl` — TOML parsing from untrusted host path; config poisoning possible if host serves crafted file.
    - `ssgx_log_t.edl` — untrusted logging can leak enclave metadata/trace IDs.
  - **Remote attestation:** `ssgx_attestation_t` wraps Intel DCAP/EPID; misleading quote payloads accepted by custom code are a crypto-attack vector.
  - **Sealing:** MRENCLAVE vs MRSIGNER sealing modes; sealed file corruption or rollback to older enclave build.
  - **Sample `millionaire_problem`:** Shows `ocall_verify_quote_untrusted` pattern — this is where host-side quote verification bugs hide.

---

### 2.3 safeheron-crypto-suites-cpp
- **Language:** C++ (OpenSSL, protobuf, GoogleTest)
- **Purpose:** Foundational crypto library: big-integer, curves (Secp256k1, P256, Ed25519, STARK), AES-GCM, commitment, Paillier, secret sharing, BIP32/39, ECIES, ZKPs. Cross-platform (Linux/macOS/Android/iOS/SGX/WASM).
- **Attack Surface (HIGH — shared crypto primitive layer):**
  - **ECIES:** Authenticated key-wrap used for key shard transport between parties and across MPC rounds — failures here break confidentiality of key shards in transit.
  - **AES-GCM:** Used for sealed storage / envelope encryption. Nonce reuse or tag bypass decrypts key material.
  - **Secret sharing:** `crypto-sss` — Shamir threshold implementation. Corruption of shares during refresh protocol or biased randomness.
  - **Paillier:** Homomorphic encryption used in GG18/GG20/CMP. Incorrect padding or plaintext ciphertext blinding leads to key recovery.
  - **Randomness/entropy:** Any uninitialized RNG state in enclave sanitized paths has outsized TEE impact.

---

### 2.4 mpc-wasm-sdk
- **Language:** TypeScript + C++ WASM (Emscripten)
- **Purpose:** Browser/WebView WASM SDK implementing 2/3 MPC CMP protocol. Provides `KeyGen`, `KeyRefresh`, `KeyRecovery`, `Signer`. Browser-side key shard is kept in JS memory / WebWorker.
- **Attack Surface (HIGH — browser enclave analog):**
  - **Key shard transport inside browser:** `KeyRefresh` / `Signer` round messages encrypted by `MPCHelper` (ECIES-style) before WebSocket/WebRTC transport. MITM or worker memory read leaks shard.
  - **WebWorker boundary:** `MPCWorkerClient.ts` posts messages across Worker thread — postMessage prototype pollution or structured-clone attacks can leak sign-key material.
  - **WASM linear memory:** Signing key material persists in WASM heap — XSS reading `window` references to WASM instance exfiltrates key.
  - **api.safeheron.vip linkage:** WASM SDK connects to Safeheron backend for Co-Signer orchestration; URL/replay attacks on webhook callbacks.
  - **fallback localStorage / IndexedDB usage (likely):** persistent shard caching creates disk-resident key material.

---

### 2.5 mpc-snap-wasm
- **Language:** C++ -> WASM (Emscripten build pipeline)
- **Purpose:** WASM build recipe for deeper C++ MPC stacks (OpenSSL, protobuf, crypto-suites, multi-party-sig → WASM). Produces a single deterministic WASM artifact consumed by the above SDK.
- **Attack Surface:**
  - **Supply chain / build container:** `scripts/build-docker-image/` Dockerfile is built-OR-transitive — compromise yields poisoned WASM containing backdoored crypto or shard leaks.
  - **WASM output bounds checking:** Post-Emscripten linear memory sanitization is done by hand in build scripts; missing checks → OOB read/write of key shard memory.

---

### 2.6 multi-mpc-snap-monorepo
- **Language:** TypeScript / JavaScript (Yarn workspaces: `snap`, `types`, `example`)
- **Purpose:** MetaMask Snap plugin for MPC wallets. Distributes key shards across MetaMask extension + two mobile Safeheron Snap apps. 2-of-3 signing via MetaMask Snaps.
- **Attack Surface (HIGH — extension/app surface):**
  - **MetaMask Snap <-> Host RPC:** The Snap bridge is the enclave/host analog. `snap` package communicates via MetaMask's `snap_dialog` / `snap_manageState`. Malformed RPC or request ID confusion triggers unauthorized signing.
  - **Key shard transport:** Shards propagated over `@safeheron/mpcsnap-types` messages; encryption relies on JS crypto layer layered on top of same CMP WASM — reuse of IV/nonce across chains plausible.
  - **State persistence:** MetaMask Snap state (`snap_manageState`) persisted encrypted on-disk — state rollback or tampering alters key shares.
  - **API auth / callbacks:** Receives Co-Signer approval callbacks from `*.safeheron.com`; webhook auth via `apiKey` + RSA blind signing — replay or substitution attack on callback parameter.
  - **Extension-side XSS/ZIP-slips:** Since it's a browser extension, any injection in UI (dApp-facing `handleRequest`) yields signing rights.

---

### 2.7 safeheron-api-sdk-js
- **Language:** TypeScript
- **Purpose:** Client SDK for `api.safeheron.vip` REST API used by integrations. Signs payloads with user's RSA key; triggers Co-Signer (TEE-backed) approval flow.
- **Attack Surface:**
  - **RSA private key handling:** README explicitly shows `rsaPrivateKey: "file:/path"` or inline PEM — inline PEM via `.env` leaks to git history. Read path traversal if `file:` is not validated by SDK.
  - **api.safeheron.vip auth:** `apiKey` + RSA signature on every request. Replay protection is timestamp-only; clock skew or network delay weakens replay window.
  - **Callback URI:** Co-Signer approval is returned to a developer-controlled HTTP endpoint; callback signature verification must be enforced client-side — bypass yields unauthorized tx.

---

### 2.8 safeheron-api-sdk-python
- **Language:** Python 3
- **Purpose:** Same REST API client for Python integrators (account creation, transaction signing, key management).
- **Attack Surface:**
  - **Private key config:** `config.yaml` stores base64 RSA private key or file path; same repo has `config.yaml.example` with placeholder keys — risk of developers committing real keys. YAML parsing deserialization attack surface if untrusted config supported.
  - **Requests library SSL verification:** Default `requests` session depends on CA bundle; pinned Safeheron public key must be enforced manually.

---

### 2.9 safeheron-api-sdk-go
- **Language:** Go (modules)
- **Purpose:** Go bindings for the same Safeheron API surface.
- **Attack Surface:**
  - **In-memory key usage:** `RsaPrivateKey: "pems/my_private.pem"` path handling; Go file reading relative to CWD is susceptible to symlink/directory traversal.
  - **TLS/Session pinning:** Not visible in README — if SDK doesn't verify Safeheron's HTTPS cert pin, MITM downgrades API calls.

---

### 2.10 safeheron-api-sdk-java
- **Language:** Java (Maven)
- **Purpose:** Java client SDK for Safeheron API.
- **Attack Surface:**
  - **YAML config for secrets:** Same `config.yaml` pattern; YAML deserialization classes in Java ecosystem (SnakeYAML) can instantiate arbitrary objects when parsing attacker-controlled config.
  - **Keystore integration:** Expected Java users will load RSA keys into JKS/PKCS12 — keystore password brute force or memory dump attacks.

---

### 2.11 hardhat-safeheron
- **Language:** TypeScript (Hardhat plugin)
- **Purpose:** Hardhat plugin to deploy contracts and sign transactions via Safeheron MPC wallet.
- **Attack Surface:**
  - **Secret management in `hardhat.config.ts`:** README shows `web3WalletAccountKey` and `web3WalletEVMAddress` in env; if `.env` is committed, attacker gains Web3 wallet control. This is the highest-frequency bug in their own README warning.
  - **RSA key loading:** `file:` prefix path should be outside the working tree, but Hardhat task resolution is relative — symlink/`../` escape possible.
  - **Network callbacks:** `skipDryRun: true` required for sepolia indicates signed transactions go directly on-chain; any Co-Signer callback manipulation drops misconfigured txs.
  - **Subscription `web3WalletEVMAddress` / `web3WalletAccountKey`:** Two-factor chain control — either alone lets attacker redirect wallet routing.

---

### 2.12 truffle-safeheron
- **Language:** JavaScript (Truffle plugin)
- **Purpose:** Truffle plugin equivalent of `hardhat-safeheron`. Same attack surface mirrored for the Truffle ecosystem.
- **Attack Surface:**
  - Mirror of Hardhat: RSA key path, `.env` leakage, callback URI, `skipDryRun`.

---

## 3. Cross-Cutting Attack Surfaces (priority order)

### 3.1 TEE / Enclave Boundary (CRITICAL)
- `ssgx` defines the OCALL surface in EDL files. Every OCALL to host is an infiltration path:
  - Filesystem: files written by host can poison enclave config or sealed storage.
  - HTTP: enclave-initiated HTTPS has no proxy pin — MITM on PCCS or IAS feeds a fake quote.
  - Log: secret material (nonce, partial signature) can leak via `ssgx_ocall_write_log`.
- Remote attestation: upstream IAS/PCCS compromise collapses trust in any TEE-backed MPC node.

### 3.2 Key Shard Transport (CRITICAL)
- `multi-party-sig-cpp` + `safeheron-crypto-suites-cpp` (Paillier, ECIES, AES-GCM) handle shard encryption across the wire.
- Symmetric state between parties must be nonce-unique. Any protobuf message replay carries old-state attack potential.

### 3.3 API Auth / Callback (HIGH)
- `safeheron-api-sdk-*` clients authenticate with `apiKey` + RSA. The RSA private key is the weakest link because SDK examples encourage on-disk `/path/file.pem` or inline strings.
- Co-Signer approval callback (developer-run HTTP endpoint) trusts a signature layer on top of webhook parameters — replay or parameter substitution wins.

### 3.4 Enclave <-> Host Interface (HIGH)
- OCALL handlers in `ssgx` that dereference untrusted pointers — a malicious host can craft memory layout to escalate trust or leak enclave buffers.
- `ssgx_filesystem_t` path input not visibly canonicalized — `../sealed/` traversal can read/write enclave seals.

### 3.5 Browser/Snap Extension Surface (HIGH)
- MetaMask Snap extension (`multi-mpc-snap-monorepo`) runs in a privileged, but attacker-influenced, host. Any XSS/compromise of dApp web page or Snap extension DOM reaches signing keys.
- `mpc-wasm-sdk` thread boundary leaks via structured clone of `ArrayBuffer` holding key material.

### 3.6 Build / Supply Chain (MEDIUM)
- `mpc-snap-wasm` Docker build不用说 — compromise the build image, inject backdoored WASM.
- `safeheron-crypto-suites-cpp` builds for SGX depend on custom OpenSSL fork (`Safeheron/openssl` tree at `stark_curve`) — other curves use it too; earlier audit coverage is partial.

---

## 4. Likely Code Hotspots for Weaponization Follow-Up

| File/Area | Repo | Why |
|-----------|------|-----|
| `ssgx/common/include/*.edl` | ssgx | EDL = source of truth for TEE surface; every OCALL is an attack angle. |
| `ssgx/sample/millionaire_problem/host/host.cpp` | ssgx | Working `ocall_verify_quote_untrusted` caller — live attestation validation logic. |
| `multi-party-sig-cpp/proto/*.proto` | multi-party-sig-cpp | MPC message schema; fields carrying nonce / partial sig / shard are targets for replay. |
| `safeheron-crypto-suites-cpp/src/crypto-sss/` | crypto-suites | Secret-sharing decode/encode boundaries. |
| `safeheron-crypto-suites-cpp/src/crypto-ecies/` | crypto-suites | Key-shard encrypt/decrypt across the wire. |
| `mpc-wasm-sdk/src/co-signer/MPCHelper.ts` | mpc-wasm-sdk | Encryption helpers for round messages. |
| `multi-mpc-snap-monorepo/packages/snap/src/` | monorepo | Ext-Snap RPC boundary. |
| `safeheron-api-sdk-js/src/config.ts` | js sdk | RSA key handling implementation. |

---

## 5. Notes & Constraints

- **No secrets inspected.** Env samples, `.yaml.example`, README code snippets, and `hardhat-safeheron/example/` configs were read solely for auth-flow pattern recognition.
- This is **weaponry-only** recon: scope is attack surface, not extraction. Actual secret/file access requires explicit instruction.
- BugRap scope overrides: day-1 focus is backend TEE/MPC stack; frontend Chrome extension and mobile apps are noted but secondary until TEE primitives are mapped.
