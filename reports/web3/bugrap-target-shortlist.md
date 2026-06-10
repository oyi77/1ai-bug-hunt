# BugRap Web3 Target Shortlist + Attack Plan
Generated: June 10, 2026  
Source: `discovery/bugrap_programs_web3_audit.md`  

## Priority Matrix

### Tier 1 — Execute Now
| Rank | Program | Ceiling | Why |
|------|---------|---------|-----|
| 1 | MerlinChain | **$200K** | SC + bridge + L2 node + zkEVM prover; code public; Day 1 triage already done |
| 2 | Safeheron | **$100K** | Core scope = TEE + MPC nodes + self-custody assets; high bounty per point |
| 3 | Morph Network | **$100K** | Explicit SC examples: unauthorized mint, freeze, oracle, replay; public repos |

### Tier 2 — Next Rotation
| Rank | Program | Ceiling | Why |
|------|---------|---------|-----|
| 4 | Cregis | **$100K** | MPC/TEE custody + smart contract explicitly in-scope |
| 5 | Bitget Wallet | **$50K app/ext** | Wallet signing + cross-chain bridge; requires mobile + extension recon |
| 6 | Tokenlon | **$50K/contract** | 18 contract addresses on-chain; pure DEX; easier to scan with automated tools |

### Tier 3 — Lower Priority
| Rank | Program | Ceiling | Why |
|------|---------|---------|-----|
| 7 | PlatON | TBD | ATON Wallet + PlaTrust JS SDK; lower competition data |
| 8 | DeSyn | TBD | On-chain asset management; smaller report count |
| 9 | Mask | TBD | Partial SC scope; lower clarity |
| 10 | Bitget (web/mobile) | $1M discretionary | High ceiling but very generic web/mobile; massive noise; switch only if SC targets exhaust |

---

## Attack Plans

### 1. MerlinChain — $200K (Days 1–7)
- **Status:** Day 1 done, Slither now running
- **Day 2:** Manual deep-dive on contract-size breached contracts and unchecked `call` returns in bridge permit
- **Day 3:** Storage-collision audit in proxy/upgrade paths
- **Day 4:** zkEVM prover source review for unsound verification logic
- **Day 5:** Write PoC skeleton, model fund-loss scenarios
- **Day 6:** Counter-dupe check on H1/Immunefi
- **Day 7:** Submit BugRap report

### 2. Safeheron — $100K (Days 1–7)
- **Day 1:** Clone TEE/MPC GitHub repos; map architecture
- **Day 2:** Review MPC key-shard signing protocol for threshold misuse or replay
- **Day 3:** Audit TEE attestation flow into enclave boundary for downgrade/forwarding
- **Day 4:** Chrome extension + mobile app static recon
- **Day 5:** Write PoC skeleton, model key-leak or freeze scenarios
- **Day 6:** Counter-dupe check
- **Day 7:** Submit BugRap report

### 3. Morph Network — $100K (Days 1–7)
- **Day 1:** Clone `morph-l2/morph`, `go-ethereum`, `tendermint`; enumerate SC surface
- **Day 2:** Review mint/burn mechanics for bridge tokens (USDT, BGB)
- **Day 3:** Oracle price-manipulation path analysis
- **Day 4:** Cross-chain replay attack surface review
- **Day 5:** Write PoC skeleton, model consensus/state-freeze scenarios
- **Day 6:** Counter-dupe check
- **Day 7:** Submit BugRap report

---

## Decision Gate
Gue lanjut **MerlinChain Day 2 manual triage dulu** karena foundation udah kuat, sambil paralel setup repo Safeheron + Morph biar jalan bareng. Setiap temuan will be logged under `reports/web3/<program>-dayX-findings.md`.

Continue?