# BugRap Web3/Smart-Contract Scope Audit
**Date:** June 10, 2026  
**Source:** https://bugrap.io/bounties + individual program pages  
**Auditor:** Automated / Agent-assisted  
**Total Programs Audited:** 10  
**Total Pages:** 1 (10 programs, next page disabled)

---

## Summary

| # | Program | Web3/Smart Contract In-Scope? | Key Web3 Assets |
|---|---------|------------------------------|-----------------|
| 1 | Bitget | ✅ YES | `Blockchain / Smart Contract` row in reward matrix |
| 2 | MerlinChain | ✅ YES | Bridge Contract, MToken Swap, Merl Airdrop, L2 Node Software, Smart Contract Source Code, zkEVM Prover |
| 3 | Safeheron | ✅ YES (Core) | Safeheron TEE, Safeheron MPC Nodes, self-custody assets |
| 4 | Cregis | ✅ YES | MPC wallet, TEE platform, digital asset custody |
| 5 | Bitget Wallet (ex-BitKeep) | ✅ YES | Multi-chain crypto wallet, token swap, NFT marketplace, DApp browser, cross-chain bridging |
| 6 | Morph Network | ✅ YES | On-chain stablecoin settlement layer; Smart Contracts/Blockchain explicitly in scope |
| 7 | PlatON | ✅ YES | Blockchain & SmartContract category; ATON Wallet, PlaTrust Wallet JS SDK, Plat Bridge |
| 8 | Mask | ✅ YES (partial) | Blockchain & SmartContracts section explicitly listed |
| 9 | DeSyn Protocol | ✅ YES | Decentralized asset management via smart contracts (on-chain) |
| 10 | Tokenlon | ✅ YES | Full DEX: 18+ on-chain smart contract addresses |

**Result: 10/10 programs have measurable Web3/smart-contract scope.**

---

## Per-Program Detail

---

### 1. Bitget
**URL:** https://bugrap.io/bounties/bitget  
**Category:** Cryptocurrency Exchange + Web3 Company  
**Reports:** 116  

**Project Description:**  
"World's leading cryptocurrency exchange and Web3 company. Bitget Wallet (formerly BitKeep) is a world-class multi-chain crypto wallet."

**In-Scope Web3 Assets:**
- Web: `*.bitget.com`
- Mobile App (Exchange): Android + iOS — Bitget Exchange
- **Wallet App**: Android + iOS — Bitget Wallet, latest version
- **Wallet Extension**: Chrome / Edge / Firefox — Bitget Wallet Extension
- Desktop Client: Windows / macOS

**Blockchain / Smart Contract Scope:**
Explicit reward matrix row: **"Blockchain / Smart Contract"** — payouts:
- Low: 100–300 USDC
- Medium: 300–1,500 USDC
- High: 2,000–4,500 USDC
- Critical: 4,500–50,000 USDC
- Discretionary cap: $1,000,000 USD for core fund-impacting vulnerabilities

**Web3 Business Context:**  
"Core business" includes spot trading, contract trading, payments, withdrawals, deposits, authentication. Web3 risk scoring explicitly covers wallet connect/signature flows, DApp leaking balances/history, spoofed signature prompts/phishing-style UX, XSS enabling wallet signature hijack or transaction manipulation.

**Web3-Specific Out-of-Scope:**  
None explicitly stated beyond third-party integrations and non-latest app versions.

**Key Finding:** Strong and explicit smart-contract / blockchain audit scope with industry-leading bounty ceiling.

---

### 2. MerlinChain
**URL:** https://bugrap.io/bounties/merlinchain  
**Category:** Bitcoin Layer 2 Infrastructure  
**Reports:** 53  

**Project Description:**  
"Bitcoin Layer 2 that integrates ZK-Rollup network, decentralized oracle network, and on-chain BTC fraud proof modules."

**In-Scope Web3 Assets:**
| Category | Asset |
|----------|-------|
| Smart Contract | Bridge Contract |
| Smart Contract | MToken Swap Contract |
| Smart Contract | Merl Token Airdrop |
| Public (Blockchain) | Layer2 Node Software of Merlin |
| Public (Blockchain) | Smart Contract Source Code of Merlin |
| Public (Blockchain) | zkEVM Implementation and Prover Source Code |

**Blockchain/DLT Impacts (In Scope):**
| Level | Impact | Reward (USDC) |
|-------|--------|---------------|
| Critical | Direct loss of funds | 50,000–200,000 |
| High | Permanent freezing of funds (hardfork) | 10,000–50,000 |
| High | Network unable to confirm tx (total shutdown) | 10,000–50,000 |

**Smart Contracts Impacts (In Scope):**
| Severity | Impact | Reward (USDC) |
|----------|--------|---------------|
| Critical | Direct theft of user funds (at-rest or in-motion) | 50,000–200,000 |
| Critical | Direct theft of NFTs | 50,000–200,000 |
| Critical | Permanent freezing of funds | 50,000–200,000 |
| Critical | Permanent freezing of NFTs | 50,000–200,000 |

**Out-of-Scope Known Issues:**  
Multi-sig management permissions, bridge mint via MPC+Cobo, AA address mint for NFT receipts, BTC Layer 2 withdrawal address entry.

**Key Finding:** Pure Web3/blockchain program. Very high bounty. Full smart contract + L2 node software + zkEVM prover all in scope.

---

### 3. Safeheron
**URL:** https://bugrap.io/bounties/safeheron  
**Category:** Digital Asset Self-Custody Platform  
**Reports:** 38  

**Project Description:**  
"Open & transparent digital asset self-custody platform."

**Core Scopes:**
| Name | Description |
|------|-------------|
| Safeheron self-custody assets | User crypto assets |
| Safeheron TEE | TrustZone/SGX/Nitro trusted execution environment |
| Safeheron MPC Nodes | Multi-party computation key sharding nodes |

**Normal Scopes:**
- Domain: `*.safeheron.com, *.safeheron.vip`
- APP: Safeheron APP
- Extension: Safeheron Chrome Extension

**Reward Tiers:**
| Severity | Core Scope | Normal Scope |
|----------|-----------|-------------|
| Critical | 50,000–100,000 USDC | 1,500–1,800 USDC |
| High | 10,000–50,000 USDC | 500–750 USDC |
| Medium | 5,000–10,000 USDC | 60–120 USDC |
| Low | 0–5,000 USDC | 15–30 USDC |

**Key Finding:** Core scope is literally custody infrastructure — TEE, MPC key shards, and self-custodied assets. This is deep cryptographic/blockchain attack surface. Highest bounty per CVSS point on the platform for core scope.

---

### 4. Cregis
**URL:** https://bugrap.io/bounties/cregis  
**Category:** Digital Asset Collaboration Platform (Web3/MPC)  
**Reports:** 48  

**Project Description:**  
"Digital asset collaboration platform in Web3 era. Based on MPC technology, prevent shards of private key from evil with TEE (TrustZone/SGX/Nitro)."

**In-Scope Assets:**
- Source Code (GitHub): Cregis GitHub Repo
- Websites & Application: `*.cregis.com`
- Android: Cregis Android (Google Play)
- iOS: Cregis for iOS

**Reward Tiers:**
| Severity | Reward (USDC) |
|----------|--------------|
| Disaster (key leakage, mass server attack) | Up to 100,000 USDC |
| Critical | 2,500–10,000 |
| High | 500–2,500 |
| Medium | 100–500 |
| Low | Based on necessity |

**Explicit Web3 Statement:**  
"We encourage and support communication with us in high-risk situations that may involve significant loss of funds, property, or servers (such as... serious vulnerabilities in smart contracts, and the possibility of significant loss of assets in user wallets due to company product issues, except for DDOS)."

**Key Finding:** MPC/TEE-based Web3 custody platform. Smart contract vulnerabilities and wallet asset losses explicitly called out as high-priority. Core business is digital assets.

---

### 5. Bitget Wallet (formerly BitKeep)
**URL:** https://bugrap.io/bounties/Bitget%20Wallet%20(Formerly%20BitKeep)  
**Category:** Multi-Chain Crypto Wallet  
**Reports:** 72  

**Project Description:**  
"World-class multi-chain crypto wallet. Offers comprehensive Web3 solutions including wallet functionality, token swap, NFT Marketplace, DApp browser, and cross-chain bridging."

**In-Scope Assets:**
| Category | Asset |
|----------|-------|
| Web | Bitget Wallet web interfaces (`*.bitget.com/web3`) |
| Wallet App | Android + iOS — Bitget Wallet latest |
| Wallet Extension | Chrome / Edge / Firefox — latest |

**Reward Matrix:**
| Asset | Critical Max |
|-------|-------------|
| Web | 20,000 USDC |
| Wallet App | 50,000 USDC |
| Wallet Extension | 50,000 USDC |

Discretionary cap: **$1,000,000 USD** for core fund-impacting issues.

**Web3-Specific Critical Classifications:**
- XSS enabling wallet signature hijack or transaction manipulation
- All supported blockchain protocols (EVM + Solana + BTC, etc.) coverage required for top-band payout

**Key Finding:** Pure Web3 wallet attack surface — mobile app, browser extension, and web interfaces all handling private keys and signing transactions across EVM/Solana/BTC ecosystems.

---

### 6. Morph Network
**URL:** https://bugrap.io/bounties/Morph%20Network  
**Category:** On-Chain Stablecoin Settlement Layer (L2)  
**Reports:** 11  

**Project Description:**  
"Secure settlement layer for global crypto payments, offering seamless on-chain stablecoin infrastructure with BGB."

**In-Scope Assets:**
- `https://github.com/morph-l2/morph`
- `https://github.com/morph-l2/go-ethereum`
- `https://github.com/morph-l2/tendermint`
- `*.morph.network`

**Critical Web3-Specific Examples Listed in Policy:**
- Unauthorized minting of core bridge tokens (USDT, BGB)
- Smart contracts becoming uncallable, causing severe financial loss
- Oracle price manipulation
- Cross-chain replay attacks
- Permanent freezing of funds
- Consensus forgery

**Reward Tiers:**
| Severity | Reward (USDC) |
|----------|--------------|
| Critical | 4,500–50,000 |
| High | 1,500–4,500 |
| Medium | 300–1,500 |
| Low | 10–300 |

**Out-of-Scope Web3 Items:**  
Third-party oracles (incorrect data), flash loans (not excluded — in scope), basic economic governance (51%), third-party custom token bridges, best practice critiques, Sybil/centralization risks.

**Key Finding:** Explicitly mentions smart contracts, bridge tokens, L2 consensus, and oracles. Full on-chain attack surface.

---

### 7. PlatON
**URL:** https://bugrap.io/bounties/PlatON  
**Category:** Privacy-Preserving Blockchain / AI Computing Network  
**Reports:** 56  

**Project Description:**  
"Next-generation Internet infrastructure protocol based on blockchain and supported by privacy-preserving computation network."

**Dedicated "BlockChain and SmartContract" Reward Track:**
| Severity | Reward (USDC) |
|----------|--------------|
| Critical | 10,000–50,000 |
| High | 2,000–10,000 |
| Medium | 500–2,000 |
| Low | 50–500 |

**In-Scope Web3 Assets:**
| Category | Asset |
|----------|-------|
| BlockChain | PlatON GitHub Repo |
| ATON Wallet | iOS App Store |
| ATON Wallet | Google Play (Android) |
| PlaTrust Wallet JS SDK | PlaTrust GitHub Repo |
| Platscan Website/Explorer | Platscan GitHub |
| Bridge | Plat Bridge Website |
| Websites | `*.platon.network` |

**Key Finding:** Has an entire dedicated reward track for blockchain/smart contract bugs, separate from websites. Includes bridge, wallet SDK, and blockchain node software.

---

### 8. Mask
**URL:** https://bugrap.io/bounties/Mask  
**Category:** Web3 Social Media Privacy Extension  
**Reports:** 28  

**Project Description:**  
"Brings privacy and benefits from Web3 to social media like Twitter & Facebook — with an open-sourced browser extension."

**Dedicated "Blockchain & SmartContracts" Reward Track:**
| Severity | Reward (USDC) |
|----------|--------------|
| Critical | 10,000–50,000 |
| High | 5,000–10,000 |
| Medium | 500–5,000 |
| Low | 100–500 |

**In-Scope Assets:**
- Source Code: Mask Network GitHub Repo
- Chrome Webstore: Mask Network Browser Extension
- Opera Addons: Mask Network Browser Extension
- Firefox: Mask Network Browser Extension
- Websites: `*.mask.io`

**Key Finding:** Despite being a browser extension for social media, the project explicitly includes a "Blockchain & SmartContracts" reward track — implying their extension facilitates on-chain interactions that have smart-contract attack surface. Scope does not specifically enumerate contract addresses but the track is clearly in-scope.

---

### 9. DeSyn Protocol
**URL:** https://bugrap.io/bounties/DeSyn  
**Category:** Decentralized Asset Management (DeFi)  
**Reports:** 28  

**Project Description:**  
"Decentralized asset management infrastructure on Web3, empowering users to securely create and manage customized pool-based portfolios with various on-chain assets (tokens, NFTs, derivatives, etc.) via smart contract."

**Dedicated "Blockchain & SmartContracts" Reward Track:**
| Severity | Reward (USDC) |
|----------|--------------|
| Critical | 20,000–50,000 |
| High | 6,000–20,000 |
| Medium | 3,000–6,000 |
| Low | 500–3,000 |

Web track mirrors the same reward structure.

**In-Scope Assets:**
- Source Code: DesynLab GitHub Repo
- Websites: `*.desyn.io`

**Key Finding:** Core technology is smart contracts — decentralized asset management pools, tokens, NFTs, derivatives, all on-chain. High bounty ceiling. Smart contract auditing is the primary value of this bounty program.

---

### 10. Tokenlon
**URL:** https://bugrap.io/bounties/Tokenlon  
**Category:** Decentralized Exchange (DEX)  
**Reports:** 36  

**Project Description:**  
"Trusted decentralized exchange protocol on blockchain networks."

**In-Scope Smart Contracts (18 on-chain addresses explicitly listed):**

| Contract Name | Address |
|---------------|---------|
| LON | `0x0000000000095413afC295d19EDeb1Ad7B71c952` |
| Tokenlon | `0x03f34bE1BF910116595dB1b11E9d1B2cA5D59659` |
| UserProxy | `0x2eF1928A890CabDe01D31A2081aD7BD856E6eF4B` |
| PermanentStorage | `0x670ac90Bb1b55eD7f8943c1e1ef668281511aFD8` |
| PermanentStorage (Upgrade Proxy) | `0x6D9Cc14a1d36E6fF13fc6efA9e9326FcD12E7903` |
| Spender | `0x3c68dfc45dc92C9c605d92B49858073e10b857A6` |
| AllowanceTarget | `0x8A42d311D282Bfcaa5133b2DE0a8bCDBECea3073` |
| PMM | `0x8D90113A1e286a5aB3e496fbD1853F265e5913c6` |
| AMMQuoter | `0x4cEc337A013a53ed8e318f204E7cC12406ffC246` |
| AMMWrapperWithPath | `0x4a14347083B80E5216cA31350a2D21702aC3650d` |
| RFQ | `0xfD6C2d2499b1331101726A8AC68CCc9Da3fAB54F` |
| xLON | `0xf88506b0f1d30056b9e5580668d5875b9cd30f23` |
| LONStaking (Logic contract) | `0x413ecce5d56204962090eef1dead4c0a247e289b` |
| MiningTreasury | `0x292a6921Efc261070a0d5C96911c102cBF1045E4` |
| TreasuryVesterFactory | `0x000000003A8DBF47cD362EDA39B3a5F3FC6E99ce` |
| MerkleRedeem | `0x0000000006a0403952389B70d8EE4E45479023db` |
| RewardDistributor | `0xbF1C2c17CC77e7Dec3466B96F46f93c09f02aB07` |
| StakingRewards (LON/ETH) | `0xb6bC1a713e4B11fa31480d31C825dCFd7e8FaBFD` |
| StakingRewards (LON/USDT) | `0x9648B119f442a3a096C0d5A1F8A0215B46dbb547` |

**Reward Tiers:**
| Severity | Reward (USDC) |
|----------|--------------|
| Critical | 10,000–50,000 |
| High | 2,500–10,000 |
| Medium | 2,500–10,000 |

**Key Finding:** Most precisely scoped Web3 program on the platform. Every on-chain contract is listed by name and address. Highest target density for DeFi/smart-contract researchers.

---

## Web3 Scope Classification

### Tier 1 — Deep Smart Contract / On-Chain (primary audit targets)
| Program | What's In Scope |
|---------|----------------|
| Tokenlon | 18 specific on-chain contract addresses (DEX AMM, staking, RFQ, etc.) |
| MerlinChain | Bridge contract, swap contract, airdrop contract, L2 node software, zkEVM prover |
| DeSyn Protocol | Smart contracts (pools, asset management) via GitHub |
| PlatON | Blockchain core, ATON wallet JS SDK, Plat Bridge |
| Morph Network | Smart contracts, L2 consensus/sequencer, bridge tokens |

### Tier 2 — Wallet / Custody Infrastructure
| Program | What's In Scope |
|---------|----------------|
| Bitget Wallet (ex-BitKeep) | Multi-chain wallet app + extension (signing, key management, bridging) |
| Safeheron | Core: TEE, MPC nodes, self-custody assets; Normal: domains + apps |
| Cregis | MPC-TEE wallet custody, smart contract vulnerabilities acknowledged |

### Tier 3 — Web3-Adjacent
| Program | What's In Scope |
|---------|----------------|
| Bitget | Dedicated "Blockchain / Smart Contract" reward row (no specific contracts listed) |
| Mask | Explicit "Blockchain & SmartContracts" reward track (extension enabling on-chain interactions) |

---

## Top Bounty Ceilings (Critical)

| Program | Critical Bounty | Notes |
|---------|----------------|-------|
| Bitget | 20,000–50,000 USDC (up to $1,000,000 discretionary) | Wallet extension highest |
| MerlinChain | 50,000–200,000 | Direct loss of funds |
| Safeheron | 50,000–100,000 | Core scope (TEE/MPC) |
| Morph Network | 4,500–50,000 | Unauthorized bridge token mint |
| PlatON | 10,000–50,000 | Blockchain track only |
| Mask | 10,000–50,000 | Blockchain track only |
| DeSyn | 20,000–50,000 | Equal for on-chain and web |
| Tokenlon | 10,000–50,000 | Per contract |
| Cregis | 2,500–10,000 | (higher "Disaster" up to 100k) |
| Bitget Wallet | 4,000–50,000 | (up to $1,000,000 discretionary) |

---

## Notes on Scope Clarity

1. **Bitget** is the only program that lists a specific "Blockchain / Smart Contract" asset category in the reward matrix but does NOT enumerate specific contract addresses. Scope is broader but less targeted than Tokenlon.
2. **Tokenlon** is the most precisely scoped — 18 specific contract addresses. Suitable for targeted smart-contract audit.
3. **MerlinChain** includes source-code-level scopes (zkEVM prover, L2 node) beyond just deployed contracts.
4. **Mask** has the most ambiguous Web3 scope — reward track exists but no specific contract addresses enumerated.
5. **Cregis** does not enumerate contracts by address but explicitly calls out smart-contract vulnerabilities and wallet asset loss in reporting rules.

---

## Program URLs Reference

1. https://bugrap.io/bounties/bitget
2. https://bugrap.io/bounties/merlinchain
3. https://bugrap.io/bounties/safeheron
4. https://bugrap.io/bounties/cregis
5. https://bugrap.io/bounties/Bitget%20Wallet%20(Formerly%20BitKeep)
6. https://bugrap.io/bounties/Morph%20Network
7. https://bugrap.io/bounties/PlatON
8. https://bugrap.io/bounties/Mask
9. https://bugrap.io/bounties/DeSyn
10. https://bugrap.io/bounties/Tokenlon

---

*End of audit.*
