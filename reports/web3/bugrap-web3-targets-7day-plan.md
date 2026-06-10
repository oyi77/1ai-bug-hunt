# Web3 BugRap 7-Day Attack Plan
Targets: MerlinChain, Safeheron, Cregis, Morph Network

This plan gives a concise, runnable 7-day sprint per target: what to clone, what toolchain to run, which vulnerability classes to prioritize, and an explicit daily deliverable.

Shared toolchain (setup once):
- Foundry (forge, cast, chisel)
- Slither
- Mythril
- Echidna
- Mainnet / testnet RPC (fork)
- Git + patch workflows

---

## MerlinChain — 200,000 USDC

Day 1 — Scope & Repo Bootstrap
- Targets: Get bridge/mint/burn/wallet adapter code paths
- Sources: `https://github.com/MerlinLayer2` org repos + any public monorepo; search for “bridge”, “rollup”
- Toolchain: foundry init; add RPC fork config (.env)
- Priority classes: access control / cross-chain replay / mint logic
- Deliverable: local foundry repo with clones, CONTEXT.md with repo list and relevant folders

Day 2 — Static Analysis
- Run Slither on every cloned contract folder
- Toolchain: slither . --exclude-dir test --solc-solcs-select
- Priority classes: missing events, untrusted caller
- Deliverable: slither-report.md with 20 highest-signal detectors

Day 3 — Symbolic Execution
- Targets: bridge deposit/redeem and withdraw
- Toolchain: mythril analyze contract.sol -o json
- Priority classes: integer overflow, signature replay, address typos
- Deliverable: mythril-notes.md with confirmed/refuted issues

Day 4 — Manual Hot Path Audit
- Inspect mint/burn invariants and fee accounting
- Priority classes: reentrancy on token callbacks, token whitelist bypass, zero-amount mint
- Deliverable: hotspot-checklist.md listing 10 suspicious line ranges

Day 5 — Fuzzing & Stateful Tests
- Toolchain: foundry test; echidna . --contract Fuzz
- Priority classes: upgrade paths, role changes
- Deliverable: fuzz log + 2 unit tests for top scenario

Day 6 — PoC Construction
- Build 1 non-destructive Foundry fork test / Echidna corpus
- Deliverable: poc/merlin/POC.md + test file

Day 7 — Report Assembly
- Deliverable: reports/web3/merlinchain-report.md + dupe check log + submit-ready zip

---

## Safeheron — 100,000 USDC

Day 1 — Scope & Repo Bootstrap
- Targets: key-management, signing, policy plugins, threshold logic
- Sources: `https://github.com/Safeheron`; fetch threshold / policy engine code
- Toolchain: foundry init with Solidity 0.8.x; RPC fork
- Priority classes: key share verification, policy bribery, threshold mismatch
- Deliverable: CONTEXT.md + repo list

Day 2 — Static Analysis
- Toolchain: Slither + custom detectors for t/*Policy*
- Priority classes: missing zero-address checks, public initializer
- Deliverable: slither-report.md with top 20

Day 3 — Symbolic Execution
- Toolchain: Mythril on policy engine + key-share contracts
- Priority classes: signature replay, nonce misuse
- Deliverable: mythril-notes.md

Day 4 — Manual Hot Path Audit
- Inspect policy evaluation and co-signer flow invariants
- Priority classes: unauthorized key addition, policy bypass, pubkey confusion
- Deliverable: hotspot-checklist.md

Day 5 — Fuzzing & Stateful Tests
- Toolchain: Echidna on policy state machine; Foundry fuzz tests
- Deliverable: fuzz log + 2 tests for edge cases

Day 6 — PoC Construction
- Deliverable: poc/safeheron/POC.md + reproducible test

Day 7 — Report Assembly
- Deliverable: reports/web3/safeheron-report.md + submit-ready packet

---

## Cregis — 100,000 USDC

Day 1 — Scope & Repo Bootstrap
- Targets: MPC / custodial wallet, asset transfer, address whitelist
- Sources: `https://github.com/cregis` + related repos
- Toolchain: foundry init; RPC fork
- Priority classes: MPC message tampering, replay, whitelist bypass
- Deliverable: CONTEXT.md + repo list

Day 2 — Static Analysis
- Toolchain: Slither
- Priority classes: external call reentrancy, missing events
- Deliverable: slither-report.md

Day 3 — Symbolic Execution
- Toolchain: Mythril
- Priority classes: underflow/overflow, tx origin checks
- Deliverable: mythril-notes.md

Day 4 — Manual Hot Path Audit
- Toolchain: manual review + line mapping
- Priority classes: role privilege escalation, gas griefing, batch tx replay
- Deliverable: hotspot-checklist.md

Day 5 — Fuzzing & Stateful Tests
- Toolchain: Echidna stateful test + Foundry test
- Deliverable: fuzz log + 2 tests

Day 6 — PoC Construction
- Deliverable: poc/cregis/POC.md + test file

Day 7 — Report Assembly
- Deliverable: reports/web3/cregis-report.md + dupe check + submit-ready packet

---

## Morph Network — 50,000 USDC

Day 1 — Scope & Repo Bootstrap
- Targets: L2 bridge, message relayer, staking contract
- Sources: `https://github.com/MorphL2` or Morph-related orgs
- Toolchain: foundry init; RPC fork
- Priority classes: liveness grief, message replay, staking math
- Deliverable: CONTEXT.md + repo list

Day 2 — Static Analysis
- Toolchain: Slither
- Priority classes: unchecked return values, missing slippage / deadline
- Deliverable: slither-report.md

Day 3 — Symbolic Execution
- Toolchain: Mythril
- Priority classes: signature replay, msg.sender vs tx.origin
- Deliverable: mythril-notes.md

Day 4 — Manual Hot Path Audit
- Toolchain: manual review
- Priority classes: forced token approval, donation attacks, upgrade hijack
- Deliverable: hotspot-checklist.md

Day 5 — Fuzzing & Stateful Tests
- Toolchain: Echidna; Foundry invariant-style tests
- Deliverable: fuzz log + 2 tests

Day 6 — PoC Construction
- Deliverable: poc/morph/POC.md + fork test

Day 7 — Report Assembly
- Deliverable: reports/web3/morph-network-report.md + dupe check + submit-ready packet
