# Smart Contract Bug Bounty Skill
# Learn + earn path for Web3 bounties (BugRap, Sherlock, Code4rena, Immunefi)

## Phase 1: Foundation (Week 1-2)
- Solidity basics: functions, modifiers, events, inheritance
- EVM model: gas, opcodes, storage layout
- Key vulns: reentrancy, overflow/underflow, access control, front-running

## Phase 2: Practice Targets (Week 3-4)
- Ethernaut (capturetheether.com)
- Damn Vulnerable DeFi
- Code4rena past contests (read reports)
- Sherlock public reports

## Phase 3: BugRap Targets
1. Bitget — 1,000,000 USDC
2. MerlinChain — 200,000 USDC
3. Safeheron — 100,000 USDC
4. Cregis — 100,000 USDC
5. Morph Network — 50,000 USDC

## Phase 4: Tooling
- Slither static analysis
- Mythril symbolic execution
- Echidna fuzzing
- Foundry test framework

## Quick Win Checklist
- [ ] Complete Ethernaut levels 1-10
- [ ] Submit 1 report to BugRap (any severity)
- [ ] Audit 1 Code4rena contest in replay mode
- [ ] Build 1 PoC exploit for reentrancy

## 4-Week Crash Plan (BugRap Bitget-first)
Target program study order:
1. Bitget — 1,000,000 USDC (highest ceiling; focus first)
2. MerlinChain — 200,000 USDC
3. Safeheron — 100,000 USDC
4. Cregis — 100,000 USDC
5. Morph Network — 50,000 USDC

### Week 1: Deep Scoping + Tooling Bootstrap
- Read Bitget docs and public contracts on BSC/ETH.
- Map contracts: token wrappers, vaults, bridge modules, timelocks.
- Build local Foundry repo; add fork-infura/mainnet RPC.
- Run Slither baseline (`slither . --exclude-dir test`) on cloned repo.
- Create `reports/web3/bugrap-bitget-submission-checklist.md` and initialize PoC scaffold under `reports/web3/poc-bitget-reentrancy/`.

### Week 2: Manual Audit + PoC Draft
- Audit hotspots: swap/withdraw path, upgrade logic, fee-on-transfer tokens.
- Write `bugrap-bitget-report-skeleton.md` with concrete placeholder locks.
- Start Foundry unit test for reentrancy scenario (testnet fork).
- Run Mythril + Echidna on top 5 high-USD contracts.
- Identify 2-3 candidate vulns and select top 1 for submission.

### Week 3: PoC Polish + Report Completion
- Finalize PoC (fork, deterministic, non-destructive).
- Run Cheats/Echidna on edge cases (fee-on-transfer, rebase tokens).
- Fill all placeholders in report skeleton; remove placeholder tokens pre-flight via `scripts/bugrap_web3_preflight.py`.
- Counter-dupe check on BugRap/H1/Immunefi for candidate vuln.

### Week 4: Submission + Secondary Target Rotation
- Submit accepted-vuln pair to BugRap (track in Correspondence Log).
- If accepted/duplicate, switch next highest-probability issue for MerlinChain program.
- Weekly 1-hour replay audit of one past Code4rena contest to keep pattern library fresh.
- Log lessons into `reports/web3/` and update this skill doc with real outcomes.
