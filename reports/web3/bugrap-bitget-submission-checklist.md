# Bitget Smart Contract BugRap Submission — Pre-Flight Checklist
Target: Bitget Web3 / Smart Contract (max bounty 1,000,000 USDC)
Platform: BugRap (https://bugrap.io/bounties)

## Account & Setup
- [ ] Register / verify account on BugRap
- [ ] Bind Web3 wallet for USDC payouts
- [ ] Review Bitget program rules, scope, and exclusions
- [ ] Confirm accepted report categories (smart contract, bridge, API, etc.)

## Reconnaissance
- [ ] Enumerate public repos: Bitget on GitHub/Docs
- [ ] Identify in-scope contracts on BSC / ETH / other chains
- [ ] Map contracts -> source -> ABI -> on-chain addresses
- [ ] Collect dependency graph and upgrade paths (proxy/multisig)

## Analysis
- [ ] Read latest audits for Bitget-related contracts
- [ ] Run Slither on target repo
- [ ] Run Mythril on key contracts
- [ ] Manual review hotspots: bridge, mint/burn, upgrade logic
- [ ] Check admin key management & timelocks

## PoC
- [ ] Foundry/Hardhat environment ready
- [ ] PoC contract(s) isolated in test/ folder
- [ ] Reproduce with `forge test` / `npx hardhat test`
- [ ] Ensure PoC is non-destructive and self-validating
- [ ] Network: use fork (mainnet fork or testnet if available)

## Report Skeleton
- [ ] Title (clear, non-hype): e.g., "Reentrancy in Bitget Vault withdraw() via ERC4626"
- [ ] Summary paragraph (3-5 sentences)
- [ ] Affected asset / contract address
- [ ] Attack scenario (step by step)
- [ ] Impact assessment (funds at risk, protocol insolvency, etc.)
- [ ] Suggested fix (concrete code change or pattern)
- [ ] References (audit reports, CVEs, similar incidents)

## Format & Attachments
- [ ] `report.md` -> submit in BugRap markdown
- [ ] `poc.md` -> assumptions + run commands + expected output
- [ ] `PoC.sol` / `test.t.sol` -> submit as attachment if allowed
- [ ] PII scrub: no personal keys, no production exploit with real funds

## Final Gate
- [ ] Self-test PoC passes locally
- [ ] Severity aligned with program matrix (Critical <-> 1M USDC ceiling)
- [ ] If duplicate suspected, search prior BugRap/H1/Immunefi reports
- [ ] Submit via BugRap -> store submission ID + timestamp
