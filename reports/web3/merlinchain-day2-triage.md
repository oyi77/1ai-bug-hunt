# MerlinChain Day 2 Manual Triage
**Scope:** Unchecked low-level `.call()` returns in bridge `permit()` flows | Contract-size breached contracts | Upgrade/storage collision surface.

---

## 1. Unchecked Low-Level `.call()` Returns — Bridge `permit()` Flows

### Affected contracts / functions
- `contracts/v2/PolygonZkEVMBridgeV2.sol`
  - `bridgeAsset()` (via `permitData` on token addresses) — lines ~957, 1009
  - `_processPermit()` / internal permit handling (two `address(token).call(...)` invocations)

### Impact
- The ERC20 `permit` call is fire-and-forget (return value not checked).
- If the token contract returns false / reverts internally, the bridge **does not revert**.
- The function then falls through to `safeTransferFrom`, which may silently fail because allowance was never approved.
- Result: user pays gas, bridge state unchanged, token balances unchanged, but the deposit/claim flow appears to have succeeded on-chain (event may be emitted).

### Exploit scenario
- **Token griefing/state corruption:** Attacker sets `permitData` for a malicious/trick token. `permit` returns false (e.g., token doesn't implement `permit` with correct signature or is a honeypot). Bridge ignores the failure and attempts `transferFrom` with zero allowance → `transferFrom` reverts → entire `bridgeAsset` reverts.
- **Alternative:** If token impl is non-standard and `permit` returns true but does nothing, bridge proceeds with `transferFrom` that may succeed without actual allowance being set (unlikely, but possible on broken tokens).
- **Reentrancy angle:** Not directly exploitable because `nonReentrant` is in place, but the unchecked call still violates checks-effects-interactions and can leave inconsistent metadata/events.

### BugRap qualification
**High** — core bridge flow. Silent gas drainage + potential inconsistent state on a core asset-transfer path. Not funds-drained directly (no attacker profit), but qualifies as high-impact business risk.

---

## 2. Contract-Size Breached Contracts

### Affected contracts / evidence
| Contract | Source size | Status |
|---|---|---|
| `contracts/v2/PolygonRollupManager.sol` | ~69 KB | **Breached** |
| `contracts/v2/PolygonZkEVMBridgeV2.sol` | ~55 KB | **Breached** |
| `contracts/mainnetUpgraded/PolygonZkEVMUpgraded.sol` | ~4.4 KB | Safe |
| Mocks (`PolygonRollupManagerMock*`, etc.) | varies | Breached / borderline |

### Impact
- EIP-170 Spurious Dragon contract-size limit is **24,576 bytes**.
- Breached contracts **cannot be deployed** as single implementations on Ethereum mainnet / L1-equivalent.
- Operators must extract libraries or split, breaking the `fork9` upgrade boundary and delaying go-live.
- Mock breaches suggest future maintenance risk: tests can diverge from production constraints.

### Exploit scenario
- **No direct runtime exploit.** This is a build/deployment constraint, not a runtime vulnerability.
- Risk: rushed refactoring to meet size limits introduces behavior changes (storage-layout shifts, removed logic paths) that can create security regressions.

### BugRap qualification
**High (operational)** — prevents mainnet deployment and forces structural changes under deadline pressure. Not a direct attacker-accessible runtime issue, but clearly high-severity under MerlinChain Q/R.

---

## 3. Upgrade/Storage Collision Surface

### Affected contracts / paths
- `PolygonZkEVMBridgeV2` (Transparent Upgradeable Proxy pattern)
- `PolygonRollupManager` (multiple variants: `newDeployments`, `mocks`, `mainnetUpgraded`)
- `PolygonZkEVMUpgraded`
- Shared base contracts: `EmergencyManager`, `DepositContractV2`, `AccessControlUpgradeable`, legacy state-variable libs

### Impact
- Heavy mix of legacy + new state vars; storage slots are not publicly documented per variant.
- Mocks + new-deployment variants share names but may have different layouts; accidental cross-upgrade can collide.
- `LegacyZKEVMStateVariables` and initializable-state libraries create a puzzle where slot assignment must remain invariant across upgrades.

### Exploit scenario
- **Proxy storage collision:** Attacker (or update admin) intentionally triggers an upgrade with mismatched storage layout, overwriting `polygonRollupManager` or `networkID`. If attacker controls `upgradeTo` calldata (admin key theft), they can corrupt bridge/rollup manager state.
- **Mock-to-mainnet leakage:** If a mock contract is ever used as an upgrade target by mistake, any pre-set state (e.g., zeroed or admin-owned) applies to real funds.

### BugRap qualification
**Critical (if admin key exposure / real upgrade path is live)** — storage collision during an upgrade can brick or hijack the rollup/bridge. But the current issue is *design-level fragility*, not an active exploit path without admin compromise.
Reduce to **High** for now, unless an upgrade script or admin key leak is confirmed.

---

## Summary & Remediation Priority

| # | Finding | Severity | Rationale |
|---|---|---|---|
| 1 | Unchecked `call` return in `permit` flows | **High** | Core bridge flow; can drain user gas / break deposits |
| 2 | Contract-size breach (RollupManager, BridgeV2) | **High** | Deployment blocker; forces refactor under pressure |
| 3 | Upgrade/storage collision surface | **High** | Design risk that could become Critical if upgrade path is exposed |

### Recommended next steps (no code changes)
1. Confirm exact contract bytecode sizes via Hardhat/Truffle `getContractCode` and document the 24 KB boundary per contract.
2. Map every `address(token).call(...)` site in `PolygonZkEVMBridgeV2` and trace whether success is checked downstream.
3. Produce a storage-layout diff artifact (e.g., `storage-layout.json`) for all variants to detect collisions before upgrade.
