# MerlinChain Day 1.5 — Slither Triage Memo
Source: Slither 0.11.0 run on `MerlinLayer2/merlin-cdk-validium-contracts` (tag `fork9`) with `--hardhat-ignore-compile --exclude-dependencies`.
Coverage: 310 contracts, 956 detector hits.

## Ranked Findings

### 1. Critical / High
- Multiple production contracts exceed the 24,576-byte Spurious Dragon contract-size limit:
  - `contracts/v2/PolygonRollupManager.sol`
  - `contracts/v2/PolygonZkEVMBridgeV2.sol`
  - `contracts/mainnetUpgraded/PolygonZkEVMUpgraded.sol`
  - plus mock variants
- Impact: Mainnet deployment risk, potential need for library factoring or upgrade boundary constraints; in a zkEVM/bridge context this directly affects operator change and bridge finalization flows.
- Action: map constructor/logic split, identify if any external call path can be gated by a failed lib extract.

### 2. High
- Unchecked low-level `call` return values in bridge `permit()` flows.
- Impact: silent failures in token/bridge permission handling; can lead to inconsistent state if the call reverts internally but outer flow continues.
- Action: isolate the exact `permit()` sites, model the reentrancy/data-corruption path, and verify whether BugRap treats it as Medium or High depending on core vs general business.

### 3. Medium
- Heavy unused legacy state variable usage in `LegacyZKEVMStateVariables` and `PolygonAccessControlUpgradeable` across multiple rollup-manager variants.
- Impact: state-bloat and upgrade/puzzle risk; not directly exploitable unless tied to initialization or migration path; good triage for storage-collision hunting.
- Action: cross-check with upgrade/migration scripts in `upgrade/` and `deployment/`.

### 4. Medium / Low
- State variables that should be `constant` in legacy rollup state libs (batch fee, timestamps, aggregator, version).
- Unused state in `ClaimCompressor` and `PolygonValidiumStorageMigration`.
- ERC20 metadata values flagged for `immutable`.
- Impact: mainly code-quality / gas, limited immediate bounty surface unless chained to other issues.

## Top 3 Targets for Next Session
1. Contract-size exception map for `PolygonRollupManager.sol` + `PolygonZkEVMBridgeV2.sol`.
2. Unchecked `call` return value exploit chain in bridge permit flow.
3. Storage-collision audit of `PolygonTransparentProxy` + `AccessControlUpgradeable` layout in upgrade paths.
