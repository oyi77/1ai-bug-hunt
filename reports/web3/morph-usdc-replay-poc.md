# Morph Network — Phase C PoC Skeleton: USDC Gateway + Messenger Replay

**Date:** June 11, 2026  
**Target:** Morph Network (BugRap)  
**Attack Surface:** L1USDCGateway / L2USDCGateway / L1CrossDomainMessenger / L2CrossDomainMessenger  
**Repo:** `/home/openclaw/repos/morph/contracts`

---

## Executive Summary

Two high-signal attack paths identified:
1. **USDC Mint Replay via Message Hash Collision / Messenger Replay** — L2USDCGateway.mint() is callable by anyone passing messenger verification; replay/failed-relay semantics may allow duplicate mints under edge conditions.
2. **Pausable Bridge Freeze (Denial-of-Service)** — both USDC gateways expose `pauseDeposit` / `pauseWithdraw` under `onlyOwner`; if owner key is leaked or governance is compromised, attacker can freeze all USDC flow.

PoC skeleton below covers attack path #1.

---

## Vulnerability: L2 USDC Mint Replay via Messenger Replay Semantics

**Severity:** High → Critical  
**Impact:** Unauthorized USDC mint on L2 → direct fund creation / duplication  
**Affected Contracts:**
- `contracts/l2/gateways/usdc/L2USDCGateway.sol` — `finalizeDepositERC20()` mints without sender replay check
- `contracts/l2/L2CrossDomainMessenger.sol` — `relayMessage()` tracks `isL1MessageExecuted` by calldata hash
- `contracts/l1/L1CrossDomainMessenger.sol` — `proveAndRelayMessage()` tracks `finalizedWithdrawals`

### Root Cause Analysis

**L2USDCGateway.sol finalizeDepositERC20:**
```solidity
function finalizeDepositERC20(
    address _l1Token, address _l2Token, address _from, address _to,
    uint256 _amount, bytes calldata _data
) external payable override onlyCallByCounterpart nonReentrant {
    // ...
    require(IFiatToken(_l2Token).mint(_to, _amount), "mint USDC failed");
    // ...
}
```
- Only check is `onlyCallByCounterpart` (must be L1 messenger) + nonReentrant
- NO check that `(from, to, amount)` tuple was not already processed
- Mint is unconditional once messenger passes

**L2CrossDomainMessenger.sol relayMessage:**
```solidity
bytes32 _xDomainCalldataHash = keccak256(_encodeXDomainCalldata(_from, _to, _value, _nonce, _message));
require(!isL1MessageExecuted[_xDomainCalldataHash], "Message was already successfully executed");
// ...
if (success) {
    isL1MessageExecuted[_xDomainCalldataHash] = true;
}
```
- Replay protection exists at messenger level
- **BUT**: if a message execution fails (returns false), `isL1MessageExecuted` stays FALSE
- Attacker can re-submit same calldata with higher gas → duplicate mint

**Attack Preconditions:**
1. Attacker can predict or influence calldata hash of a deposit message
2. The first execution intentionally reverts L2USDCGateway.mint (e.g., by front-running with a custom token address that fails IFiatToken.mint check)
3. Attacker then replays with correct parameters → mint succeeds; second successful execution not prevented

**Note on L1USDCGateway.sol:** L1 finalizeWithdrawERC20 only burns (no mint); this path is not directly fund-creating but burns user USDC without L2 counterpart if gated.

---

## PoC Skeleton (Foundry / Hardhat Test)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity =0.8.24;

import "forge-std/Test.sol";
import {L2USDCGateway} from "contracts/l2/gateways/usdc/L2USDCGateway.sol";
import {IL2CrossDomainMessenger} from "contracts/l2/IL2CrossDomainMessenger.sol";
import {IFiatToken} from "contracts/interfaces/IFiatToken.sol";

contract MorphUSDCReplayPoC is Test {
    L2USDCGateway gateway;
    IFiatToken usdc;
    address alice = address(0xA1);
    address attacker = address(0xB1);

    function setUp() public {
        // deploy / mock USDC, gateway, messenger
    }

    function testFailingMintThenReplay() public {
        // 1. Craft message hash that will fail first (e.g., wrong token address)
        // 2. relayMessage with attacker as _from → should emit FailedRelayedMessage
        // 3. Replay same calldata with correct token address → isL1MessageExecuted still false
        // 4. gateway.finalizeDepositERC20 mints to attacker 2x
    }
}
```

### Execution Steps
1. Deploy L2USDCGateway + mock IFiatToken + mock L2CrossDomainMessenger on fork
2. Construct `relayMessage(alice, gateway, 0, nonce, finalizeDepositERC20_calldata)` payload
3. First call: modify calldata to pass invalid `_l2Token` → expect revert in `mint()` → `isL1MessageExecuted` stays FALSE
4. Second call: pass valid calldata → should mint successfully
5. **Assert:** `usdc.balanceOf(attacker) == 2 * _amount` → confirms replay mint

---

## Attack Path #2: Bridge Freeze via Pause Functions

**Contract:** Both `L1USDCGateway` and `L2USDCGateway`  
**Function:** `pauseDeposit(bool)` / `pauseWithdraw(bool)` — `onlyOwner`  
**Impact:** Denial-of-service; all USDC deposits/withdrawals frozen  
**Privilege:** Owner key compromise or malicious governance upgrade  
**Proof:** Call `pauseDeposit(true)` as owner; verify all subsequent `_deposit` calls revert with `"deposit paused"`

---

## Remediation Suggestions

1. **Replay Guard in Gateway:** Add mapping `processedMessages[keccak256(_from, _to, _amount)]` to L2USDCGateway and check before mint.
2. **Messenger Atomicity:** L2CrossDomainMessenger should mark `isL1MessageExecuted = true` BEFORE calling target contract, not after — prevents reentrancy + replay.
3. **Pause Circuit Breaker:** Pause functions should be time-locked; require `timelock.delay >= 24h` for deposit/withdraw freezes on value-bearing gateways.
4. **Circle Caller Validation:** `circleCaller` in L1USDCGateway should be `bytes32` hash of expected EIP-191 signature, not raw address, to prevent spoofing via address collision.

---

## Deliverables

| File | Status |
|------|--------|
| `morph-network-attack-surface.md` | ✅ Done |
| `morph-usdc-replay-poc.md` (this file) | ✅ Done |
| PoC test code (`test/USDCReplay.t.sol`) | pending |
| Counter-dupe check (H1/BugRap prior reports) | pending |
| Final BugRap submission draft | pending |

---

## Next Step

Gue lanjutin:
1. Write actual Foundry/Hardhat PoC skeleton under `~/projects/bugbounty/scripts/morph_poc/`
2. Counter-dupe check on existing Morph / bridge reports
3. Draft BugRap submission report

Continue?
