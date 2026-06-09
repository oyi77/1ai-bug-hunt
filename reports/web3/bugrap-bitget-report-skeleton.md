# BugRap Report — Bitget Web3 Smart Contract
**Target:** Bitget (https://bugrap.io/bounties)  
**Program:** Web3 / Smart Contract  
**Max bounty:** 1,000,000 USDC  
**Report status:** FIRST SUBMISSION (template / skeleton)  
**Date:** 2026-06-09

---

## 1. Summary
Replace this paragraph with a concise description of the vulnerability. Include:
- Contract name and address
- Function/surface involved
- Severity guess (Critical / High / Medium / Low)
- Whether this is state-churning or read-only

Example placeholder:
> The `withdraw()` function in `Vault.sol` (0xABC...) is vulnerable to reentrancy because state updates occur after external calls to token transfers. This allows a malicious actor to drain the vault in a single transaction under specific conditions.

---

## 2. Affected Asset / Contract
| Field | Value |
|-------|-------|
| Chain | BSC / ETH / Polygon (pick one) |
| Contract address | 0x0000000000000000000000000000000000000000 |
| Source repo / commit | https://github.com/BitgetLabs/... |
| Relevant file(s) | contracts/vault/Vault.sol |

---

## 3. Attack Scenario
### Pre-conditions
- Attacker holds a short-term deposit in the vault
- Token used is supported and not pausable
- No rate limiters on `withdraw()`

### Steps
1. Attacker deposits `X` tokens.
2. Attacker calls `withdraw(X)`.
3. Contract calls `token.transfer(msg.sender, X)` BEFORE updating `userShares[msg.sender]`.
4. In the token’s `transfer()` hook, attacker reenters `withdraw()` with the same amount.
5. Reentrant withdrawal succeeds because state still reflects full balance.
6. Repeat until vault is drained or gas exhausted.

### Code snippet
```solidity
// contracts/vault/Vault.sol:114-121
function withdraw(uint256 shares) external nonReentrant {
    uint256 assets = convertToAssets(shares);
    uint256 allowed = allowance(msg.sender, address(this));
    // Vulnerable flow:
    // 1. Call external token transfer
    // 2. Burn / update shares AFTER transfer
    _transferOut(msg.sender, assets);
    _burn(msg.sender, shares);
    emit Withdraw(msg.sender, shares, assets);
}
```

---

## 4. Impact
- Critical: direct fund theft by single attacker
- Potential second-order: cascading liquidations if vault is used as collateral
- Reputation / trust loss for BitgetDeFi

---

## 5. Suggested Fix
- Apply Checks-Effects-Interactions pattern:
  ```solidity
  function withdraw(uint256 shares) external nonReentrant {
      // Effects first
      _burn(msg.sender, shares);
      uint256 assets = convertToAssets(shares);
      // Interactions last
      _transferOut(msg.sender, assets);
      emit Withdraw(msg.sender, shares, assets);
  }
  ```
- Add reentrancy guard or OpenZeppelin ReentrancyGuard
- Document time-to-finality in risk disclosures

---

## 6. Proof of Concept Checklist
- [ ] PoC repo initialized under `~/projects/bugbounty/reports/web3/poc-bitget-reentrancy/`
- [ ] Fork mode configured (`FORK_URL=...` for mainnet/testnet)
- [ ] `test/Reentrancy.t.sol` reproduces the drain in `forge test`
- [ ] Test logs show doubled withdrawal and final vault balance mismatch
- [ ] No live mainnet funds used
- [ ] Report POC steps:
  1. `forge test --match-test testReentrancy -vvvv`
  2. Expected console output shows withdrawal > deposit + compound

---

## 7. References & Prior Art
- SWC-107: Reentrancy
- Ethernaut level 10: Reentrancy
- Similar historical incidents: bZx, Lien Finance
- Bitget public audits: append links here

---

## 8. Correspondence Log (fill after submission)
| Date | Action | ID |
|------|--------|----|
| YYYY-MM-DD | Submitted to BugRap | REF-XXXXX |
| YYYY-MM-DD | Triage update | — |

---

*Report prepared by BugBounty agent under BugRap lane.*  
*Verify all placeholders before submission.*
