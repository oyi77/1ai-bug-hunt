# Morph Day 1 Attack-Surface Mapping

Scope: L1/L2 token mint-burn paths, oracles, replay/message-passing.
Base repo: /home/openclaw/repos/morph/contracts
Date: 2026-06-11
Mode: audit-only, no code changes.

---

## Enumerated Token Mint/Burn Paths (L1/L2 Gateways, USDC focus)

### 1. L2USDCGateway (USDC)
- Contract: `contracts/l2/gateways/usdc/L2USDCGateway.sol`
- Mint path (deposit finalization):
  - Function: `finalizeDepositERC20(...)`
  - Guardrails: `onlyCallByCounterpart`, `nonReentrant`, `msg.value == 0`, token whitelist (`_l1Token == l1USDC`, `_l2Token == l2USDC`), `depositPaused`.
  - Action: `IFiatToken(_l2Token).mint(_to, _amount)`
  - Risk: Unauthorized mint if counterpart/L1 path is compromised. Also burns are called only on L2 withdraw with single fail-silent `require` on the FiatToken interface that returns `bool`, but no error propagation path was found.

- Burn path (withdrawal):
  - Function: `_withdraw(...)`
  - Guardrails: `nonReentrant`, `_token == l2USDC`, `withdrawPaused`, zero data enforced.
  - Action: transfer token in, then `IFiatToken(_token).burn(_amount)`
  - Risk: Accepts arbitrary `_to` on L1; L1 finalize path is not validated here. No limit or replay protection beyond `nonce + messenger`.

### 2. Generic ERC20
- Contract: `contracts/l2/gateways/L2StandardERC20Gateway.sol`
- Mint: `IMorphERC20Upgradeable(_l2Token).mint(_to, _amount)` in finalize deposit.
- Burn: underlying L2 token `burn(_from, _amount)` in withdraw.
- Risk: bridge uses `_msgSender()` augmentation in withdraw (L2GatewayRouter wrapper), but the USDC branch disables callback by design; legacy pathways may differ.

### 3. Custom ERC20 Gateway
- Contract: `contracts/l2/gateways/L2CustomERC20Gateway.sol`
- Mint: `IMorphERC20Upgradeable(_l2Token).mint(_to, _amount)`; custom has permit-style upgrades and may bypass standard checks.
- Risk: Could miss whitelist/permission invariants if `L2TokenRegistry` and router mappings become stale.

### 4. L1USDCGateway (L1 side)
- Contract: `contracts/l1/gateways/L1USDCGateway.sol`
- Burn path expected (lock + burn branch) and role transfer interface for Circle upgrader:
  - `transferUSDCRoles(address owner)` restricted to `circleCaller`.
- Risk: USDC role transfer is a privileged hot path; if `circleCaller` is wrong, USDC ecosystem functions (mint, blacklist, pause) can be re-pointed; freeze/pause risk.

### 5. L1ReverseCustomGateway
- Contract: `contracts/l1/gateways/L1ReverseCustomGateway.sol`
- Mint: `IMorphERC20Upgradeable(_l1Token).mint(_receiver, _amount)` and same contract mints L2 variant by calling L2 Mint Extension via message callback.
- Risk: reverse mint may reintroduce reentrancy risk if not careful; candidate for replay if nonce is duplicated.

---

## Oracle / Price Path

### 1. L2GasPriceOracle
- Contract: `contracts/l2/gas_oracle/L2GasPriceOracle.sol` (inferred from spec)
- Function: `gas-oracle`
- Path: `L2GasPriceOracle` takes batches, stores `overhead`, `scalar`, and computes `gas price`. It inputs `baseFee`, `blobBaseFee`, `feeScalar`.
- Risk: If `baseFee` can be manipulated by sequencer within the same block snapshot, the oracle is not disputable out-of-band. High risk of under/over-quoting gas if chain tip is attacked.

### 2. Token Price Oracle
- Contract: `contracts/l2/oracles/TokenPriceOracle.sol` and `L2TokenPriceOracle.sol` (reported by BugRap as critical)
- Function: `token-price-oracle`
- Risk: price-manipulation critical token. If it uses a single DEX pair or off-chain feed without circuit breakers, a sequencer-time price spike could distort deposit/withdrawal limits or fee calculation; also freezes logic if it depends on this price for accounting.

### 3. L1 Gas Price Oracle
- Contract: `contracts/l1/gas_oracle/GasPriceOracle.sol` and `L1GasPriceOracle.sol`
- Function: `gas-oracle`
- Risk: same assumptions about L1 base fee; no fail-safe default risks mischarging fees paid in L1->L2 message fees.

### 4. L2 Staking / Reward Oracle
- Contract: `contracts/l2/staking/L2Staking.sol`
- Risk: if token price oracle feeds into reward distribution, any price manipulation has compounding effect across staking rewards.

---

## Replay / Message-Passing Paths Between L1 and L2

### 1. L2CrossDomainMessenger
- Contract: `contracts/l2/messengers/L2CrossDomainMessenger.sol`
- Function: relay messages, `nonce` tracking
- Path: `relayMessage` / `relayedMessage` logs, `success` flag management, re-entrancy and gas metering.
- Risk: Relay proof re-entrancy; if a call to hook runs on L2 and reverts after system update, it can cause proofs to revert in an attack window. Also replayed messages if proper nonce/relayedMessage not enforced on retries.

### 2. L1CrossDomainMessenger
- Contract: `contracts/l1/messengers/L1CrossDomainMessenger.sol`
- Function: relay to L2, `relayedMessage`, `success` storage.
- Risk: same message-replay concern; add more risk if fallback or relay enables synchronous cross-domain calls.

### 3. L2MessageQueue
- Contract: `contracts/l2/message_queue/L2MessageQueue.sol`
- Function: `forceInclude` / `appendMessage`
- Risk: if sequencer can include messages without proofs, queue could be exploited for forced deposits or withdrawals without L1 finalization. `forceInclude` combined with finalizer is especially risky.

### 4. L2ToL1MessagePasser
- Contract: `contracts/l2/message_queue/L2ToL1MessagePasser.sol`
- Function: `passMessageToL1`
- Risk: L2-to-L1 relayer uses this for withdrawals; if a message is duplicated by dishonest relayers, the L1 counterpart must enforce `relayedMessage` uniqueness.

---

## Ranked Risks

1. CRITICAL: Unauthorized USDC mint via L2USDCGateway if L1USDCGateway/L1CrossDomainMessenger path is compromised or replay occurs. Direct USDT/BGB-style emergency burn not mirrored in L2USDCGateway withdraw.

2. CRITICAL: Oracle price manipulation via token-price-oracle (L2TokenPriceOracle). If it drives feecalc or limits, an attacker manipulating the price feed can steal large sums or freeze user deposits.

3. HIGH: Smart-contract freeze via USDC `pause`/`blacklist` roles if L2USDCGateway `circleCaller` is poisoned or L2 USDC ownership transfers incorrectly. An attacker freezing accounts or the gateway poses systemic risk.

4. HIGH: Cross-chain replay / re-entrancy in L2CrossDomainMessenger and L1CrossDomainMessenger around `relayedMessage` and external call hooks. Replayed deposits/withdrawals can duplicate mint/burn cycles.

5. HIGH: L2MessageQueue `forceInclude` bypassing L1 proofs. An attacker could inject fake events to mint tokens by force-including deposit messages.

6. HIGH: Custom gateway mint/burn balance tracking stale due to registry / router mutable state; absent re-entrancy of base contract permits re-use of stale router mappings.

7. MEDIUM: L1ReverseCustomGateway mint/callback path re-entrancy / replay risk across the L2 Mend extension flow.

8. MEDIUM: Gas oracle undercharge leading to low-fee spam in deposit paths.

---

## Recommendations

- Enforce explicit nonce + relay-proof checks on L1USDCGateway finalizations and L2MessageQueue imports.
- Add fee and balance sanity checks around `L2USDCGateway` mint against L1USDC balances/events.
- Lock `updateCircleCaller` behind timelock + multisig; audit role transfers carefully.
- Introduce circuit breakers for `L2TokenPriceOracle` if a single-source or low-liquidity pair is exploited.
- Re-run static analyzer on the custom gateway contract context for reentrancy and state-mutation ordering.
- Document and enforce `success` enum invariant (0/1/2) in messengers to prevent replay windows.

---

## Files/Paths Referenced

- contracts/l2/gateways/usdc/L2USDCGateway.sol
- contracts/l2/gateways/L2StandardERC20Gateway.sol
- contracts/l2/gateways/L2CustomERC20Gateway.sol
- contracts/l1/gateways/L1USDCGateway.sol
- contracts/l1/gateways/L1ReverseCustomGateway.sol
- contracts/l2/messengers/L2CrossDomainMessenger.t.sol
- contracts/l1/messengers/L1CrossDomainMessenger.t.sol
- contracts/l2/message_queue/L2MessageQueue.t.sol
- contracts/l2/message_queue/L2ToL1MessagePasser.t.sol
- contracts/test/base/L2GasPriceOracle.t.sol
- contracts/test/L1Staking.t.sol
- contracts/libraries/token/FiatTokenV1.sol
- contracts/test/L2CustomERC20Gateway.t.sol
