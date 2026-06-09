# Gojek FortKnox (HashiCorp Vault) — Public Exposure & Information Disclosure

## Summary
A publicly accessible HashiCorp Vault instance (FortKnox) was discovered on Gojek's infrastructure. The Vault is **unsealed** and exposes critical system information including internal IP addresses, cluster configuration, leader election details, and the full Vault UI — all without authentication.

## Severity: High

## Affected Endpoint
- **URL:** `https://fortknox.service.q.gojek.com/`
- **Service:** HashiCorp Vault v1.16.3 (Enterprise: false)
- **Environment:** Pre-production (`vault-pre-production-0`)

## Findings

### 1. Vault Health Status (Unauthenticated)
**Endpoint:** `/v1/sys/health`

```json
{
  "initialized": true,
  "sealed": false,
  "standby": false,
  "performance_standby": false,
  "replication_performance_mode": "disabled",
  "replication_dr_mode": "disabled",
  "server_time_utc": 1779245932,
  "version": "1.16.3",
  "enterprise": false,
  "cluster_name": "vault-cluster-e5caa5d4",
  "cluster_id": "b6a58030-268e-b4dd-f09b-7d68b23916a4",
  "echo_duration_ms": 1,
  "clock_skew_ms": 0
}
```

**Risk:** Vault is **UNSEALED** — this means secrets are accessible if authentication can be bypassed. The version (1.16.3) enables targeted CVE exploitation.

### 2. Leader Information Leak (Internal IP + Hostname)
**Endpoint:** `/v1/sys/leader`

```json
{
  "ha_enabled": true,
  "is_self": true,
  "active_time": "2026-04-10T05:07:30.736345379Z",
  "leader_address": "https://10.17.86.21:8200",
  "leader_cluster_address": "https://vault-pre-production-0.vault-pre-production-internal:8201",
  "performance_standby": false,
  "raft_committed_index": 82122143,
  "raft_applied_index": 82122143
}
```

**Risk:** Leaks:
- **Internal IP address:** `10.17.86.21` (RFC 1918 private range)
- **Cluster hostname:** `vault-pre-production-0.vault-pre-production-internal`
- **Port:** 8200 (standard Vault), 8201 (cluster port)
- **Active since:** April 10, 2026
- **This is a pre-production instance** — likely less hardened than production

### 3. Seal Status (Unauthenticated)
**Endpoint:** `/v1/sys/seal-status`

```json
{
  "type": "transit",
  "initialized": true,
  "sealed": false,
  "t": 3,
  "n": 5,
  "progress": 0,
  "version": "1.16.3",
  "build_date": "2024-05-29T14:28:42Z",
  "storage_type": "raft",
  "recovery_seal": true,
  "recovery_seal_type": "shamir"
}
```

**Risk:** Exposes:
- Seal type: Transit (auto-unseal via cloud KMS)
- Recovery seal: Shamir 3-of-5 threshold
- Exact Vault build date
- Storage backend: Integrated Raft

### 4. Root Token Generation Endpoint Accessible
**Endpoint:** `/v1/sys/generate-root/attempt`

```json
{
  "nonce": "",
  "started": false,
  "progress": 0,
  "required": 3,
  "complete": false,
  "encoded_token": "",
  "encoded_root_token": "",
  "pgp_fingerprint": "",
  "otp": "",
  "otp_length": 28
}
```

**Risk:** The generate-root endpoint is unauthenticated and accessible. While it returns empty values (no active generation), this confirms that an attacker could potentially initiate root token generation if they obtain the required 3 recovery keys.

### 5. Vault UI Fully Accessible
**Endpoint:** `/ui/`

The complete Vault web UI is served publicly. The embedded configuration in the HTML meta tag reveals:
- Ember.js application configuration
- Polling URLs (sys/health, sys/replication/status, sys/seal-status)
- Namespace root URLs
- Default page size (100)
- Service worker scope (`/v1/sys/storage/raft/snapshot`)

**Risk:** The UI provides a login interface. Combined with the leaked information above, an attacker has everything needed to attempt authentication bypass.

### 6. Seal Init Endpoint
**Endpoint:** `/v1/sys/init`

Returns `{"initialized": true}` — confirms the Vault is initialized and ready for use.

## Impact

An attacker with this information can:
1. **Target the specific Vault version (1.16.3)** for known CVEs
2. **Map the internal network** using the leaked IP (10.17.86.21)
3. **Attempt authentication bypass** via the public UI
4. **Initiate root token generation** if recovery keys are compromised
5. **Access pre-production secrets** if authentication is bypassed (this is likely a less-secured environment)
6. **Pivot to production** using the same Vault configuration patterns

## Steps to Reproduce

1. `curl https://fortknox.service.q.gojek.com/v1/sys/health` — returns full system status
2. `curl https://fortknox.service.q.gojek.com/v1/sys/leader` — returns internal IP + cluster info
3. `curl https://fortknox.service.q.gojek.com/v1/sys/seal-status` — returns seal configuration
4. `curl https://fortknox.service.q.gojek.com/v1/sys/generate-root/attempt` — returns root gen status
5. Visit `https://fortknox.service.q.gojek.com/ui/` — full Vault UI loads

## Remediation

1. **Restrict network access** — Vault API and UI should not be publicly accessible
2. **Enable authentication** on system endpoints (sys/health, sys/leader, sys/seal-status)
3. **Move to production environment** — pre-production Vault should not be internet-facing
4. **Audit access logs** — check for unauthorized access to Vault endpoints
5. **Rotate secrets** — assume pre-production secrets may have been compromised
6. **Implement network segmentation** — Vault should only be accessible from internal networks

## References
- HashiCorp Vault Security Model: https://www.vaultproject.io/docs/internals/security
- Vault API Documentation: https://www.vaultproject.io/api-docs
