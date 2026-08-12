# Blindkeep historic stack

**What this is:** an open, end-to-end path for *content-gated* and
*account-decoupled* frontier inference — with receipts that refuse to over-claim.

**What this is not:** zero-metadata magic, or IP anonymity when one person runs
both the OHTTP relay and the gateway.

---

## Architecture

```
┌────────────────── CLIENT (your machine) ──────────────────┐
│  private question + keep context                          │
│       │                                                   │
│       ▼                                                   │
│  local model abstracts  ──►  LeakGate (mechanical)        │
│       │                         │ refuse if leak          │
│       │                         ▼                         │
│       │                    NOTHING SENT                   │
│       ▼                                                   │
│  cleared generic text only                                │
│  + one-time blind token (no API key)                      │
└───────────────────────┬───────────────────────────────────┘
                        │  optional OHTTP (independent relay)
                        ▼
┌────────────────── GATEWAY (operator) ─────────────────────┐
│  redeems blind token once                                 │
│  holds provider API key                                   │
│  calls frontier API with cleared prompt only              │
└───────────────────────┬───────────────────────────────────┘
                        ▼
                 frontier provider
                        │
                        ▼
┌────────────────── CLIENT ─────────────────────────────────┐
│  re-specialise answer locally with private context        │
│  emit receipt: claims vs residual                         │
└───────────────────────────────────────────────────────────┘
```

| Property | How | Status |
|----------|-----|--------|
| Storage node cannot read memories | AES-GCM + client-side key | Shipping |
| Log cannot be rewritten unnoticed | Merkle + signed head | Shipping |
| Prove membership without naming record | Sigma / halo2 | Shipping |
| Private facts off the wire | Abstract + LeakGate | Shipping |
| Client not a named API customer | Gateway + blind token | Shipping |
| IP split from content | OHTTP + independent operators | Code shipping; ops required |
| Formal zero-metadata guarantee | — | **Not claimed** |

---

## Quickstart (pro path)

### Offline proof (no API key, no Ollama)

```bash
python tools/demo_historic_stack.py
```

### Live path

```bash
# Terminal A — gateway holds the provider credential
export BLINDKEEP_CLOUD_KEY=sk-...
python -m blindkeep frontier-gateway \
  --api-base https://api.x.ai \
  --api-key "$BLINDKEEP_CLOUD_KEY" \
  --issuer-key data/gateway_issuer.pem \
  --port 8751

# Terminal B — one-time token
python -m blindkeep token issue \
  --issuer-key data/gateway_issuer.pem \
  --out token.json

# Terminal C — client (Ollama required for live abstraction)
python -m blindkeep frontier-chat \
  --enable-frontier --accept-residual-risks \
  --gateway-url http://127.0.0.1:8751 \
  --token token.json \
  --model <model-id> \
  --text "…"
```

App UI: **Privacy truth → Historic frontier stack** (gateway mode default).

### Optional OHTTP relay

```bash
python -m blindkeep frontier-relay --gateway http://GATEWAY:8751 --port 8750
# Only meaningful if a *different* party runs the gateway.
```

---

## Receipt flags

| Flag | Meaning |
|------|---------|
| `content_private` | Private facts must not appear on the wire (gate-enforced) |
| `identity_private` | Client presented no provider API key (gateway + token) |
| `metadata_private` | Only if caller asserts independent OHTTP operators |
| `account_decoupled` | Same as identity path via gateway |

---

## Threat model (short)

| Adversary | Protected? |
|-----------|------------|
| Storage node operator | Yes — ciphertext only |
| Frontier provider (content) | Yes if LeakGate holds |
| Frontier provider (account) | Yes if gateway holds the key |
| Curious gateway operator | Sees **cleared** prompts — not your keep key |
| Network observer + colluding relay/gateway | Not if same operator |
| Malware on unlocked client | No |

---

## Related modules

| Module | Role |
|--------|------|
| `delegate.py` | Abstraction + LeakGate |
| `anon_token.py` | Chaum / Privacy Pass-shaped entitlement |
| `frontier_gateway.py` | Account-decoupled gateway |
| `frontier_relay.py` | OHTTP relay HTTP surface |
| `frontier_private.py` | Composition + receipts |
| `oblivious.py` / `hpke.py` | OHTTP crypto |
| `memory_gate.py` | Tiered release policy |
| `zk_keep.py` / `circuits/` | Membership proofs |

---

*Blindkeep remains v0 alpha. No public multi-operator network is shipped.*
