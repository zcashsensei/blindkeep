# Oblivio frontier stack

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
export OBLIVIO_CLOUD_KEY=sk-...
python -m oblivio frontier-gateway \
  --api-base https://api.x.ai \
  --api-key "$OBLIVIO_CLOUD_KEY" \
  --issuer-key data/gateway_issuer.pem \
  --port 8751

# Terminal B — one-time token
python -m oblivio token issue \
  --issuer-key data/gateway_issuer.pem \
  --out token.json

# Terminal C — client (Ollama required for live abstraction)
python -m oblivio frontier-chat \
  --enable-frontier --accept-residual-risks \
  --gateway-url http://127.0.0.1:8751 \
  --token token.json \
  --model <model-id> \
  --text "…"
```

App UI: **Privacy truth → Historic frontier stack** (gateway mode default).

### Optional OHTTP relay

```bash
python -m oblivio frontier-relay --gateway http://GATEWAY:8751 --port 8750
# Only meaningful if a *different* party runs the gateway.
```

The client then needs the gateway's key config, read from `GET /v1/params`:

```bash
python -m oblivio frontier-chat … \
  --relay-url http://RELAY:8750 \
  --ohttp-config "<ohttp_key_config_b64 from /v1/params>" \
  --ohttp-independent            # your assertion; nothing can verify it
```

The same two fields work on `POST /api/frontier-chat` as `relay_url` and
`ohttp_config`. The config is **passed in, never fetched by the client from the
gateway** — asking the gateway for its own key would open the very connection
OHTTP exists to avoid. A `relay_url` without an `ohttp_config` is refused rather
than quietly downgraded to a direct send.

---

## Receipt flags

| Flag | Meaning |
|------|---------|
| `content_private` | Private facts must not appear on the wire (gate-enforced) |
| `identity_private` | Client presented no provider API key (gateway + token) |
| `metadata_private` | OHTTP was the actual transport, relay and gateway are different non-local hosts, **and** the caller asserts independence. Asserting alone earns nothing |
| `account_decoupled` | Same as identity path via gateway |
| `transport` | What carried the request: `ohttp` or `direct`. Read from the completer, not from the request |

`metadata_private` is computed by `frontier_private.assess_network` from the
transport that actually ran. Until 2026-08-13 it was set from a request-body
flag, so `/api/frontier-chat` reported an IP split while talking straight to the
gateway — the endpoint had no way to reach the OHTTP transport at all. The
reason for every refusal is returned in `metadata_reasons`.

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

*Oblivio remains v0 alpha. No public multi-operator network is shipped.*
