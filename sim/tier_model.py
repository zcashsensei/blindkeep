"""Memory-tier simulation: when does network-attached memory beat not running at all?

The question this answers
-------------------------
A user cannot run a model because it does not fit in their GPU. Can memory
contributed over a network make it runnable, and if so, how slowly?

The model
---------
Autoregressive decoding is **memory-bandwidth bound**, not compute bound. To
produce one token the hardware must read every model weight and the whole KV
cache. So the ceiling is:

    tokens/second  =  1 / sum over tiers of (bytes resident in tier / tier bandwidth)

That is the standard roofline for decode. It ignores compute time, kernel
overheads and scheduling, which makes every number here an **optimistic upper
bound** — real throughput is lower. That is the right direction for this
question: if the optimistic bound is already unusable, the real thing certainly is.

Prefill is treated separately: it is a one-off transfer whose cost amortises
over the whole generation, which is why a link that is hopeless for chat can be
perfectly reasonable for a long batch job.

Assumptions are stated as constants below so they can be argued with.
"""

from __future__ import annotations

from dataclasses import dataclass

GB = 1024 ** 3
MB = 1024 ** 2


# --------------------------------------------------------------------------- #
# Hardware tiers. Bandwidths are sustained, not burst.
# HBM/DRAM/NVMe follow NVIDIA's published context-memory hierarchy.
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Tier:
    name: str
    bandwidth_gbps_bytes: float      # GB/s
    latency_ms: float

    @property
    def bps(self) -> float:
        return self.bandwidth_gbps_bytes * GB


TIERS = [
    Tier("GPU HBM (H100)",          3350.0, 0.0001),
    Tier("CPU DRAM (PCIe 5.0)",       63.0, 0.001),
    Tier("Local NVMe SSD",             7.0, 0.1),
    Tier("Datacentre 100 GbE",        12.5, 0.5),
    Tier("Datacentre 10 GbE",          1.25, 1.0),
    Tier("Home fibre 1 Gbps",          0.125, 15.0),
    Tier("Fast broadband 300 Mbps",    0.0375, 25.0),
    Tier("Typical upload 40 Mbps",     0.005, 40.0),
]


# --------------------------------------------------------------------------- #
# Models. Real configurations; KV sizing accounts for grouped-query attention,
# which most current models use and which shrinks the cache by ~8x versus MHA.
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Model:
    name: str
    params_b: float
    layers: int
    kv_heads: int
    head_dim: int

    def weight_bytes(self, bits: int) -> float:
        return self.params_b * 1e9 * bits / 8

    def kv_bytes_per_token(self, bits: int = 16) -> float:
        # 2 tensors (K and V) per layer per kv head
        return 2 * self.layers * self.kv_heads * self.head_dim * (bits / 8)

    def kv_bytes(self, context: int, bits: int = 16) -> float:
        return self.kv_bytes_per_token(bits) * context


MODELS = [
    Model("Llama-3 8B",    8.0,  32,  8, 128),
    Model("Llama-3 70B",  70.0,  80,  8, 128),
    Model("Llama-3 405B", 405.0, 126, 8, 128),
]

GPUS = {
    "RTX 3060 (12 GB)": 12 * GB,
    "RTX 4090 (24 GB)": 24 * GB,
    "A100 (80 GB)":     80 * GB,
}


# --------------------------------------------------------------------------- #
# The model
# --------------------------------------------------------------------------- #

def decode_tokens_per_sec(resident_local: float, offloaded: float,
                          local: Tier, remote: Tier, batch: int = 1) -> float:
    """Upper bound on decode throughput.

    Weights are shared across a batch, so streaming them amortises over batch
    size. KV cache is per sequence and does not amortise.
    """
    if offloaded <= 0:
        seconds = resident_local / local.bps
    else:
        seconds = (resident_local / local.bps) + (offloaded / remote.bps) / max(batch, 1)
        seconds += remote.latency_ms / 1000.0
    return 1.0 / seconds if seconds > 0 else float("inf")


def fits_locally(model: Model, bits: int, context: int, vram: float) -> bool:
    return model.weight_bytes(bits) + model.kv_bytes(context) < vram * 0.9


def split(model: Model, bits: int, context: int, vram: float) -> tuple[float, float]:
    """(bytes kept in VRAM, bytes that must come from elsewhere)."""
    total = model.weight_bytes(bits) + model.kv_bytes(context)
    usable = vram * 0.9                       # headroom for activations
    resident = min(total, usable)
    return resident, max(0.0, total - resident)


def fmt(n: float) -> str:
    if n >= GB:
        return f"{n / GB:.1f} GB"
    if n >= MB:
        return f"{n / MB:.0f} MB"
    return f"{n / 1024:.0f} KB"


# --------------------------------------------------------------------------- #
# Reports
# --------------------------------------------------------------------------- #

def report_sizes() -> None:
    print("=" * 78)
    print("1. WHAT HAS TO MOVE")
    print("=" * 78)
    print(f"{'model':<14}{'4-bit wts':>12}{'fp16 wts':>12}"
          f"{'KV @8k':>11}{'KV @128k':>11}")
    for m in MODELS:
        print(f"{m.name:<14}{fmt(m.weight_bytes(4)):>12}{fmt(m.weight_bytes(16)):>12}"
              f"{fmt(m.kv_bytes(8192)):>11}{fmt(m.kv_bytes(131072)):>11}")
    print("\nKV cache per token (fp16, GQA):")
    for m in MODELS:
        print(f"  {m.name:<14}{m.kv_bytes_per_token() / 1024:>8.0f} KB/token")


def report_local_feasibility() -> None:
    print()
    print("=" * 78)
    print("2. WHAT FITS TODAY, WITH NO NETWORK AT ALL  (4-bit, 8k context)")
    print("=" * 78)
    print(f"{'GPU':<20}" + "".join(f"{m.name:>16}" for m in MODELS))
    for gpu, vram in GPUS.items():
        row = f"{gpu:<20}"
        for m in MODELS:
            ok = fits_locally(m, 4, 8192, vram)
            need = m.weight_bytes(4) + m.kv_bytes(8192)
            row += f"{('fits' if ok else 'NO ' + fmt(need)):>16}"
        print(row)
    print("\nEvery 'NO' is a task the user simply cannot perform.")


def report_decode_throughput() -> None:
    print()
    print("=" * 78)
    print("3. DECODE SPEED WHEN THE SHORTFALL COMES OVER A LINK")
    print("=" * 78)
    print("Llama-3 70B, 4-bit, 8k context, on a 24 GB GPU.")
    m = MODELS[1]
    vram = GPUS["RTX 4090 (24 GB)"]
    resident, offloaded = split(m, 4, 8192, vram)
    hbm = TIERS[0]
    print(f"needs {fmt(m.weight_bytes(4) + m.kv_bytes(8192))}, "
          f"has {fmt(vram)} -> {fmt(offloaded)} must come from elsewhere\n")
    print(f"{'tier':<30}{'batch=1':>12}{'batch=8':>12}{'batch=32':>12}")
    for t in TIERS[1:]:
        row = f"{t.name:<30}"
        for b in (1, 8, 32):
            tps = decode_tokens_per_sec(resident, offloaded, hbm, t, batch=b)
            row += f"{tps:>11.2f} "
        print(row)
    print("\nRule of thumb: <0.5 tok/s is unusable, 1-5 tok/s is batch-only,")
    print(">10 tok/s is interactive. Reading speed is roughly 5-8 tok/s.")


# Effective compute for prefill, which is compute-bound rather than
# bandwidth-bound. Dense fp16 peak, derated to a realistic model-FLOPs
# utilisation, because nobody achieves peak.
GPU_TFLOPS = {"RTX 3060 (12 GB)": 25.0, "RTX 4090 (24 GB)": 165.0,
              "A100 (80 GB)": 312.0}
MFU = 0.45


def prefill_seconds(model: Model, context: int, tflops: float) -> float:
    """Time to compute a KV cache from scratch: roughly 2*N*P FLOPs."""
    flops = 2 * model.params_b * 1e9 * context
    return flops / (tflops * 1e12 * MFU)


def report_context_retrieval() -> None:
    print()
    print("=" * 78)
    print("4. THE CASE THAT ACTUALLY FITS OBLIVIO: RETRIEVING STORED CONTEXT")
    print("=" * 78)
    print("Weights that do not fit must stream every token, so 'load once' does")
    print("not apply to them. Where it does apply is a KV cache: a context you")
    print("built before and want back without paying for it again.")
    print()
    print("So the honest comparison is not transfer versus nothing. It is")
    print("TRANSFER versus RECOMPUTE — and recompute is not free.\n")

    m = MODELS[1]
    gpu = "RTX 4090 (24 GB)"
    for context in (8192, 32768, 131072):
        kv = m.kv_bytes(context)
        recompute = prefill_seconds(m, context, GPU_TFLOPS[gpu])
        print(f"  Llama-3 70B, {context:,}-token context "
              f"-> KV cache {fmt(kv)}, recompute {recompute:.0f} s on a 4090")
        for t in (TIERS[2], TIERS[3], TIERS[5], TIERS[6], TIERS[7]):
            secs = kv / t.bps
            verdict = "RETRIEVE" if secs < recompute else "recompute instead"
            print(f"      {t.name:<28}{secs:>8.1f} s   {verdict}")
        print()

    print("  Retrieval wins whenever the link moves the cache faster than the")
    print("  GPU can rebuild it. That threshold rises with context length,")
    print("  because recompute grows linearly while the cache does too — but")
    print("  recompute is paid in scarce GPU time and transfer is not.")


def required_bandwidth(resident: float, offloaded: float, local: Tier,
                       target_tps: float, batch: int) -> float:
    """Bandwidth in GB/s needed to hit a target decode rate. Solved, not sampled."""
    budget = 1.0 / target_tps - resident / local.bps
    if budget <= 0:
        return float("inf")
    return (offloaded / batch) / budget / GB


def report_crossover() -> None:
    print()
    print("=" * 78)
    print("5. CROSSOVER: BANDWIDTH REQUIRED, SOLVED DIRECTLY")
    print("=" * 78)
    print("Llama-3 70B 4-bit, 8k context. How fast must the link be to reach")
    print("a given decode rate, if the shortfall is served over it?\n")
    m = MODELS[1]
    hbm = TIERS[0]
    print(f"{'GPU':<20}{'batch':>7}{'0.5 tok/s':>13}{'1 tok/s':>13}{'5 tok/s':>13}")
    for gpu, vram in GPUS.items():
        resident, offloaded = split(m, 4, 8192, vram)
        if offloaded <= 0:
            print(f"{gpu:<20}{'—':>7}{'fits locally, no link required':>39}")
            continue
        for batch in (1, 32):
            row = f"{gpu:<20}{batch:>7}"
            for target in (0.5, 1.0, 5.0):
                need = required_bandwidth(resident, offloaded, hbm, target, batch)
                row += f"{need:>10.1f} GB/s" if need != float("inf") else f"{'impossible':>13}"
            print(row)
    print()
    print("  For scale: NVMe is 7 GB/s, 100 GbE is 12.5 GB/s, 1 Gbps home")
    print("  fibre is 0.125 GB/s, and residential upload is 0.005 GB/s.")


def report_verdict() -> None:
    print()
    print("=" * 78)
    print("VERDICT — what the numbers actually support")
    print("=" * 78)
    m = MODELS[1]
    vram = GPUS["RTX 4090 (24 GB)"]
    resident, offloaded = split(m, 4, 8192, vram)
    hbm = TIERS[0]

    print("  1. Pooling memory over CONSUMER links: NO, in every mode tested.")
    for t, label in ((TIERS[5], "1 Gbps fibre"), (TIERS[7], "40 Mbps upload")):
        tps = decode_tokens_per_sec(resident, offloaded, hbm, t, 32)
        print(f"       {label:<18} {tps:>6.2f} tok/s even at batch 32")
    print("     And context retrieval loses to simply recomputing the cache.")
    print()

    print("  2. Over links of 1-10 Gbps and above: YES, with batching.")
    need = required_bandwidth(resident, offloaded, hbm, 1.0, 32)
    print(f"       1 tok/s at batch 32 needs {need:.2f} GB/s "
          f"({need * 8:.1f} Gbps).")
    print("       That is a business or colocation link, not a home connection.")
    print()

    print("  3. The contributed resource is NVMe, not VRAM.")
    print("       NVIDIA's own bottom tier is 7 GB/s of SSD. A node serving")
    print("       that tier needs a fast disk and a fast link — not a $30,000")
    print("       accelerator. That is a far easier commons to bootstrap.")
    print()

    print("  4. For Oblivio as it exists, none of this is the constraint.")
    print("       A stored memory is kilobytes, not gigabytes:")
    for size, label in ((4 * 1024, "a note"), (256 * 1024, "a document"),
                        (10 * MB, "a large record")):
        secs = size / TIERS[7].bps
        print(f"       {label:<16}{fmt(size):>10}  ->  {secs * 1000:>7.1f} ms "
              f"even on 40 Mbps upload")
    print("       Record storage is bandwidth-trivial. GPU memory pooling is a")
    print("       different product with different physics, and conflating the")
    print("       two is how this proposal would fail review.")
    print()
    print("  ASSUMPTIONS, so these can be argued with:")
    print("    - Decode is bandwidth-bound; compute time ignored (optimistic).")
    print("    - Recompute assumes the model can run locally at all, which for")
    print("      70B on a 24 GB card it cannot — so that comparison is a bound,")
    print("      not a measurement.")
    print("    - No compression, no quantised KV, no cache reuse across users.")
    print("      Each of those moves the threshold in the network's favour.")


if __name__ == "__main__":
    report_sizes()
    report_local_feasibility()
    report_decode_throughput()
    report_context_retrieval()
    report_crossover()
    report_verdict()
