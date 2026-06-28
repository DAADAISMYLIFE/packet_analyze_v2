# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Full pipeline: pcap → Suricata → Zeek → evidence package
./scripts/analyze.sh pcaps/<file>.pcap

# Run Suricata only
bash scripts/run_suricata.sh pcaps/<file>.pcap

# Run Zeek only
bash scripts/run_zeek.sh pcaps/<file>.pcap

# Compress only (when Zeek/Suricata output already exists)
python3 scripts/compress.py <name> --pkts <N> --md
#   --top N : top-N per list (default 20)
#   --md    : also write human-readable .md

# LLM verdict (requires vLLM running, e.g. on Colab)
python3 scripts/llm_analyze.py <name> --base-url http://localhost:8000/v1 \
    --model Qwen/Qwen2.5-7B-Instruct-AWQ

# Dry-run: validate prompt wiring without an LLM
python3 scripts/llm_analyze.py <name> --dry-run

# Test drill-down tools standalone
python3 scripts/tools.py <name>
```

Python has no external dependencies — stdlib only.

## Architecture

The pipeline is split into two environments:

```
[Local PC — no GPU needed]              [Colab T4 — GPU needed]
analyze.sh → evidence.json  ─GitHub→   llm_analyze.py → verdict.json
```

`report/*.evidence.json` is the only artifact committed to git. `pcaps/`, `output/`, and `.md` reports are gitignored.

### Three-stage pipeline

**Stage 1 — Collect** (`run_suricata.sh`, `run_zeek.sh`)
- Suricata (local install, ET Open rules): signature detection → `output/suricata/<name>/eve.json`
- Zeek (Docker `zeek/zeek:latest`): flow structuring → `output/zeek/<name>/*.log` + `extract_files/`
- Both tools run with `community_id` enabled at seed=0 so alerts can be joined to flows by hash.
- Both scripts clean their output directory before running to prevent log accumulation across re-runs.
- `analyze.sh` uses `set -uo pipefail` (no `-e`): each stage runs regardless of prior failures; final status is recorded in the evidence package, not as a shell exit code.

**Stage 2 — Compress** (`compress.py`)
Deterministically compresses tens of MB of logs into a ~4.5K-token evidence package (JSON). No LLM or randomness involved — same input always produces same output.

Two-layer structure with fallback:
- **Layer 1 (backbone, protocol-agnostic):** Suricata alert dedup/classification, conn.log statistics, beacon/scan/lateral-movement detectors
- **Layer 2 (enrichment, when present):** dedicated compressors for http/dns/files/ssl logs
- **Fallback:** `generic()` handles any unregistered log type by summarizing row count + top values

Alert classification uses prefix matching (`ET MALWARE` → threat, `ET HUNTING` → suspicious, etc.) with Suricata severity as a backstop for unmatched prefixes, so novel signatures don't silently fall into the noise buckets.

Detection thresholds are constants at the top of `compress.py` (`BEACON_MIN_CONNS`, `BEACON_CV_MAX`, `SCAN_MIN_PORTS`, `LATERAL_PORTS`, `NOISE_BUCKET_LIMIT`).

**Stage 3 — LLM verdict** (`llm_analyze.py` + `tools.py`)
- LLM receives a slim evidence package (summary + timeline + host profiles + malware hashes).
- If it needs more detail, it calls drill-down tools in `tools.py` via OpenAI-compatible function calling (`DrillDownTools` class, 7 tools).
- Verdict is submitted via a `submit_verdict` tool call (structured output, never free text).
- `needs_review` is enforced by code, not by the LLM: any `confidence != high` or `classification == unknown_anomaly` sets it to `true`.

### Key data flow invariant

`community_id` is the join key between Suricata alerts and Zeek conn/http/dns/ssl logs. This is why both tools are configured with the same seed. `build_timeline()` in `compress.py` anchors alert timestamps to actual conn.log timestamps via this key — the LLM never invents timestamps.

### Status values (`meta.status`)

| Value | Meaning |
|---|---|
| `OK` | Input parsed and flows extracted |
| `FAILED_TO_PARSE` | libpcap could not read the capture format |
| `NO_IP_FLOWS` | Capture readable but contains no IP flows |

These prevent a broken input from appearing as a clean "no threats found" result.

## Environment requirements

- Suricata 8.0.5 (local install, ET Open rules, `suricata` group membership required)
- Zeek 8.2.0 via Docker (`zeek/zeek:latest`)
- Python 3 (stdlib only — no pip installs needed)
- `tcpdump` for packet count in `analyze.sh`
- Colab with T4 GPU for LLM verdict step (`notebooks/colab_llm.ipynb` bootstraps vLLM + Qwen2.5-7B)
