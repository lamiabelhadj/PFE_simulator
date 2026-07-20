"""
main.py
────────
CLI entry point.

Usage:
    python main.py                         # use defaults from config/settings.py
    python main.py --normal 500 --attack 100
    python main.py --normal 200 --attack 50 --seed 7 --out my_dataset.csv
"""

import argparse
import sys
import time
from pathlib import Path

# Windows consoles default to cp1252, which cannot encode characters like '→'
# used in log/print output across the simulator.
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from simulator.config.settings import cfg, DATA_DIR
from simulator.runner import run_simulation
from simulator.data.exporter import save


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="IoT Auth Simulator")
    p.add_argument("--normal",  type=int,  default=cfg.simulation.num_sessions_normal,
                   help="Number of normal sessions")
    p.add_argument("--attack",  type=int,  default=cfg.simulation.num_sessions_attack,
                   help="Number of attack sessions")
    p.add_argument("--devices", type=int,  default=cfg.simulation.num_devices,
                   help="Size of the device pool")
    p.add_argument("--seed",    type=int,  default=cfg.simulation.random_seed,
                   help="Random seed for reproducibility")
    p.add_argument("--out",     type=str,  default=cfg.simulation.output_filename,
                   help="Output CSV filename")
    p.add_argument("--parquet", action="store_true",
                   help="Also save a Parquet copy")
    p.add_argument("--wire-entities", action="store_true",
                   help="Drive the real core/ domain entities (ECDH, token "
                        "issuance/validation, broker sessions) during generation")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    # Override config with CLI args
    cfg.simulation.num_sessions_normal = args.normal
    cfg.simulation.num_sessions_attack = args.attack
    cfg.simulation.num_devices         = args.devices
    cfg.simulation.random_seed         = args.seed
    cfg.simulation.output_filename     = args.out
    cfg.simulation.wire_entities       = args.wire_entities

    print("=" * 60)
    print("  IoT Authentication Simulator")
    print("=" * 60)
    print(f"  Device pool    : {args.devices}")
    print(f"  Normal sessions: {args.normal}")
    print(f"  Attack sessions: {args.attack}")
    print(f"  Attack split   : {cfg.simulation.attack_distribution}")
    print(f"  Random seed    : {args.seed}")
    print(f"  Wire entities  : {'on' if args.wire_entities else 'off'}")
    print(f"  Output         : {DATA_DIR / args.out}")
    print("=" * 60)

    t0 = time.time()

    def progress(current, total, msg):
        pct = int(current / total * 40)
        bar = "█" * pct + "░" * (40 - pct)
        print(f"\r  [{bar}] {current}/{total}  {msg}          ", end="", flush=True)

    sequences = run_simulation(progress_callback=progress)
    print()

    csv_path = save(sequences, filename=args.out, parquet=args.parquet)

    elapsed = time.time() - t0
    total   = len(sequences)
    normal  = sum(1 for _, ctx in sequences if ctx.attack_type == "normal")
    attack  = total - normal

    print()
    print("=" * 60)
    print(f"  Done in {elapsed:.1f}s")
    print(f"  Total sessions : {total:,}")
    print(f"  Normal         : {normal:,}  ({normal / total * 100:.1f}%)")
    print(f"  Attack         : {attack:,}  ({attack / total * 100:.1f}%)")
    attack_types: dict = {}
    for _, ctx in sequences:
        t = ctx.attack_type
        attack_types[t] = attack_types.get(t, 0) + 1
    for t, c in sorted(attack_types.items()):
        print(f"    {t:<20}: {c:,}")
    print(f"  Dataset        : {csv_path}")
    print("=" * 60)


if __name__ == "__main__":
    main()
