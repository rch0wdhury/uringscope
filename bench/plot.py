#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Summarize bench/results/ into the overhead-vs-fidelity table.

Reads the per-cell artifacts collect.sh drops (fio JSON + sys JSON) and
prints, per workload x observer: fio IOPS and p99 completion latency
(mean over runs), CPU cost relative to the baseline cells, and the
observer's own output byte rate. stdlib only -- no pandas needed.

  ./plot.py [results-dir]            # table to stdout
  ./plot.py [results-dir] --csv F    # also write a CSV
"""
import csv
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path


def fio_read_stats(path):
    """(iops, p99_clat_ns) from a fio --output-format=json file."""
    with open(path) as f:
        data = json.load(f)
    job = data["jobs"][0]
    rw = job["read"] if job["read"]["iops"] > 0 else job["write"]
    pct = rw.get("clat_ns", {}).get("percentile", {})
    p99 = next((v for k, v in pct.items() if k.startswith("99.0")), 0)
    return rw["iops"], p99


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    results = Path(args[0] if args else Path(__file__).parent / "results")
    csv_path = None
    if "--csv" in sys.argv:
        csv_path = sys.argv[sys.argv.index("--csv") + 1]

    # cells[(workload, observer)] -> list of per-run dicts
    cells = defaultdict(list)
    for sysf in sorted(results.glob("*.sys.json")):
        with open(sysf) as f:
            meta = json.load(f)
        # tag = workload.observer.rN
        workload, observer, run = meta["cell"].rsplit(".", 2)
        fiof = results / f"{meta['cell']}.fio.json"
        if not fiof.exists():
            continue
        try:
            iops, p99 = fio_read_stats(fiof)
        except (KeyError, json.JSONDecodeError):
            print(f"skipping {fiof}: unparseable fio json", file=sys.stderr)
            continue
        cells[(workload, observer)].append({
            "iops": iops, "p99_ns": p99,
            "jiffies": meta.get("cpu_jiffies", 0),
            "obs_bytes": meta.get("obs_bytes", 0),
        })

    if not cells:
        sys.exit(f"no cells found under {results} (run collect.sh first)")

    rows = []
    for (workload, observer), runs in sorted(cells.items()):
        base = cells.get((workload, "baseline"))
        base_j = statistics.mean(r["jiffies"] for r in base) if base else 0
        base_i = statistics.mean(r["iops"] for r in base) if base else 0
        iops = statistics.mean(r["iops"] for r in runs)
        rows.append({
            "workload": workload,
            "observer": observer,
            "runs": len(runs),
            "iops": iops,
            "iops_vs_base_pct":
                100.0 * (iops - base_i) / base_i if base_i else 0.0,
            "p99_us":
                statistics.mean(r["p99_ns"] for r in runs) / 1e3,
            "cpu_vs_base_pct": (100.0 * (statistics.mean(
                r["jiffies"] for r in runs) - base_j) / base_j)
                if base_j else 0.0,
            "obs_mb": statistics.mean(
                r["obs_bytes"] for r in runs) / 1e6,
        })

    hdr = (f"{'workload':<24} {'observer':<13} {'runs':>4} {'IOPS':>12} "
           f"{'vs base':>8} {'p99(us)':>9} {'cpu vs base':>12} {'out MB':>8}")
    print(hdr)
    print("-" * len(hdr))
    for r in rows:
        print(f"{r['workload']:<24} {r['observer']:<13} {r['runs']:>4} "
              f"{r['iops']:>12,.0f} {r['iops_vs_base_pct']:>+7.1f}% "
              f"{r['p99_us']:>9.1f} {r['cpu_vs_base_pct']:>+11.1f}% "
              f"{r['obs_mb']:>8.1f}")

    if csv_path:
        with open(csv_path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=rows[0].keys())
            w.writeheader()
            w.writerows(rows)
        print(f"\nwrote {csv_path}")


if __name__ == "__main__":
    main()
