# SPDX-License-Identifier: MIT
"""Compare uringscope's JSON counters with CQEs actually reaped by the app."""
import json
import os
from pathlib import Path
import re
import select
import subprocess
import sys
import tempfile

scope, repro = map(os.path.abspath, sys.argv[1:])


def check(mode, background=False, trace=False):
    sibling = None
    try:
        if background:
            sibling = subprocess.Popen(
                [repro, "continuous", "10000000"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            )
            assert select.select([sibling.stdout], [], [], 5)[0], "sibling startup"
            assert sibling.stdout.readline() == "READY continuous\n", "sibling failed"
        with tempfile.TemporaryDirectory(prefix="uringscope-multishot-") as tmp:
            report = Path(tmp) / "report.json"
            timeline = Path(tmp) / "trace.json"
            args = [scope, "--json=" + str(report)]
            if trace:
                args += ["--trace", str(timeline)]
            proc = subprocess.run(
                args + ["--", repro, mode, "32" if trace else "3000"],
                text=True, capture_output=True, timeout=45,
            )
            if proc.returncode:
                raise RuntimeError(proc.stdout + proc.stderr)
            gt = next(line.removeprefix("GROUND-TRUTH ")
                      for line in proc.stdout.splitlines()
                      if line.startswith("GROUND-TRUTH "))
            gt, data = json.loads(gt), json.loads(report.read_text())
            counters = data["counters"]
            for name, expected in (
                ("submissions", gt["submitted"]),
                ("completions", gt["completed"]),
                ("multishot_cqes", gt["more"]),
                ("errors", gt["enobufs"]),
                ("multishot_enobufs", 0 if mode in ("single", "duplicate")
                 else gt["enobufs"]),
                ("untracked_completions", gt["more"] if mode == "duplicate" else 0),
                ("aux_index_drops", 0),
            ):
                assert counters[name] == expected, (mode, name, expected, counters)
            tags = {finding["tag"] for finding in data["findings"]}
            assert ("ERRORS" in tags) == (mode in ("single", "duplicate")), tags
            if mode != "single":
                assert "BATCH" not in tags, tags
            op = next(op for op in data["ops"] if op["op"] == gt["op"])
            assert op["submitted"] == gt["submitted"], op
            assert op["completed"] == (gt["submitted"] if mode == "duplicate"
                                       else gt["completed"]), op
            assert op["errors"] == gt["enobufs"], op
            # The text report must not subtract MORE CQEs as retired SQEs.
            pending = re.search(r"inflight at exit: (-?\d+)", proc.stdout)
            if pending:
                assert int(pending.group(1)) == 0, proc.stdout
            if trace:
                assert counters["trace_rb_drops"] == 0, counters
                events = json.loads(timeline.read_text())["traceEvents"]
                phases = [event["ph"] for event in events]
                assert phases.count("b") == gt["submitted"], phases
                assert phases.count("n") == gt["more"], phases
                assert phases.count("e") == gt["submitted"], phases
                active = set()
                for event in events:
                    phase, key = event["ph"], event.get("id")
                    if phase == "b":
                        assert key not in active, event
                        active.add(key)
                    elif phase in ("n", "e"):
                        assert key in active, event
                        assert event["args"]["multishot"] == (phase == "n"), event
                        if phase == "e":
                            active.remove(key)
                assert not active, active
            print(f"PASS {mode}{' with foreign multishot traffic' if background else ''}: "
                  f"{gt['completed']} CQEs, {gt['more']} MORE"
                  f"{'; trace spans balanced' if trace else ''}", flush=True)
    finally:
        if sibling is not None:
            sibling.terminate()
            sibling.wait(timeout=5)


for mode in ("recv", "read", "continuous", "duplicate", "two-rings", "single"):
    check(mode)
check("recv", background=True)
check("recv", trace=True)
