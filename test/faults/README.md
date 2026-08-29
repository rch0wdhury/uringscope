# Fault injection & findings scoring

`inject.c` deliberately induces known io_uring faults and prints
`GROUND-TRUTH` lines stating exactly what it injected. `run.sh` runs each
scenario under uringscope and scores the findings against that
truth. The output is both an integration test and the
detection-effectiveness table.

```sh
make -C ../..            # build uringscope
sudo ./run.sh            # build inject, run all scenarios, PASS/FAIL
```

## Scenarios

| scenario | injects | detector |
|---|---|---|
| `punt N` | N reads forced onto io-wq (IOSQE_ASYNC) | shipped (PUNT) |
| `nobatch N` | N reads at 1 SQE/syscall | shipped (BATCH) |
| `overflow N` | CQ overflow via tiny CQ + no reaping | shipped (OVERFLOW) |
| `errors N` | N res<0 completions (read on bad fd) | shipped (ERRORS) |
| `leak K [S]` | K reads submitted, never completed, held S sec | shipped (LEAK) |
| `sqpoll-stall S` | SQPOLL ring with a sparse duty cycle | shipped (SQPOLL) |
| `worker-storm N` | N io-wq workers pinned at once | shipped (WORKERS) |
| `uaf-reg` | overlapping in-flight reads into one registered buffer | shipped (HAZARD, `--check`) |
| `uaf-reg-lifetime` | buffer index unregistered with live fixed-op refs | shipped (HAZARD-BUFREG, `--check`) |
| `uaf-unmap` | munmap a buffer with a read into it in flight | shipped (HAZARD-UAF, `--check`) |
| `reap-lag MS` | ready CQE left unreaped MS ms | shipped (REAP-LAG, uprobes) |

The three hazard scenarios are scored under `--check` (see
`docs/buffer-hazards.md`). A scenario can be marked FUTURE in `run.sh`
while its detector is designed but not shipped; it then asserts only that
the injection reproduced. Every current row is a full PASS/FAIL
assertion.

## Why injection-with-ground-truth

Detection tools are easy to fool with hand-picked demos. Printing machine
-readable ground truth and scoring against it gives an honest
precision/recall story: a scenario that fails to trip its rule is a FAIL,
and a clean run (`inject nobatch` should NOT trip PUNT) guards against
false positives. Add negative cases (inject X, assert the report does NOT
include Y) as the rule set grows.
