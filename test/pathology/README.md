# Pathology injection & doctor scoring

`pathogen.c` deliberately induces known io_uring pathologies and prints
`GROUND-TRUTH` lines stating exactly what it injected. `run.sh` runs each
scenario under uringscope and scores the doctor's findings against that
truth. The output is both an integration test and the paper's
detection-effectiveness table.

```sh
make -C ../..            # build uringscope
sudo ./run.sh            # build pathogen, run all scenarios, PASS/FAIL
```

## Scenarios

| scenario | injects | doctor tier |
|---|---|---|
| `punt N` | N reads forced onto io-wq (IOSQE_ASYNC) | shipped (PUNT) |
| `nobatch N` | N reads at 1 SQE/syscall | shipped (BATCH) |
| `overflow N` | CQ overflow via tiny CQ + no reaping | shipped (OVERFLOW) |
| `errors N` | N res<0 completions (read on bad fd) | shipped (ERRORS) |
| `leak K [S]` | K reads submitted, never completed, held S sec | shipped (LEAK) |
| `sqpoll-stall S` | SQPOLL ring with a sparse duty cycle | shipped (SQPOLL) |
| `worker-storm N` | N io-wq workers pinned at once | shipped (WORKERS) |
| `uaf-unmap` | munmap a buffer with a read into it in flight | FUTURE (hazard mode) |
| `uaf-reg` | overlapping in-flight writes to one registered buffer; unregister while in flight | FUTURE (hazard mode) |
| `reap-lag MS` | ready CQE left unreaped MS ms | FUTURE (uprobe mode) |

FUTURE scenarios target detectors that are designed but not shipped (see
`docs/buffer-hazards.md`). They assert only that the injection reproduced;
they become full PASS/FAIL assertions when the detector lands. `uaf-unmap`
reliably produces `res=-EFAULT(-14)` today, which is the corruption the
hazard detector will catch *before* it manifests.

## Why injection-with-ground-truth

Detection tools are easy to fool with hand-picked demos. Printing machine
-readable ground truth and scoring against it gives an honest
precision/recall story: a scenario that fails to trip its rule is a FAIL,
and a clean run (`pathogen nobatch` should NOT trip PUNT) guards against
false positives. Add negative cases (inject X, assert doctor does NOT
report Y) as the rule set grows.
