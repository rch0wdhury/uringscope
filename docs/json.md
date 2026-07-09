# The JSON report: schema and stability contract

`--json[=PATH]` emits the full report as one JSON object. This document is
the schema reference; treat it as the tool's machine API. Scripts, CI
gates, and LLM agents should consume this (plus the exit status, see
[Exit status](#exit-status-and---fail-on)) rather than parsing the human
tables, which may be reformatted at any time.

## Versioning

The top-level `schema` field is the contract:

* Within a schema number, changes are **additive only**: new keys, new
  counters, new doctor tags, new evidence keys. Consumers must accept
  unknown keys.
* Renaming or removing a key, changing a type, or changing the meaning of
  an existing tag bumps `schema`.
* Doctor **tags** (`PUNT`, `BATCH`, ...) are stable identifiers. New tags
  may be added within a schema version; existing tags are never renamed
  without a bump.

Current schema: **1**.

## Top-level object

| key | type | meaning |
|---|---|---|
| `tool` | string | always `"uringscope"` (baseline files are sniffed on this) |
| `schema` | int | schema version, see above |
| `tool_version` | string | uringscope version |
| `wall_ns` | int | observation window, nanoseconds |
| `completion_coarse` | bool | `true` when the kernel only supports the count-only completion fallback: per-op latency and the leak scan are unavailable (5.15 legacy tier) |
| `counters` | object | global counters, see glossary below |
| `rings` | array | one object per observed ring: `fd`, `comm`, `sq_entries`, `cq_entries`, `flags` (raw `IORING_SETUP_*` bits), `sqpoll` (bool) |
| `ops` | array | per-opcode stats, see below |
| `leak` | object | `suspected` (aged past threshold), `pending` (younger, likely still in progress), `oldest_ns` |
| `hazards` | object | `--check` totals: `overlap`, `bufreg`, `unmap` (all 0 unless `--check`) |
| `end_to_end` | object | liburing-uprobe boundary data; `available: false` means the uprobes never attached (static link, stripped, or no liburing) and all other keys are absent |
| `doctor` | array | findings, see below |

### `counters` glossary

All values are totals over the window.

| key | meaning |
|---|---|
| `enter_calls` | `io_uring_enter()` syscalls |
| `to_submit_sum` | sum of `to_submit` across enters |
| `ret_submitted_sum` | sum of successful enter() return values |
| `submissions` | SQEs seen at the submit tracepoint |
| `completions` | CQEs seen at the complete tracepoint |
| `punted` | requests punted to io-wq async workers |
| `cq_overflows` | CQ overflow events |
| `poll_armed` | requests parked on the poll-retry path |
| `task_work_runs`, `task_work_items` | task-work delivery batches / items |
| `local_task_work_runs` | DEFER_TASKRUN local task work runs |
| `multishot_cqes` | completions flagged `IORING_CQE_F_MORE` |
| `untracked_completions` | completions with no matching submit record (fidelity metric) |
| `inflight_map_drops` | submits not tracked because the in-flight map was full (fidelity metric) |
| `trace_rb_drops` | `--trace` events lost because the ring buffer was full (fidelity metric; 0 outside trace mode) |
| `short_writes` | `io_uring_short_write` events |
| `sqpoll_offcpu_ns`, `sqpoll_switches` | SQPOLL thread off-CPU time / context switches |
| `workers_distinct` | distinct io-wq worker threads observed |
| `rings_created` | rings created while tracing |
| `cq_depth_samples`, `cq_depth_sum`, `cq_depth_max` | CQ occupancy sampling |
| `errors` | completions with `res < 0` (excluding `-EAGAIN`) |
| `hazard_overlaps`, `hazard_bufreg`, `hazard_unmap` | `--check` hazard counts |

### `ops[]` entries

```json
{"op": "READ", "opcode": 22, "submitted": 1000, "completed": 1000,
 "punted": 0, "errors": 0, "avg_ns": 8123, "p50_ns": 8192, "p99_ns": 16384}
```

Latency is kernel submit→complete. Percentiles are log2-bucket upper
bounds (so always powers of two): they answer "under which power of two",
not "exactly which nanosecond".

## `doctor[]` findings

Each finding:

```json
{
  "tag": "PUNT",
  "severity": "WARN",
  "message": "34.1% of requests fell back to the io-wq async worker pool (341 of 1000). ...",
  "suggestion": "Identify the punting opcode (per-op findings follow); ...",
  "evidence": {"punt_pct": 34.100, "punted": 341, "submitted": 1000}
}
```

* `tag` — stable rule identifier (registry below).
* `severity` — `CRIT` | `WARN` | `INFO`.
* `message` — the complete human sentence, identical to the terminal
  output. Do not parse numbers out of it; they are in `evidence`.
* `suggestion` — the action, when the rule has one. Optional.
* `evidence` — machine-readable numbers/strings backing the finding.
  Optional. Keys are per-tag (below); values are integers, decimals, or
  strings. `user_data`/`base` values are decimal integers here even where
  the message prints hex.

A tag can appear multiple times: detail findings (per-opcode punt
breakdown, individual hazard samples, leak samples) repeat the parent's
tag and carry their own evidence. Order is stable: a parent summary
precedes its details.

### Tag registry (schema 1)

| tag | severity | fires when | evidence keys |
|---|---|---|---|
| `OVERFLOW` | CRIT | CQ overflowed | `overflows`, `cq_entries` |
| `PUNT` | WARN | ≥5% of ≥100 submits punted to io-wq; detail rows per opcode ≥20% punts | `punt_pct`, `punted`, `submitted`; details add `op` |
| `WORKERS` | WARN | distinct io-wq workers > min(2×CPUs, 32) | `workers`, `cpus` |
| `BATCH` | INFO | <1.5 SQEs per enter over ≥1000 calls | `sqes_per_enter`, `enter_calls` |
| `SQPOLL` | WARN / INFO | sqpoll >25% off-CPU (WARN); never switched, i.e. busy-polling a core (INFO) | `offcpu_pct` (WARN form) |
| `DEFER-TW` | WARN | DEFER_TASKRUN ring but local task work never ran | `completions` |
| `SHORT-WRITE` | INFO | short writes seen | `short_writes` |
| `ERRORS` | WARN | >1% of ≥100 completions errored | `error_pct`, `errors`, `completions` |
| `LEAK` | WARN | requests submitted, never completed, older than the threshold | `leaked`, `polled`, `pending`, `oldest_s`, `threshold_s`; details add `op`, `count` or `user_data` |
| `HAZARD` | CRIT | `--check`: overlapping in-flight buffer ranges | `overlaps`; samples add `op_a`, `user_data_a`, `op_b`, `user_data_b`, `base`, `len`, `bufidx` |
| `HAZARD-BUFREG` | CRIT | `--check`: buffer index unregistered with live in-flight references | `bufidx`, `live_refs` |
| `HAZARD-UAF` | CRIT | `--check`: munmap over an in-flight request's target | `base`, `len`, `op`, `user_data` |
| `REAP-LAG` | WARN | CQEs sat ready >500µs (p99) before the app reaped them | `avg_ns`, `p99_ns`, `samples` |
| `TOOL` | INFO | uringscope's own fidelity degraded (map full, untracked completions, trace drops) | `inflight_map_drops` / `untracked_completions` / `trace_rb_drops` |

`TOOL` findings are self-reports about measurement quality, not workload
pathologies; they are excluded from the `--fail-on` gate.

## Exit status and `--fail-on`

`--fail-on info|warn|crit` turns the doctor's verdict into the exit
status, so a gate needs no parsing at all:

```sh
uringscope --json=report.json --fail-on=warn -p "$PID" -d 10
case $? in
  0) ;;                        # ran fine, nothing at/above warn
  3) alert < report.json ;;    # doctor found something
  *) echo "uringscope or workload failed" ;;
esac
```

Precedence (first match wins):

1. **1** — uringscope itself failed (setup, BPF load, bad arguments).
2. **N** — a spawned command exited nonzero: its status propagates and
   outranks the gate (CI should see the workload's own failure).
3. **3** — the doctor reported a finding at or above the `--fail-on`
   threshold (`TOOL` excluded).
4. **0** — otherwise.

`--fail-on` requires the doctor and is rejected alongside `--no-doctor`.

## Baselines and diffs

`--baseline FILE` writes this same JSON object; `--diff FILE` reads one
back and prints a delta table. The reader is a purpose-built scanner for
this format, not a general JSON parser — another reason renames require a
schema bump.
