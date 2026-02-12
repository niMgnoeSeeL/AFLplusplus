# AFL++ Custom Mutator Sampling Guide

**Complete reference for understanding the sampling mechanism in `custom_post_run.c` and `custom_post_run_gtonly_efficient.c`**

---

## Table of Contents

1. [Quick Overview](#quick-overview)
2. [Key Concepts](#key-concepts)
3. [Visual Explanation](#visual-explanation)
4. [Variable Reference](#variable-reference)
5. [Line-by-Line Code Trace](#line-by-line-code-trace)
6. [State Transitions](#state-transitions)
7. [Deep Dive: Double-Buffering](#deep-dive-cov_per_sample_store-double-buffering)
8. [Summary](#summary)

---

# Quick Overview

## What is Sampling?

Both mutators implement **batched sampling**: multiple fuzzer executions within a time interval are aggregated into a **single sample**.

```
Per-Interval Mode (sample_interval = 5s):
┌─────────────────────────┐  ┌─────────────────────────┐
│ Exec 1, 2, 3, ..., 100  │  │ Exec 101, 102, ..., 200 │
└─────────────────────────┘  └─────────────────────────┘
         Sample 1                     Sample 2

100 executions → 1 sample    100 executions → 1 sample
```

## Why Sampling?

1. **Memory efficiency**: Track samples instead of individual executions
2. **Statistical estimation**: Count singletons per sample for Good-Turing estimator
3. **Ground truth**: Evaluate retrospectively how much coverage remained undiscovered
4. **Flexible granularity**: Adjust `sample_interval` to balance precision vs. overhead

## Two Operating Modes

| Mode | Config | Behavior | Ratio |
|------|--------|----------|-------|
| **Per-Execution** | `sample_interval = 0` | Each exec = 1 sample | `n_samples = n_execs` |
| **Per-Interval** | `sample_interval > 0` | Aggregate execs over time | `n_samples < n_execs` |

---

# Key Concepts

## The Core Idea

**Multiple executions** within a time window **accumulate** their coverage into temporary buffers. When the time interval elapses, these buffers are **finalized** as a single sample and then **reset** for the next period.

```
ACCUMULATION PHASE          FINALIZATION PHASE       RESET PHASE
┌──────────────┐            ┌───────────────┐        ┌─────────────┐
│ Exec 1 → buf │            │ Save buf data │        │ buf = NULL  │
│ Exec 2 → buf │    →       │ n_samples++   │   →    │ Ready for   │
│ Exec 3 → buf │            │ Merge to perm │        │ next sample │
└──────────────┘            └───────────────┘        └─────────────┘
```

## Key Variables by Purpose

### Timing Control
- **`sample_interval`**: Seconds between samples (0 = per-exec mode)
- **`last_sglt_clust_update_time`**: When last sample finished

### Accumulators (Reset Each Sample)
- **`curr_covered`**: All coverage in current sample period
- **`curr_sglt_clust`**: New singletons in current sample period
- **`cov_per_sample_live`**: Coverage intensity accumulator

### Permanent Storage
- **`n_samples`**: Total samples (★ incremented at line 325)
- **`n_execs`**: Total executions
- **`covered_prev`**: Cumulative coverage (all samples)
- **`cov_per_sample_store`**: Saved intensity (double-buffer)

---

# Visual Explanation

## Timeline View (sample_interval = 5 seconds)

```
TIME:      0s    1s    2s    3s    4s    5s    6s    7s    8s    9s   10s
           │     │     │     │     │     │     │     │     │     │     │
EXECS:     ●     ●●    ●     ●●●   ●     │     ●     ●     ●●    ●     ●
           │     ││    │     │││   │     │     │     │     ││    │     │
           └─────┴─────┴─────┴─────┘     └─────┴─────┴─────┴─────┘
           ╰────── SAMPLE 1 ──────╯      ╰────── SAMPLE 2 ──────╯

Coverage:  {A}  {A,B} {C}  {A,D,E}{F}   │    {G}   {H}  {G,I} {J}   {K}
           │                             │
           v                             v
Accumulated: {A,B,C,D,E,F}              {G,H,I,J,K}
           │                             │
           v                             v
n_samples++                          n_samples++
(n_samples=1)                        (n_samples=2)
```

## Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                  SAMPLE PERIOD (0s - 5s)                    │
└─────────────────────────────────────────────────────────────┘

Execution 1 (0s):                    Execution 2 (1s):
┌──────────────┐                     ┌──────────────┐
│ Coverage: A  │────┐                │Coverage: A,B │────┐
└──────────────┘    │                └──────────────┘    │
                    v                                    v
              ┌──────────────┐                    ┌──────────────┐
              │curr_covered: │                    │curr_covered: │
              │    {A}       │                    │   {A,B}      │
              ├──────────────┤                    ├──────────────┤
              │curr_sglt_    │                    │curr_sglt_    │
              │  clust: {A}  │                    │  clust: {A,B}│
              └──────────────┘                    └──────────────┘

Execution 3 (2s):                    Execution 4 (3s):
┌──────────────┐                     ┌──────────────┐
│ Coverage: C  │────┐                │Coverage:A,D,E│────┐
└──────────────┘    │                └──────────────┘    │
                    v                                    v
              ┌──────────────┐                    ┌──────────────┐
              │curr_covered: │                    │curr_covered: │
              │  {A,B,C}     │                    │ {A,B,C,D,E}  │
              ├──────────────┤                    ├──────────────┤
              │curr_sglt_    │                    │curr_sglt_    │
              │clust:{A,B,C} │   (A seen again)   │clust:{B,C,D,E}│
              └──────────────┘    (A removed)     └──────────────┘

Execution 5 (4s):
┌──────────────┐
│ Coverage: F  │────┐
└──────────────┘    │
                    v
              ┌────────────────┐
              │curr_covered:   │
              │{A,B,C,D,E,F}   │  ◄── Accumulating ALL coverage
              ├────────────────┤
              │curr_sglt_clust:│
              │{B,C,D,E,F}     │  ◄── Only NEW singletons
              └────────────────┘

                    │
                    │ Time reaches 5s
                    │ (get_cur_time() - last_sglt_clust_update_time >= 5000)
                    v

         ┌─────────────────────────────┐
         │ update_singleton_clusters() │
         └─────────────────────────────┘
                    │
                    ├─► n_samples++ (n_samples = 1)  ★ SAMPLE CREATED
                    │
                    ├─► cov_per_sample_unique = |curr_covered| = 6
                    │
                    ├─► Move curr_covered → covered_prev
                    │   covered_prev = covered_prev ∪ {A,B,C,D,E,F}
                    │
                    ├─► Save curr_sglt_clust as singleton cluster #1
                    │   sglt_clusts = [{B,C,D,E,F}]
                    │   n_sglt_clusts = 1
                    │
                    ├─► cov_per_sample_store = cov_per_sample_live
                    │
                    └─► RESET accumulators for next sample:
                        curr_covered = NULL
                        curr_sglt_clust = NULL
                        cov_per_sample_live = 0

┌─────────────────────────────────────────────────────────────┐
│              NEW SAMPLE PERIOD (5s - 10s)                   │
│                  (Process repeats...)                       │
└─────────────────────────────────────────────────────────────┘
```

## Example Scenario

**Setup:**
- `sample_interval = 10` seconds
- Fuzzer runs at ~100 execs/sec
- Sample period sees ~1000 executions

**Result:**
```
┌───────────────────────────────────────────────────────────┐
│ Time Window: 0s - 10s                                     │
├───────────────────────────────────────────────────────────┤
│ Executions: 1000                                          │
│                                                           │
│ ┌─────────────────────────────────────────────────────┐  │
│ │ Exec 1:   Coverage = {edge_1, edge_5, edge_20}     │  │
│ │ Exec 2:   Coverage = {edge_1, edge_7}              │  │
│ │ Exec 3:   Coverage = {edge_5, edge_12}             │  │
│ │ ...                                                │  │
│ │ Exec 1000: Coverage = {edge_5, edge_100}           │  │
│ └─────────────────────────────────────────────────────┘  │
│                         │                                 │
│                         v                                 │
│              ┌──────────────────┐                         │
│              │ Accumulated in:  │                         │
│              │  curr_covered =  │                         │
│              │  {edge_1, edge_5,│                         │
│              │   edge_7, edge_12│                         │
│              │   ..., edge_100} │                         │
│              └──────────────────┘                         │
└───────────────────────────────────────────────────────────┘
                        │
                        v (10 seconds elapsed)
                ┌───────────────┐
                │ Sample #1     │
                │ n_samples = 1 │
                │ n_execs = 1000│
                └───────────────┘

Result: 1000 executions → 1 sample
Ratio:  n_samples / n_execs = 1/1000 = 0.001
```

---

# Variable Reference

## File: custom_post_run_gtonly_efficient.c

### Complete Variable Table

#### 1. Timing Variables
| Variable | Type | Location | Purpose |
|----------|------|----------|---------|
| `sample_interval` | `u32` | `afl->sample_interval` | Interval in seconds (0=per-exec, >0=per-interval) |
| `last_sglt_clust_update_time` | `u64` | Line 99 (my_mutator_t) | Timestamp of last sample finalization |

#### 2. Accumulator Variables (Per Sample)
| Variable | Type | Location | Purpose |
|----------|------|----------|---------|
| `curr_covered` | `SimpleSet*` | Line 72 (covmanager_t) | Accumulates coverage during sample period |
| `curr_sglt_clust` | N/A | (not in gtonly) | (Only in custom_post_run.c) |
| `cov_per_sample_live` | `unsigned long` | Line 74 (covmanager_t) | Running sum of coverage intensity |

#### 3. Saved/Permanent Variables
| Variable | Type | Location | Purpose |
|----------|------|----------|---------|
| `n_samples` | `u32` | Line 68 (covmanager_t) | **Total samples taken** |
| `n_execs` | `u32` | Line 69 (covmanager_t) | Total executions |
| `covered_prev` | `SimpleSet*` | Line 70 (covmanager_t) | All coverage seen so far (cumulative) |
| `cov_per_sample_unique` | `unsigned long` | Line 73 (covmanager_t) | Unique edges in last sample |
| `cov_per_sample_store` | `unsigned long` | Line 74 (covmanager_t) | Intensity from last sample |

### Where Each Variable Changes

| Variable | Initialized | Read | Written | Purpose |
|----------|-------------|------|---------|---------|
| `n_samples` | Line 143: `= 0` | Line 768: CSV output | **Line 325: `++`** ← SAMPLE COUNT | Count samples |
| `n_execs` | Line 144: `= 0` | Lines 564, 607, 831 | **Line 505: `++`** | Count executions |
| `curr_covered` | Line 147: `= NULL` | Lines 309, 334, 342, 345, 349 | **Line 309: `set_add()`**<br>**Line 353: `= NULL`** | Accumulate coverage |
| `covered_prev` | Line 146: `set_init()` | Lines 317, 610, 612, 640 | **Line 344: `set_add()`** | Cumulative coverage |
| `cov_per_sample_live` | Line 150: `= 0` | Line 350 | **Line 551: `+=`**<br>**Line 351: `= 0`** | Accumulate intensity |
| `cov_per_sample_store` | Line 149: `= 0` | Line 651 | **Line 350: `=`** | Save last intensity |
| `cov_per_sample_unique` | Line 148: `= 0` | Line 649 | **Line 349: `=`** | Save unique edges |
| `last_sglt_clust_update_time` | Line 238: `get_cur_time()` | **Line 557: check** | **Line 574: `get_cur_time()`** | Time next sample |
| `sample_interval` | AFL config | **Lines 556, 558, 580** | N/A (read-only) | Config: interval |

---

# Line-by-Line Code Trace

## INITIALIZATION

### Lines 141-153: `covmanager_init()`
```c
141  covmanager_t *covmanager_init(void) {
142    covmanager_t *covman = (covmanager_t *)malloc(sizeof(covmanager_t));
143    covman->n_samples = 0;              // ← Initialize sample counter to 0
144    covman->n_execs = 0;                // ← Initialize exec counter to 0
145    covman->covered_prev = (SimpleSet *)malloc(sizeof(SimpleSet));
146    set_init(covman->covered_prev);     // ← Empty set for cumulative coverage
147    covman->curr_covered = NULL;        // ← No current sample yet
148    covman->cov_per_sample_unique = 0;  // ← No metrics yet
149    covman->cov_per_sample_store = 0;   // ← No stored intensity
150    covman->cov_per_sample_live = 0;    // ← No live accumulator
151    return covman;
152  }
```

**Variables initialized:**
- `n_samples = 0` (no samples yet)
- `n_execs = 0` (no executions yet)
- `curr_covered = NULL` (will be created on first execution)
- `cov_per_sample_live = 0` (accumulator starts at 0)

### Lines 238-243: `afl_custom_init()`
```c
238    data->last_sglt_clust_update_time = get_cur_time();  // ← Set initial timestamp
239    data->records = NULL;
240    data->records_len = 0;
241    data->force_save = false;
242    data->last_record_add_time = get_cur_time();
243    data->last_record_write_time = get_cur_time();
```

**Variables initialized:**
- `last_sglt_clust_update_time = current_time` (start timer)

---

## EXECUTION PHASE (Each Fuzzer Run)

### Line 496: Entry point - `afl_custom_post_run()`
```c
496  void afl_custom_post_run(my_mutator_t *data) {
```

### Line 505: Increment execution counter
```c
505    data->covman_total->n_execs++;  // ← n_execs++ (count this execution)
```
**WRITE: `n_execs`** - Incremented every time this function is called

### Lines 534-537: Initialize accumulator if needed
```c
534    if (!data->covman_total->curr_covered) {
535      data->covman_total->curr_covered = (SimpleSet *)malloc(sizeof(SimpleSet));
536      set_init(data->covman_total->curr_covered);  // ← Create empty accumulator
537    }
```
**WRITE: `curr_covered`** - Created on first execution of sample period

### Lines 539-553: Accumulate coverage from this execution
```c
539    for (i = 0; i < data->afl->fsrv.map_size; i++) {
540      // if the trace bit is nonzero, then this has been covered in this run
541      if (data->afl->fsrv.trace_bits[i]) {
542        const char *key = idx_to_str(i);
543        // update covmanager:
544        // if the key was not in covered_prev, add it as a new singleton
545        // if the key was in singletons, remove it from singletons
546        is_update = update_covmanager(data->covman_total, key) || is_update;
                     // └─► Calls line 308 ───┘
547  #ifndef IGNORE_FINDS
548        is_update = update_covmanager(data->covman_reset, key) || is_update;
549        is_update = update_covmanager(covman_curr, key) || is_update;
550  #endif
551        data->covman_total->cov_per_sample_live += data->afl->fsrv.trace_bits[i];
              // └─► WRITE: cov_per_sample_live (accumulate intensity)
552      }
553    }
```

**Line 546** calls → **Line 308-320: `update_covmanager()`**
```c
308  bool update_covmanager(covmanager_t *covman, const char *key) {
309    set_add(covman->curr_covered, key); // ← WRITE: curr_covered (add this edge)
310                                        // maintain the covered set during the
311                                        // sampling period for the ground truth
312                                        // computation. This will be reset every
313                                        // update_singleton_clusters call, where
314                                        // sampling period ends and samples are
315                                        // gathered.
316    bool add_new_record = false;
317    if (set_contains(covman->covered_prev, key) == SET_FALSE) {
              // └─► READ: covered_prev (check if new coverage)
318      add_new_record = true;
319    }
320    return add_new_record;
321  }
```

**For EACH execution in the sample period:**
- **WRITE: `curr_covered`** (line 309) - Add edges to accumulator
- **READ: `covered_prev`** (line 317) - Check if edge is new
- **WRITE: `cov_per_sample_live`** (line 551) - Add to intensity counter

---

## SAMPLE FINALIZATION PHASE

### Lines 554-575: Check if sample period ended
```c
554    // if per execution sampling, or per interval sampling and the sampling
555    // interval came, update singleton clusters
556    if (data->afl->sample_interval == 0 || (
              // └─► READ: sample_interval
557          get_cur_time() - data->last_sglt_clust_update_time >=
                              // └─► READ: last_sglt_clust_update_time
558          data->afl->sample_interval * 1000)) {
                           // └─► READ: sample_interval (convert to milliseconds)
559      // flag up the check_new for all records. this recording for the missing
560      // mass analysis only done until the number of executions is doubled.
561      record_t *curr_record = data->records;
562      record_t *iter_record = curr_record;
563      while (iter_record && iter_record->execs * 2
564             >= data->covman_total->n_execs) {
                                  // └─► READ: n_execs
565        iter_record->check_new = true;
566        iter_record = iter_record->prev;
567      }
568      record_t *stop_record = iter_record;
569      update_singleton_clusters(data->covman_total, curr_record, stop_record);
            // └─► Calls line 322 ───────────────┘
570  #ifndef IGNORE_FINDS
571      update_singleton_clusters(data->covman_reset, curr_record, stop_record);
572      update_singleton_clusters(covman_curr, curr_record, stop_record);
573  #endif
574      data->last_sglt_clust_update_time = get_cur_time();
            // └─► WRITE: last_sglt_clust_update_time (reset timer)
575    }
```

**Condition check (lines 556-558):**
- **READ: `sample_interval`** - Check mode
- **READ: `last_sglt_clust_update_time`** - Check if interval elapsed
- If TRUE → Sample period is over, finalize sample

**Line 569** calls → **Lines 322-353: `update_singleton_clusters()`**

```c
322  void update_singleton_clusters(covmanager_t *covman,
323                                 record_t *curr_record, record_t *stop_record) {
324    // each time this function is called, we have a new sample
325    covman->n_samples++;
      // └─► WRITE: n_samples (THIS IS WHERE SAMPLE COUNT INCREMENTS!)
      //     This is the KEY line that converts accumulated execs into 1 sample
326
327    // For ground truth computation, we update the record's n_found_new based on
328    // what are covered until the record vs what's in covman->curr_covered
329    if (curr_record) {
330      record_t *iter_record = curr_record;
331      while (iter_record) {
332        if (iter_record == stop_record) { break; }
333        if (iter_record->check_new &&
334            set_is_subset(covman->curr_covered,
                              // └─► READ: curr_covered (check if new vs old record)
335                          iter_record->covered_cum) == SET_FALSE) {
336            iter_record->n_found_new++;
                  // └─► WRITE: record's n_found_new (ground truth tracking)
337            iter_record->check_new = false;
338        }
339        iter_record = iter_record->prev;
340      }
341    }
342    for (u32 i = 0; i < covman->curr_covered->number_nodes; ++i) {
                               // └─► READ: curr_covered
343      if (covman->curr_covered->nodes[i] != NULL) {
344        set_add(covman->covered_prev,
                  // └─► WRITE: covered_prev (merge sample coverage into cumulative)
345                covman->curr_covered->nodes[i]->_key);
                    // └─► READ: curr_covered
346      }
347    }
348    // reset covman->curr_covered for the next sampling period
349    covman->cov_per_sample_unique = set_length(covman->curr_covered);
      // └─► WRITE: cov_per_sample_unique (save metric)
      //     └─► READ: curr_covered
350    covman->cov_per_sample_store = covman->cov_per_sample_live;
      // └─► WRITE: cov_per_sample_store (save accumulated intensity)
      //     └─► READ: cov_per_sample_live
351    covman->cov_per_sample_live = 0;
      // └─► WRITE: cov_per_sample_live (reset accumulator for next sample)
352    set_destroy(covman->curr_covered);
      // └─► Destroy the accumulator set
353    covman->curr_covered = NULL;
      // └─► WRITE: curr_covered (reset to NULL for next sample)
354  }
```

**After line 574: Timer reset**
```c
574    data->last_sglt_clust_update_time = get_cur_time();
      // └─► WRITE: last_sglt_clust_update_time (start timing next sample)
```

---

## Critical Lines Summary

### Execution Phase (Accumulation)
- **Line 505**: `n_execs++` - Count this execution
- **Line 309**: `set_add(curr_covered, key)` - Add coverage to accumulator
- **Line 551**: `cov_per_sample_live += ...` - Add to intensity accumulator

### Finalization Check
- **Lines 556-558**: Check if `(current_time - last_update_time) >= sample_interval`

### Finalization Phase (Sample Creation)
- **Line 325**: `n_samples++` - ★ THIS CREATES THE SAMPLE ★
- **Lines 342-346**: Merge `curr_covered` → `covered_prev`
- **Line 349**: Save `cov_per_sample_unique`
- **Line 350**: Save `cov_per_sample_store`
- **Line 351**: Reset `cov_per_sample_live = 0`
- **Line 353**: Reset `curr_covered = NULL`
- **Line 574**: Reset `last_sglt_clust_update_time`

---

# State Transitions

## Complete Variable State Transitions

### Sample Period Timeline

```
┌─────────────────────────────────────────────────────────────────────┐
│ BEFORE FIRST EXECUTION                                              │
├─────────────────────────────────────────────────────────────────────┤
│ n_samples = 0                                                       │
│ n_execs = 0                                                         │
│ curr_covered = NULL                                                 │
│ covered_prev = {}                                                   │
│ cov_per_sample_live = 0                                            │
│ last_sglt_clust_update_time = T0                                   │
└─────────────────────────────────────────────────────────────────────┘

        ↓ Execution 1 (Line 505, 309, 551)

┌─────────────────────────────────────────────────────────────────────┐
│ AFTER EXECUTION 1                                                   │
├─────────────────────────────────────────────────────────────────────┤
│ n_samples = 0                    (unchanged - no finalization yet)  │
│ n_execs = 1                      (Line 505: n_execs++)              │
│ curr_covered = {edge_5}          (Line 309: set_add)                │
│ covered_prev = {}                (unchanged)                        │
│ cov_per_sample_live = 8          (Line 551: += trace_bits[5])      │
│ last_sglt_clust_update_time = T0 (unchanged)                       │
└─────────────────────────────────────────────────────────────────────┘

        ↓ Execution 2 (Lines 505, 309, 551)

┌─────────────────────────────────────────────────────────────────────┐
│ AFTER EXECUTION 2                                                   │
├─────────────────────────────────────────────────────────────────────┤
│ n_samples = 0                                                       │
│ n_execs = 2                      (Line 505: n_execs++)              │
│ curr_covered = {edge_5, edge_12} (Line 309: set_add)                │
│ covered_prev = {}                                                   │
│ cov_per_sample_live = 23         (Line 551: += trace_bits[12])     │
│ last_sglt_clust_update_time = T0                                   │
└─────────────────────────────────────────────────────────────────────┘

        ↓ Execution 3 (Lines 505, 309, 551)
        ↓ ...
        ↓ Execution N (Lines 505, 309, 551)

┌─────────────────────────────────────────────────────────────────────┐
│ AFTER EXECUTION N (Still accumulating)                              │
├─────────────────────────────────────────────────────────────────────┤
│ n_samples = 0                                                       │
│ n_execs = N                                                         │
│ curr_covered = {edge_5, edge_12, ..., edge_99}                      │
│ covered_prev = {}                                                   │
│ cov_per_sample_live = 456                                          │
│ last_sglt_clust_update_time = T0                                   │
└─────────────────────────────────────────────────────────────────────┘

        ↓ Time check (Line 557): current_time - T0 >= sample_interval?
        ↓ YES! Call update_singleton_clusters() at line 569

        ↓ Line 325: n_samples++
        ↓ Lines 342-346: Merge curr_covered → covered_prev
        ↓ Line 349: Save cov_per_sample_unique
        ↓ Line 350: Save cov_per_sample_store
        ↓ Line 351: Reset cov_per_sample_live = 0
        ↓ Line 353: curr_covered = NULL
        ↓ Line 574: last_sglt_clust_update_time = T1

┌─────────────────────────────────────────────────────────────────────┐
│ AFTER SAMPLE FINALIZATION (Ready for next sample)                   │
├─────────────────────────────────────────────────────────────────────┤
│ n_samples = 1                    (Line 325: n_samples++)  ★         │
│ n_execs = N                      (unchanged)                        │
│ curr_covered = NULL              (Line 353: reset)                  │
│ covered_prev = {edge_5,...,edge_99} (Lines 344: merged)             │
│ cov_per_sample_live = 0          (Line 351: reset)                  │
│ cov_per_sample_unique = 20       (Line 349: saved)                  │
│ cov_per_sample_store = 456       (Line 350: saved)                  │
│ last_sglt_clust_update_time = T1 (Line 574: reset timer)  ★         │
└─────────────────────────────────────────────────────────────────────┘

        ↓ Next execution starts NEW sample period
        ↓ (curr_covered will be created again at line 535)
```

---

# Deep Dive: `cov_per_sample_store` Double-Buffering

## The Problem

**Sample finalization** and **record creation** happen at **different times**:
- Samples finalize every `sample_interval` seconds (line 569)
- Records are created less frequently with additional logic (lines 577-593)

Without a buffer, the coverage intensity metric would be lost between these events.

## The Solution: Double-Buffering

`cov_per_sample_store` acts as a **holding buffer** between sample finalization and record creation.

## All Occurrences of `cov_per_sample_store`

| Line | Function | Action | Purpose |
|------|----------|--------|---------|
| 74 | `covmanager_t` | Declared | Storage variable in structure |
| 148 | `covmanager_init()` | `= 0` | Initialize to zero |
| **349** | `update_singleton_clusters()` | **`= cov_per_sample_live`** | **SAVE** accumulated value |
| **651** | `afl_custom_post_run()` | **READ** → record | **USE** - Copy to record |
| 652 | `afl_custom_post_run()` | `= 0` | Reset after copying |

## Complete Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│ SAMPLE PERIOD 1 (Executions accumulating)                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ Line 551 (each execution):                                     │
│   cov_per_sample_live += trace_bits[i]                         │
│                                                                 │
│ Execution 1:  cov_per_sample_live = 8                          │
│ Execution 2:  cov_per_sample_live = 23   ◄─ Accumulating      │
│ Execution 3:  cov_per_sample_live = 45                         │
│ ...                                                             │
│ Execution N:  cov_per_sample_live = 456                        │
│                                                                 │
│ cov_per_sample_store = 0  ◄─ Still holding old value          │
└─────────────────────────────────────────────────────────────────┘
                         ↓
          (Sample interval elapses - Line 557 check passes)
                         ↓
          update_singleton_clusters() called (Line 569)
                         ↓
┌─────────────────────────────────────────────────────────────────┐
│ SAMPLE FINALIZATION (Lines 349-351)                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ Line 349:                                                       │
│   cov_per_sample_store = cov_per_sample_live;  ◄─ SAVE!       │
│                          └─► 456                                │
│                                                                 │
│ Line 350:                                                       │
│   cov_per_sample_live = 0;  ◄─ RESET for next sample          │
│                                                                 │
│ Result after line 351:                                         │
│   cov_per_sample_store = 456  ✓ Saved and preserved           │
│   cov_per_sample_live = 0     ✓ Ready for next sample         │
└─────────────────────────────────────────────────────────────────┘
                         ↓
          Next executions continue (new sample period starts)
                         ↓
┌─────────────────────────────────────────────────────────────────┐
│ SAMPLE PERIOD 2 (New executions accumulating)                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ Line 551 (each new execution):                                 │
│   cov_per_sample_live += trace_bits[i]                         │
│                                                                 │
│ Execution N+1: cov_per_sample_live = 12                        │
│ Execution N+2: cov_per_sample_live = 29  ◄─ Accumulating again│
│ ...                                                             │
│                                                                 │
│ cov_per_sample_store = 456  ◄─ STILL holding Sample 1's value │
│                                 (preserved until record created)│
└─────────────────────────────────────────────────────────────────┘
                         ↓
          (Record creation logic triggers - Lines 577-593)
                         ↓
          add_new_record = true (Line 601)
                         ↓
┌─────────────────────────────────────────────────────────────────┐
│ RECORD CREATION (Lines 651-652)                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ Line 651:                                                       │
│   new_record->cov_per_sample = cov_per_sample_store;           │
│                                └─► 456  ◄─ USE!                │
│                                                                 │
│ Line 652:                                                       │
│   cov_per_sample_store = 0;  ◄─ CLEAR after copying           │
│                                                                 │
│ Result:                                                         │
│   Record now has cov_per_sample = 456 (Sample 1's intensity)   │
│   cov_per_sample_store = 0 (ready for next sample's value)     │
└─────────────────────────────────────────────────────────────────┘
```

## Timeline View

```
Time:     0s─────5s─────10s─────15s─────20s─────25s
          │      │       │       │       │       │
Samples:  │  S1  │   S2  │   S3  │   S4  │   S5  │
          └──────┴───────┴───────┴───────┴───────┘

Line 349: │  ←───│  ←────│  ←────│  ←────│  ←────│
(Save)    store  store   store   store   store
          =456   =312    =289    =401    =378
            ↓      ↓       ↓       ↓       ↓
          held   held    held    held    held
            ↓      ↓       ↓       ↓       ↓

Line 651: │              ↑               ↑        │
(Use)     └──────────────┘───────────────┘────────┘
          Record #1           Record #2
          created here        created here
          (cov=456)          (cov=289)

Note: Records are NOT created for every sample!
      They're created based on additional logic (lines 577-593)
```

## Code Trace Example

**Detailed execution with values:**

```c
// ═══════════════════════════════════════════════════════════════
// SAMPLE PERIOD 1: Time 0-5s
// ═══════════════════════════════════════════════════════════════

// Initialize (Line 148)
cov_per_sample_store = 0;
cov_per_sample_live = 0;

// Execution 1 at t=0.5s
trace_bits[5] = 8;
// Line 551:
cov_per_sample_live += 8;          // cov_per_sample_live = 8

// Execution 2 at t=1.2s
trace_bits[5] = 8, trace_bits[12] = 7;
// Line 551:
cov_per_sample_live += 15;         // cov_per_sample_live = 23

// ... more executions ...

// Execution N at t=4.9s
// After all executions: cov_per_sample_live = 456

// ═══════════════════════════════════════════════════════════════
// SAMPLE FINALIZATION at t=5s
// ═══════════════════════════════════════════════════════════════

// Line 557: Check elapsed
get_cur_time() - last_sglt_clust_update_time = 5000ms ≥ 5000ms ✓

// Line 569: Call update_singleton_clusters()

// Line 349: SAVE live → store
cov_per_sample_store = cov_per_sample_live;  // = 456

// Line 350: RESET live
cov_per_sample_live = 0;

// State now:
//   cov_per_sample_store = 456  ← Preserved
//   cov_per_sample_live = 0     ← Reset

// ═══════════════════════════════════════════════════════════════
// SAMPLE PERIOD 2: Time 5-10s (new sample accumulating)
// ═══════════════════════════════════════════════════════════════

// Execution N+1 at t=5.3s
trace_bits[7] = 6;
// Line 551:
cov_per_sample_live += 6;          // cov_per_sample_live = 6

// State now:
//   cov_per_sample_store = 456  ← Still holding Sample 1's value!
//   cov_per_sample_live = 6     ← Accumulating Sample 2

// ... more executions accumulate in cov_per_sample_live ...

// ═══════════════════════════════════════════════════════════════
// RECORD CREATION at t=7s (during Sample Period 2)
// ═══════════════════════════════════════════════════════════════

// Lines 577-593: Determine add_new_record = true
// Lines 601-661: Create new record

// Line 651: Copy store → record
new_record->cov_per_sample = cov_per_sample_store;  // = 456

// Line 652: Clear store
cov_per_sample_store = 0;

// State now:
//   new_record->cov_per_sample = 456  ← Record has Sample 1's value
//   cov_per_sample_store = 0          ← Cleared
//   cov_per_sample_live = 89          ← Still accumulating Sample 2
```

## Why This Matters

**Without `cov_per_sample_store`:**
```
Sample finalized → cov_per_sample_live reset to 0
                   (value lost!)
Record created   → Nothing to copy (data is gone)
```

**With `cov_per_sample_store`:**
```
Sample finalized → Save to cov_per_sample_store (preserved)
                   Reset cov_per_sample_live (ready for next)
Record created   → Copy from cov_per_sample_store (data available!)
                   Clear cov_per_sample_store (cleanup)
```

## CSV Output

The value appears as **`#covpersmp`** in the CSV (lines 720, 746):

```csv
time,#samples,#covpersmp,#covperuniqsmp,#execs,#seeds,...
5000,1,456,23,1000,5,...
        ↑
        └── This is the total coverage intensity from Sample 1
            (sum of all trace_bits values during that sample period)
```

**Interpretation**: Higher `#covpersmp` means:
- More edges hit during the sample, OR
- Edges hit with higher hit counts, OR
- Both

It measures the **intensity** of coverage, not just the **count** of unique edges covered.

---

# Summary

## Key Insight

**The magic happens at Line 325: `covman->n_samples++;`**

This single line converts all the accumulated executions into **1 sample**. Everything before this is accumulation; everything after is reset for the next sample.

## The Sampling Mechanism in 3 Steps

1. **ACCUMULATE** (Lines 505, 309, 551)
   - Each execution adds to `curr_covered` and `cov_per_sample_live`
   - Multiple executions accumulate in the same buffers

2. **FINALIZE** (Line 325 + 342-351)
   - When `sample_interval` elapses, `n_samples++`
   - Merge accumulators to permanent storage
   - Save metrics

3. **RESET** (Lines 351, 353)
   - Clear accumulators
   - Ready for next sample period

## Why Sampling Enables Better Fuzzing Analysis

1. **Memory efficiency**: Track samples instead of individual executions
2. **Statistical estimation**: Singletons per sample → Good-Turing estimator
3. **Ground truth validation**: Compare past predictions vs. actual discoveries
4. **Flexible granularity**: Tune `sample_interval` for your needs

## Quick Reference Table

| Variable | Purpose | Increment At | Reset At |
|----------|---------|--------------|----------|
| `n_execs` | Count executions | Line 505 (every exec) | Never |
| `n_samples` | Count samples | Line 325 (finalization) | Never |
| `curr_covered` | Accumulate coverage | Line 309 (every exec) | Line 353 (finalization) |
| `cov_per_sample_live` | Accumulate intensity | Line 551 (every exec) | Line 351 (finalization) |
| `cov_per_sample_store` | Hold intensity | Line 350 (finalization) | Line 652 (record creation) |
| `covered_prev` | Permanent coverage | Line 344 (finalization) | Never |

---

**End of Guide** • For more details, see the source code: `custom_post_run_gtonly_efficient.c`
