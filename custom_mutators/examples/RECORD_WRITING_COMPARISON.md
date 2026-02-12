# Record Writing Frequency Comparison

This document compares the record creation and writing logic between the three custom mutator implementations, explaining the **fundamental algorithmic differences** that drive their different memory and I/O behaviors.

---

## Executive Summary

| File | Computation Type | "Done" Check | Memory Management | Records in Memory |
|------|-----------------|--------------|-------------------|-------------------|
| **custom_post_run.c** | Instantaneous estimation | ❌ **COMMENTED OUT** (line 868) | Flush all immediately | ~0 (flushes all) |
| **custom_post_run_gtonly_efficient.c** | Ground truth evaluation | ✅ **ACTIVE** (line 831) | Keep recent records | Up to 10 recent |
| **custom_post_run_efficient.c** | Ground truth evaluation | ✅ **ACTIVE** | Keep recent records | Up to 10 recent |

**Key Insight**: The memory behavior differences are not optimization choices—they're **algorithmic requirements** driven by whether the implementation computes ground truth.

---

## Fundamental Algorithmic Difference

The three implementations differ in **what they compute**:

### custom_post_run.c - Instantaneous Estimation

**What it computes:**
- Estimates coverage discovery probability **at the current moment only**
- Records the state: "At time T, we had seen X coverage"

**What it does NOT compute:**
- Does NOT track what was **newly discovered** from a retrospective viewpoint
- Does NOT compare "what we knew at time T" vs. "what we learned later"

**Memory requirement:**
- **None** - Can flush records immediately
- No need to maintain historical state

**Why flush is safe:**
- Each record is independent
- No future lookback required
- All information captured in the CSV write

### gtonly_efficient.c / efficient.c - Ground Truth Evaluation

**What it computes:**
- Computes **empirical discovery probability with ground truth**
- Retrospectively evaluates: "What was the TRUE discovery probability at time T?"

**Requires:**
- Track what was **seen at time T** (stored in record created at time T)
- Compare with what is **seen at time 2T** (current state)
- Determine what was **newly discovered** between T and 2T

**Memory requirement:**
- **Must maintain recent records** until enough future samples are collected
- Records are "done" when: `cur->execs * 2 >= total_execs`
- This means we've collected enough future data to compute ground truth

**Why flush is NOT safe:**
- Need historical records for retrospective comparison
- Ground truth = comparing past observation with future discoveries
- Records must stay in memory until "done"

---

## How This Affects Record Management

The algorithmic difference drives different record management strategies:

### custom_post_run.c - Immediate Flush Strategy

```c
while (cur) {
  // check if the record is done
  // if (cur->execs * 2 >= data->covman_total->n_execs) { break; }  // ← COMMENTED OUT!

  // write the record to the file
  write_row(f, data, cur, true);

  // FREE the record (no need to keep it)
  if (cur->next) {
    cur = cur->next;
    free(cur->prev);  // ← Frees EVERY record
    cur->prev = NULL;
    data->records_len--;
  } else {
    free(cur);
    data->records = NULL;
    data->records_len = 0;  // ← ALL records freed!
  }
}
```

**Result**: Memory resets to ~0 after each write

**Why this works**: No future lookback needed, so no need to keep records

### gtonly_efficient.c / efficient.c - Selective Flush Strategy

```c
while (cur) {
  // check if the record is done
  if (cur->execs * 2 >= data->covman_total->n_execs) { break; }  // ← ACTIVE!

  // write the record to the file (only "done" records reach here)
  write_row(f, data, cur, true);

  // FREE only "done" records
  if (cur->next) {
    cur = cur->next;
    free(cur->prev);  // ← Only frees "done" records
    cur->prev = NULL;
    data->records_len--;
  } else {
    free(cur);
    data->records = NULL;
    data->records_len = 0;
  }
}
// Recent records (where execs * 2 >= total_execs) remain in memory
```

**Result**: Keeps up to 10 recent records in memory

**Why this is necessary**: Recent records needed for ground truth computation

---

## Understanding "Done" Records

### What is a "Done" Record?

A record is "done" when we've collected enough **future samples** to evaluate its ground truth:

```c
// A record is "done" if:
cur->execs * 2 < data->covman_total->n_execs

// Meaning:
// - Record created when we had N executions (cur->execs = N)
// - Now we have at least 2N executions (total_execs >= 2N)
// - We've collected enough future data to compute ground truth for this record
```

### Why 2x Threshold?

The 2x threshold ensures:
1. **Record created at time T**: `cur->execs = N`
2. **Evaluated at time 2T**: `total_execs >= 2N`
3. **Retrospective view**: Compare what we knew at N vs. what we learned from N to 2N
4. **Ground truth**: Determine true discovery probability at time T

---

## Code-Level Differences

### 1. The "Done" Check

| File | Line | Status | Code |
|------|------|--------|------|
| **custom_post_run.c** | 868 | ❌ Commented | `// if (cur->execs * 2 >= ...) { break; }` |
| **gtonly_efficient.c** | 831 | ✅ Active | `if (cur->execs * 2 >= ...) { break; }` |
| **efficient.c** | Similar | ✅ Active | `if (cur->execs * 2 >= ...) { break; }` |

### 2. Record Creation Limits

**gtonly_efficient.c** (Lines 591-593):
```c
// restrict the number of records for efficiency
if (data->records_len >= 10 && add_new_record) {
  add_new_record = false;  // ← BLOCKS new records when limit reached
}
```

**custom_post_run.c**:
```c
// (NO LIMITING CODE)
// No upper bound on record creation
```

**efficient.c** (Lines 722-724):
```c
// restrict the number of records for efficiency
if (data->records_len >= 10 && add_new_record) {
  add_new_record = false;  // ← BLOCKS new records when limit reached
}
```

**Why the difference?**
- **custom_post_run.c**: Flushes all records immediately, so no need to limit
- **gtonly_efficient/efficient**: Keeps records in memory, so limit to bound memory usage

### 3. Write Triggers (Per-Interval Mode)

**gtonly_efficient.c** (Lines 685-690):
```c
else {
  // Write when: new record created OR buffer limit reached
  if (add_new_record || data->records_len >= 10) {
    update_record(data, false);
  }
}
```

**custom_post_run.c** (Lines 734-738):
```c
else {
  // Write when: new record created only
  if (add_new_record) {
    update_record(data, false);
  }
}
```

**efficient.c** (Lines 821-826):
```c
else {
  // Write when: new record created OR buffer limit reached
  if (add_new_record || data->records_len >= 10) {
    update_record(data, false);
  }
}
```

---

## Memory and I/O Impact

### Memory Usage Scenario

**Setup**: Fuzzing for 24 hours with `sample_interval = 10` seconds

#### custom_post_run.c (FLUSH ALL)

```
Every write (every 10 seconds):
├─ Creates 1 new record
├─ Writes ALL records to disk
├─ Frees ALL records
└─ Memory resets to ~0

At any moment: 0-1 records in memory (~0-200 bytes)
Total disk writes: 8,640 times (every 10 seconds)
Memory profile: O(1) - constant minimal memory
```

#### gtonly_efficient.c / efficient.c (KEEP RECENT)

```
Every write (every 10 seconds OR when limit reached):
├─ Creates records (max 10)
├─ Writes only "done" records to disk
├─ Frees only "done" records
└─ Keeps recent (not done) records in memory

At any moment: Up to 10 recent records (~2 KB)
Total disk writes: Fewer (only when records become "done")
Memory profile: O(1) - bounded at 10 records
```

### Behavior Timeline Example

**Setup**: `sample_interval = 60` seconds, fuzzing for 13 minutes

```
Time (min)  0    1    2    3    4    5    6    7    8    9   10   11   12
            │    │    │    │    │    │    │    │    │    │    │    │    │
Samples:    S1   S2   S3   S4   S5   S6   S7   S8   S9  S10  S11  S12  S13

custom_post_run.c (FLUSH ALL):
Records:    R1   R2   R3   R4   R5   R6   R7   R8   R9  R10  R11  R12  R13
In Memory:  0-1  0-1  0-1  0-1  0-1  0-1  0-1  0-1  0-1  0-1  0-1  0-1  0-1
Write:      ↓    ↓    ↓    ↓    ↓    ↓    ↓    ↓    ↓    ↓    ↓    ↓    ↓
            (writes ALL records → frees ALL → memory ~0)

gtonly_efficient.c / efficient.c (KEEP RECENT):
Records:    R1   R2   R3   R4   R5   R6   R7   R8   R9  R10  (10) (10) (10)
In Memory:  1    2    3    4    5    6    7    8    9   10   ~10  ~10  ~10
Write:      ↓    ↓    ↓    ↓    ↓    ↓    ↓    ↓    ↓    ↓    ↓    ↓    ↓
            (writes only "done" → frees only "done" → keeps recent)

After 30 minutes:
  custom_post_run.c:      ~0 records in memory (all written and freed)
  gtonly/efficient.c:     ~10 records in memory (old freed, recent kept)
```

### Disk I/O Patterns

**custom_post_run.c**:
- Writes to disk every `sample_interval` seconds
- Writes ALL records each time (no "done" filtering)
- High disk I/O, minimal memory

**gtonly_efficient.c / efficient.c**:
- Writes to disk every `sample_interval` seconds OR when limit reached
- Writes only "done" records (filters by `cur->execs * 2 >= total_execs`)
- Lower disk I/O (only writes completed ground truth)
- Bounded memory (max 10 records)

---

## Summary Table

| Aspect | gtonly_efficient | custom_post_run | efficient |
|--------|-----------------|-----------------|-----------|
| **Computation Type** | Ground truth | Instantaneous | Ground truth |
| **Needs Historical Records** | ✅ Yes | ❌ No | ✅ Yes |
| **"Done" Check** | ✅ Active | ❌ Commented | ✅ Active |
| **Record Limit** | ✅ Max 10 | ❌ Unlimited | ✅ Max 10 |
| **Memory Usage** | Bounded (~2 KB) | Minimal (~0-200 bytes) | Bounded (~2 KB) |
| **Disk I/O** | Lower (selective) | Higher (flush all) | Lower (selective) |
| **Memory Profile** | O(1) bounded | O(1) minimal | O(1) bounded |

---

## Practical Implications

### When to Use Each Version

**Use custom_post_run.c when:**
- You only need instantaneous probability estimates
- No ground truth computation required
- Memory is extremely constrained
- High disk I/O is acceptable
- Real-time estimation without retrospective analysis

**Use gtonly_efficient.c / efficient.c when:**
- You need accurate ground truth discovery probabilities
- Retrospective analysis required (compare past vs. future)
- Willing to maintain bounded memory for recent records
- Prefer lower disk I/O
- Long fuzzing campaigns where ground truth matters

### CSV Output Differences

**custom_post_run.c**:
- All records written to `records.csv` immediately
- No concept of "done" vs "not done" records
- Each record is final when written

**gtonly_efficient.c / efficient.c**:
- "Done" records written to `records.csv` continuously
- "Not done" records written to `records_not_done.csv` at exit
- Ground truth computed only for "done" records

---

## Conclusion

The record management differences between these implementations are driven by **fundamental algorithmic requirements**, not arbitrary optimization choices:

### The Core Difference

1. **custom_post_run.c**: Estimates discovery probability at each moment
   - No future lookback → No need to maintain records → Flush immediately

2. **gtonly_efficient.c / efficient.c**: Computes ground truth discovery probability
   - Requires retrospective comparison → Must maintain recent records → Selective flush

### Memory Behavior Summary

| File | In-Memory Records | Why? |
|------|------------------|------|
| **custom_post_run.c** | ~0 (flushes all) | No ground truth → no need to keep records |
| **gtonly_efficient.c** | Up to 10 recent | Ground truth → must keep records until "done" |
| **efficient.c** | Up to 10 recent | Ground truth → must keep records until "done" |

### The "Done" Check is Essential

The "done" check (`if (cur->execs * 2 >= total_execs) { break; }`) is not just a memory optimization—it's **required for ground truth computation**:

- Determines when enough future data has been collected
- Marks when retrospective evaluation can be finalized
- Separates records that can be flushed from those still needed

Both approaches are valid for their respective use cases!
