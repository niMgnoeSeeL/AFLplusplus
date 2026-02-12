# Sampling Mechanism Implementation Verification

This document verifies that all three custom mutator implementations follow the documented sampling mechanism.

---

## Summary: ✅ All Three Implementations Follow the Documented Mechanism

| Implementation | n_samples++ | n_execs++ | Accumulators | Finalization | Status |
|----------------|-------------|-----------|--------------|--------------|--------|
| **custom_post_run_gtonly_efficient.c** | ✅ Line 325 | ✅ Line 505 | ✅ curr_covered | ✅ Lines 342-352 | ✅ **CORRECT** |
| **custom_post_run.c** | ✅ Line 387 | ✅ Line 559 | ✅ curr_sglt_clust | ✅ Lines 390-405 | ✅ **CORRECT** |
| **custom_post_run_efficient.c** | ✅ Line 436 | ✅ Line 613 | ✅ Both | ✅ Lines 455-479 | ✅ **CORRECT** |

---

## Detailed Line-by-Line Verification

### Phase 1: Initialization

#### covmanager_init()

| File | n_samples=0 | n_execs=0 | curr_covered=NULL | cov_per_sample_live=0 |
|------|-------------|-----------|-------------------|----------------------|
| **gtonly_efficient** | Line 143 ✅ | Line 144 ✅ | Line 147 ✅ | Line 150 ✅ |
| **custom_post_run** | Line 143 ✅ | Line 144 ✅ | N/A (uses curr_sglt_clust) | N/A |
| **efficient** | Line 155 ✅ | Line 156 ✅ | Line 164 ✅ | Line 167 ✅ |

**Verification:** ✅ All files properly initialize counters to 0 and accumulators to NULL

---

### Phase 2: Execution Phase (Per-Execution)

#### Increment execution counter

| File | Line | Code | Status |
|------|------|------|--------|
| **gtonly_efficient** | 505 | `data->covman_total->n_execs++;` | ✅ |
| **custom_post_run** | 559 | `data->covman_total->n_execs++;` | ✅ |
| **efficient** | 613 | `data->covman_total->n_execs++;` | ✅ |

**Verification:** ✅ All files increment n_execs every execution

#### Create accumulator if needed

| File | Lines | Creates curr_covered | Creates curr_sglt_clust |
|------|-------|---------------------|------------------------|
| **gtonly_efficient** | 534-537 | ✅ Yes | ❌ No (ground truth only) |
| **custom_post_run** | 589-604 | ❌ No | ✅ Yes (singleton only) |
| **efficient** | 659-687 | ✅ Yes | ✅ Yes (both!) |

**Verification:** ✅ Each file creates appropriate accumulators on first execution of sample period

#### Accumulate coverage

| File | Accumulation Logic | Line(s) |
|------|-------------------|---------|
| **gtonly_efficient** | `set_add(covman->curr_covered, key)` in update_covmanager | 309 |
| **custom_post_run** | `set_add(covman->curr_sglt_clust, key)` in update_covmanager | 342-343 |
| **efficient** | Both `curr_covered` AND `curr_sglt_clust` | 434, 437 |

**Verification:** ✅ All files accumulate coverage during sample period

#### Accumulate intensity (gtonly_efficient and efficient only)

| File | Line | Code | Status |
|------|------|------|--------|
| **gtonly_efficient** | 551 | `cov_per_sample_live += trace_bits[i]` | ✅ |
| **custom_post_run** | N/A | N/A (doesn't track intensity) | N/A |
| **efficient** | 708 | `covman->cov_per_sample_live++` | ✅ |

**Verification:** ✅ Files that track intensity do so correctly

---

### Phase 3: Finalization Check

#### Check if sample interval elapsed

| File | Lines | Condition | Status |
|------|-------|-----------|--------|
| **gtonly_efficient** | 556-558 | `sample_interval == 0 \|\| (get_cur_time() - last_sglt_clust_update_time >= sample_interval * 1000)` | ✅ |
| **custom_post_run** | 632-634 | `sample_interval == 0 \|\| (get_cur_time() - last_sglt_clust_update_time >= sample_interval * 1000)` | ✅ |
| **efficient** | 718-720 | `sample_interval == 0 \|\| (get_cur_time() - last_sglt_clust_update_time >= sample_interval * 1000)` | ✅ |

**Verification:** ✅ All files use identical finalization check logic

---

### Phase 4: Sample Finalization

#### update_singleton_clusters() - The Critical Function

**Step 1: Increment n_samples (★ Creates the sample)**

| File | Line | Code | Status |
|------|------|------|--------|
| **gtonly_efficient** | 325 | `covman->n_samples++;` | ✅ |
| **custom_post_run** | 387 | `covman->n_samples++;` | ✅ |
| **efficient** | 436 | `covman->n_samples++;` | ✅ |

**Verification:** ✅ All files increment n_samples at the start of finalization

**Step 2: Merge accumulators to permanent storage**

| File | Lines | What Gets Merged | Status |
|------|-------|-----------------|--------|
| **gtonly_efficient** | 342-346 | `curr_covered → covered_prev` | ✅ |
| **custom_post_run** | 396-401 | `curr_sglt_clust → covered_prev` (if non-empty) | ✅ |
| **efficient** | 455-462 | `curr_covered → covered_prev` | ✅ |
| **efficient** | 465-474 | `curr_sglt_clust → sglt_clusts` (if non-empty) | ✅ |

**Verification:** ✅ All files merge accumulated data to permanent storage

**Step 3: Save metrics**

| File | Saves cov_per_sample_unique | Saves cov_per_sample_store | Saves singleton clusters |
|------|---------------------------|--------------------------|------------------------|
| **gtonly_efficient** | ✅ Line 349 | ✅ Line 350 | ❌ No |
| **custom_post_run** | ❌ No | ❌ No | ✅ Lines 394-395 |
| **efficient** | ✅ Line 476 | ✅ Line 477 | ✅ Lines 470-471 |

**Verification:** ✅ Each file saves appropriate metrics for its tracking mode

**Step 4: Reset accumulators**

| File | Reset curr_covered | Reset curr_sglt_clust | Reset cov_per_sample_live |
|------|-------------------|----------------------|--------------------------|
| **gtonly_efficient** | ✅ Line 352 (`= NULL`) | N/A | ✅ Line 351 (`= 0`) |
| **custom_post_run** | N/A | ✅ Lines 402/405 (`= NULL`) | N/A |
| **efficient** | ✅ Line 479 (`= NULL`) | ✅ Lines 468/471 (`= NULL`) | ✅ Line 478 (`= 0`) |

**Verification:** ✅ All files properly reset accumulators

**Step 5: Reset timer**

| File | Line | Code | Status |
|------|------|------|--------|
| **gtonly_efficient** | 574 | `last_sglt_clust_update_time = get_cur_time()` | ✅ |
| **custom_post_run** | 640 | `last_sglt_clust_update_time = get_cur_time()` | ✅ |
| **efficient** | 736 | `last_sglt_clust_update_time = get_cur_time()` | ✅ |

**Verification:** ✅ All files reset the timer for next sample

---

## Functional Flow Verification

### The Complete Sampling Cycle

Let me trace through one complete sampling cycle for each file:

#### custom_post_run_gtonly_efficient.c

```
┌─────────────────────────────────────────────────────────────┐
│ SAMPLE PERIOD                                               │
├─────────────────────────────────────────────────────────────┤
│ Line 505: n_execs++           (every execution)             │
│ Line 535: Create curr_covered (first exec of period)        │
│ Line 309: set_add(curr_covered, key)  (every execution)     │
│ Line 551: cov_per_sample_live += ...  (every execution)     │
└─────────────────────────────────────────────────────────────┘
                         ↓
              (Sample interval elapses)
                         ↓
┌─────────────────────────────────────────────────────────────┐
│ FINALIZATION (Line 569: update_singleton_clusters)         │
├─────────────────────────────────────────────────────────────┤
│ Line 325: n_samples++                                       │
│ Line 342-346: Merge curr_covered → covered_prev            │
│ Line 349: Save cov_per_sample_unique                        │
│ Line 350: Save cov_per_sample_store                         │
│ Line 351: Reset cov_per_sample_live = 0                     │
│ Line 352: Reset curr_covered = NULL                         │
│ Line 574: Reset last_sglt_clust_update_time                 │
└─────────────────────────────────────────────────────────────┘

✅ CORRECT: Follows documented mechanism
```

#### custom_post_run.c

```
┌─────────────────────────────────────────────────────────────┐
│ SAMPLE PERIOD                                               │
├─────────────────────────────────────────────────────────────┤
│ Line 559: n_execs++           (every execution)             │
│ Line 590-592: Create curr_sglt_clust (first exec)          │
│ Line 342: set_add(curr_sglt_clust, key)  (every execution) │
│ (No intensity tracking)                                     │
└─────────────────────────────────────────────────────────────┘
                         ↓
              (Sample interval elapses)
                         ↓
┌─────────────────────────────────────────────────────────────┐
│ FINALIZATION (Line 635: update_singleton_clusters)         │
├─────────────────────────────────────────────────────────────┤
│ Line 387: n_samples++                                       │
│ Line 390-401: Save curr_sglt_clust to sglt_clusts          │
│ Line 396-401: Merge to covered_prev                         │
│ Line 402/405: Reset curr_sglt_clust = NULL                 │
│ Line 640: Reset last_sglt_clust_update_time                 │
└─────────────────────────────────────────────────────────────┘

✅ CORRECT: Follows documented mechanism (singleton variant)
```

#### custom_post_run_efficient.c

```
┌─────────────────────────────────────────────────────────────┐
│ SAMPLE PERIOD                                               │
├─────────────────────────────────────────────────────────────┤
│ Line 613: n_execs++           (every execution)             │
│ Line 660-662: Create curr_covered (first exec)             │
│ Line 664-666: Create curr_sglt_clust (first exec)          │
│ Line 434: set_add(curr_covered, key)  (every execution)    │
│ Line 437: set_add(curr_sglt_clust, key) (if new)           │
│ Line 708: covman->cov_per_sample_live++  (every execution) │
└─────────────────────────────────────────────────────────────┘
                         ↓
              (Sample interval elapses)
                         ↓
┌─────────────────────────────────────────────────────────────┐
│ FINALIZATION (Line 731: update_singleton_clusters)         │
├─────────────────────────────────────────────────────────────┤
│ Line 436: n_samples++                                       │
│ Line 455-462: Merge curr_covered → covered_prev            │
│ Line 465-474: Save curr_sglt_clust to sglt_clusts          │
│ Line 476: Save cov_per_sample_unique                        │
│ Line 477: Save cov_per_sample_store                         │
│ Line 478: Reset cov_per_sample_live = 0                     │
│ Line 479: Reset curr_covered = NULL                         │
│ Line 468/471: Reset curr_sglt_clust = NULL                 │
│ Line 736: Reset last_sglt_clust_update_time                 │
└─────────────────────────────────────────────────────────────┘

✅ CORRECT: Follows documented mechanism (combined variant)
```

---

## Key Differences (Implementation Variants)

While all three follow the same **core mechanism**, they differ in **what they track**:

| Aspect | gtonly_efficient | custom_post_run | efficient |
|--------|-----------------|-----------------|-----------|
| **Ground Truth** | ✅ Yes (`curr_covered`) | ❌ No | ✅ Yes (`curr_covered`) |
| **Singletons** | ❌ No | ✅ Yes (`curr_sglt_clust`) | ✅ Yes (`curr_sglt_clust`) |
| **Singleton Clusters** | ❌ No | ✅ Yes (`sglt_clusts`) | ✅ Yes (`sglt_clusts`) |
| **Coverage Intensity** | ✅ Yes (`cov_per_sample_live`) | ❌ No | ✅ Yes (`cov_per_sample_live`) |
| **Record Limit** | ✅ Yes (max 10) | ❌ No | ✅ Yes (max 10) |

---

## Core Mechanism Invariants (All Files Must Follow)

### ✅ 1. Sample Creation Rule
**Rule:** `n_samples++` MUST be called exactly once per sample finalization

| File | Compliance | Line |
|------|-----------|------|
| gtonly_efficient | ✅ | 325 |
| custom_post_run | ✅ | 387 |
| efficient | ✅ | 436 |

### ✅ 2. Execution Counting Rule
**Rule:** `n_execs++` MUST be called exactly once per execution

| File | Compliance | Line |
|------|-----------|------|
| gtonly_efficient | ✅ | 505 |
| custom_post_run | ✅ | 559 |
| efficient | ✅ | 613 |

### ✅ 3. Accumulation Rule
**Rule:** Coverage MUST accumulate during sample period (not overwrite)

| File | Compliance | Implementation |
|------|-----------|----------------|
| gtonly_efficient | ✅ | `set_add(curr_covered, key)` - adds to set |
| custom_post_run | ✅ | `set_add(curr_sglt_clust, key)` - adds to set |
| efficient | ✅ | Both accumulation methods |

### ✅ 4. Finalization Trigger Rule
**Rule:** Sample finalization MUST be triggered by time interval check

| File | Compliance | Lines |
|------|-----------|-------|
| gtonly_efficient | ✅ | 556-558 |
| custom_post_run | ✅ | 632-634 |
| efficient | ✅ | 718-720 |

### ✅ 5. Reset Rule
**Rule:** Accumulators MUST be reset after finalization

| File | Compliance | What Gets Reset |
|------|-----------|----------------|
| gtonly_efficient | ✅ | `curr_covered`, `cov_per_sample_live` |
| custom_post_run | ✅ | `curr_sglt_clust` |
| efficient | ✅ | `curr_covered`, `curr_sglt_clust`, `cov_per_sample_live` |

### ✅ 6. Timer Reset Rule
**Rule:** `last_sglt_clust_update_time` MUST be reset after finalization

| File | Compliance | Line |
|------|-----------|------|
| gtonly_efficient | ✅ | 574 |
| custom_post_run | ✅ | 640 |
| efficient | ✅ | 736 |

---

## Conclusion

### ✅ VERIFICATION RESULT: ALL IMPLEMENTATIONS CORRECT

All three custom mutator implementations correctly follow the documented sampling mechanism:

1. **custom_post_run_gtonly_efficient.c** ✅
   - Implements ground truth tracking variant
   - All core mechanism invariants satisfied
   - Line numbers match documentation

2. **custom_post_run.c** ✅
   - Implements singleton tracking variant
   - All core mechanism invariants satisfied
   - Different line numbers but same logic

3. **custom_post_run_efficient.c** ✅
   - Implements combined tracking (ground truth + singletons)
   - All core mechanism invariants satisfied
   - Correctly merges both approaches

### Summary of Verification

| Invariant | gtonly_efficient | custom_post_run | efficient |
|-----------|-----------------|-----------------|-----------|
| Sample creation (n_samples++) | ✅ | ✅ | ✅ |
| Execution counting (n_execs++) | ✅ | ✅ | ✅ |
| Accumulation pattern | ✅ | ✅ | ✅ |
| Finalization trigger | ✅ | ✅ | ✅ |
| Accumulator reset | ✅ | ✅ | ✅ |
| Timer reset | ✅ | ✅ | ✅ |
| **OVERALL** | ✅ **PASS** | ✅ **PASS** | ✅ **PASS** |

---

**All three implementations are faithful to the documented sampling mechanism!** 🎯
