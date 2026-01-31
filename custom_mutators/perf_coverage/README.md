# Perf Coverage Custom Mutator for AFL++

## Overview

This custom mutator integrates perf-based coverage sampling into AFL++ for greybox fuzzing **without binary instrumentation**. Instead of compile-time instrumentation, it uses Linux perf to sample instruction pointers during execution and maps them to coverage.

## Goal

Enable **profiler-guided fuzzing** - using perf-based coverage sampling to guide AFL++'s mutation decisions while maintaining fast execution (no instrumentation overhead).

## Status

### Implemented ✓

1. **Core perf integration**
   - Streaming `perf record | perf script` pipeline
   - IP extraction and bitmap updates
   - Non-blocking sample reading

2. **Configurable sampling modes**
   - **Frequency mode** (`AFL_PERF_SAMPLE_MODE=freq`): Sample at fixed Hz using timer events
   - **Period mode** (`AFL_PERF_SAMPLE_MODE=period`): Sample every N events (requires hardware PMU)

3. **Batch processing**
   - Configurable read intervals (default: 5000 execs or 1000ms)
   - Reduces I/O overhead by batching sample reads

4. **PID selection**
   - Correctly attaches to `child_pid` (the executing process in persistent mode)
   - Optional pgrep fallback for finding target by binary name

5. **Source mode with MEG**
   - addr2line resolution for source:line coverage
   - Must-execute graph expansion for additional coverage inference

### Known Limitations

1. **Timer-based sampling doesn't work for fast targets**
   - Persistent mode targets spend most time sleeping in `AFL_LOOP()`
   - Timer samples rarely catch the brief execution bursts
   - **Solution**: Use period-based sampling with hardware PMU on bare metal

2. **`afl_custom_fuzz_count` is disabled**
   - Returns 0 which causes AFL++ to skip fuzzing
   - Keep disabled until time-based scheduling is needed

## Requirements

### For Timer Mode (VM/Cloud)
- Linux with perf support
- `task-clock` event (software, always available)
- **Note**: Unlikely to capture samples from fast targets

### For Period Mode (Bare Metal) - RECOMMENDED
- Hardware PMU (Performance Monitoring Unit)
- `instructions` or `cycles` events
- Bare metal or VM with PMU passthrough

## Usage

### Build

```bash
cd aflplusplus/custom_mutators/perf_coverage
make
```

### Run on Bare Metal (Recommended)

```bash
AFL_CUSTOM_MUTATOR_LIBRARY=./perf_mutator.so \
AFL_PERF_SAMPLE_MODE=period \
AFL_PERF_EVENT=instructions \
AFL_PERF_PERIOD=50000 \
AFL_PERF_DEBUG=1 \
afl-fuzz -i in -o out -- ./target @@
```

### Run on VM (Fallback - limited effectiveness)

```bash
AFL_CUSTOM_MUTATOR_LIBRARY=./perf_mutator.so \
AFL_PERF_SAMPLE_MODE=freq \
AFL_PERF_EVENT=task-clock \
AFL_PERF_HZ=10000 \
AFL_PERF_DEBUG=1 \
afl-fuzz -i in -o out -- ./target @@
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AFL_PERF_SAMPLE_MODE` | `freq` | `freq` (timer) or `period` (event count) |
| `AFL_PERF_EVENT` | `task-clock`/`instructions` | Perf event to sample |
| `AFL_PERF_HZ` | `5000` | Sampling frequency for freq mode |
| `AFL_PERF_PERIOD` | `100000` | Event count for period mode |
| `AFL_PERF_READ_INTERVAL` | `5000` | Read samples every N executions |
| `AFL_PERF_READ_INTERVAL_MS` | `1000` | Read samples every N milliseconds |
| `AFL_PERF_START_DELAY` | `100` | Start perf after N executions (skip calibration) |
| `AFL_PERF_DEBUG` | `0` | Enable debug logging to `perf_mutator.log` |
| `AFL_PERF_COVERAGE_MODE` | `ip` | `ip` (fast) or `source` (addr2line resolution) |
| `AFL_PERF_USE_PID_FILTER` | `1` | Use `-p PID` instead of system-wide `-a` |
| `AFL_PERF_USE_PGREP` | `0` | Find PID by binary name using pgrep |
| `AFL_PERF_MUST_EXEC` | - | Path to must-execute binary file for MEG |

## Testing on Bare Metal

### Expected Behavior

1. Perf attaches to the persistent child process
2. Samples IPs every N instructions (e.g., 50000)
3. New IPs update the coverage bitmap
4. AFL++ sees new paths and explores accordingly

### Verification

Check `perf_mutator.log` in the output directory:
```
[PERF] Starting perf at exec 100, child_pid=12345, using=12345
[PERF] Started perf for pid 12345 (pid_filter=on)
[STATS] execs=1000, perf_samples=150, ips_seen=42, window_new=12
```

If `perf_samples > 0`, sampling is working.

## Architecture

```
AFL++ fuzzer
    |
    v
afl_custom_post_run() -- called after each execution
    |
    v
perf_read_samples() -- read from perf script pipe (batched)
    |
    v
ip_cache_add() -- deduplicate and hash IPs
    |
    v
trace_bits[hash] = 1 -- update AFL++ bitmap
```

## Files

- `perf_mutator.c` - Main implementation (~2000 lines)
- `Makefile` - Build configuration
- `README.md` - This file

## Related Work

- `low-fidelity/tools/profiler/monitor.py` - External profiler (works, but separate from AFL++)
- `low-fidelity/PLAN.md` - Detailed testing notes and findings

## Next Steps

1. **Test on bare metal** with period-based sampling
2. **Verify samples are captured** from target binary
3. **Compare coverage** with instrumented baseline
4. **Enable time-based scheduling** if needed

## Author

Developed as part of the low-fidelity fuzzing research project.
