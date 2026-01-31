/*
 * Perf Coverage Custom Mutator for AFL++
 *
 * This custom mutator integrates perf-based coverage into AFL++ for
 * greybox fuzzing without binary instrumentation.
 *
 * Build:
 *   cd aflplusplus/custom_mutators/perf_coverage
 *   make
 *
 * Usage:
 *   AFL_CUSTOM_MUTATOR_LIBRARY=./perf_mutator.so \
 *   afl-fuzz -i in -o out -- ./target @@
 *
 * PERFORMANCE OPTIMIZATIONS (v2.0):
 * ================================
 * This version includes several optimizations to reduce overhead:
 *
 * 1. PROCESS-SPECIFIC SAMPLING (enabled by default)
 *    Instead of system-wide sampling (-a) which captures all processes
 *    and requires filtering, we use -p PID to only sample the target.
 *    This dramatically reduces perf overhead and eliminates filtering cost.
 *    Disable: AFL_PERF_USE_PID_FILTER=0
 *
 * 2. BATCH MODE / REDUCED READ FREQUENCY
 *    Don't read the perf pipe on every execution. Instead, read periodically:
 *    - Every N executions (default: 5000), OR
 *    - Every N milliseconds (default: 1000ms), whichever comes first.
 *    This accumulates samples over longer windows, critical for timer-based
 *    sampling where individual execution bursts are too short to sample.
 *    Configure: AFL_PERF_READ_INTERVAL=<execs> AFL_PERF_READ_INTERVAL_MS=<ms>
 *
 * 3. BATCH PROCESSING
 *    Process multiple lines at once with a larger buffer (16KB).
 *    Limits lines per read to prevent blocking (MAX_LINES_PER_BATCH=1000).
 *    When using -p PID mode, skip binary name filtering entirely.
 *
 * Environment Variables:
 *   AFL_PERF_READ_INTERVAL    - Read every N executions (default: 5000)
 *   AFL_PERF_READ_INTERVAL_MS - Read every N ms (default: 1000)
 *   AFL_PERF_USE_PID_FILTER   - Use -p PID mode: 1=yes (default), 0=no
 *   AFL_PERF_USE_PGREP        - Find PID by binary name using pgrep: 0=no (default), 1=yes
 *   AFL_PERF_TARGET           - Target binary path (for filtering if needed)
 *   AFL_PERF_DEBUG            - Enable debug logging: 1=yes, 0=no
 *   AFL_PERF_COVERAGE_MODE    - Coverage mode: "ip" (default) or "source"
 *   AFL_PERF_HZ               - Sampling frequency in Hz (default: 5000)
 *   AFL_PERF_MUST_EXEC        - Path to must-execute binary file
 *   AFL_PERF_START_DELAY      - Start perf after N executions (default: 100)
 *
 * SAMPLING MODE CONFIGURATION:
 *   AFL_PERF_SAMPLE_MODE      - "freq" (default) or "period"
 *                               freq: sample at fixed frequency (Hz)
 *                               period: sample every N events (e.g., instructions)
 *   AFL_PERF_PERIOD           - Event count for period mode (default: 100000)
 *   AFL_PERF_EVENT            - Perf event to use (default: "task-clock" for freq,
 *                               "instructions" for period mode)
 *
 * TIMER-BASED SAMPLING (for VMs without hardware PMU):
 *   Timer-based sampling (freq mode with task-clock) has limitations on fast
 *   targets that spend most time sleeping. The batch mode settings above
 *   (5000 execs / 1000ms intervals) accumulate samples over longer windows.
 *   For better results, use higher Hz (e.g., 10000) or switch to period mode
 *   on bare metal with hardware PMU support.
 *
 * Note: Period mode with "instructions" event requires hardware PMU support.
 *       On systems without PMU (e.g., some cloud VMs), use freq mode with
 *       "task-clock" event (the default).
 */

#include "afl-fuzz.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <poll.h>
#include <limits.h>

/* Configuration */
#define PERF_DEFAULT_HZ 5000            /* Higher default for timer-based sampling */
#define PERF_DEFAULT_PERIOD 100000      /* Event count for period mode */
#define PERF_DEFAULT_EVENT_FREQ "task-clock"
#define PERF_DEFAULT_EVENT_PERIOD "instructions"
#define IP_CACHE_SIZE 65536
#define IP_CACHE_MAX_ENTRIES 100000  /* Limit total IPs to prevent memory issues */
#define INPUT_WINDOW_INIT_CAP 1024
#define PERF_READ_BUF_SIZE 16384  /* Larger buffer for batch processing */
#define DEFAULT_TIME_UNIT_MS 100  /* 0.1 seconds */
#define MUST_EXEC_MAGIC "MEXE"
#define MUST_EXEC_VERSION 1
#define LOC_HASH_SIZE 65536  /* Hash table size for location lookup */

/* OPTIMIZATION: Read frequency control defaults - tuned for timer-based sampling */
#define DEFAULT_READ_INTERVAL 5000      /* Read every N executions (higher for batch mode) */
#define DEFAULT_READ_INTERVAL_MS 1000   /* Or every 1 second (longer for sample accumulation) */
#define MAX_LINES_PER_BATCH 10000       /* Process up to this many lines per read call */

/* Hash function for IPs */
static inline u32 hash_ip(u64 ip) {
    /* FNV-1a hash */
    u32 hash = 2166136261u;
    for (int i = 0; i < 8; i++) {
        hash ^= (ip >> (i * 8)) & 0xFF;
        hash *= 16777619u;
    }
    return hash;
}

/* Hash function for file:line */
static inline u32 hash_file_line(const char *file, u32 line) {
    u32 hash = 2166136261u;
    for (const char *p = file; *p; p++) {
        hash ^= (u8)*p;
        hash *= 16777619u;
    }
    hash ^= line;
    hash *= 16777619u;
    return hash;
}

/*
 * Must-Execute Data Structures
 * Binary format from convert_to_c.py
 */

/* Location entry in must-execute data */
typedef struct must_exec_loc {
    u32 file_offset;      /* Offset into string table */
    u32 line;             /* Line number */
    u32 cluster_id;       /* Cluster ID */
    u32 n_must_exec;      /* Number of must-execute locations */
    u32 must_exec_offset; /* Offset into must-exec index array */
} must_exec_loc_t;

/* Hash table entry for fast location lookup */
typedef struct loc_hash_entry {
    const char *file;     /* Pointer into string table */
    u32 line;
    u32 loc_idx;          /* Index in locations array */
    struct loc_hash_entry *next;
} loc_hash_entry_t;

/* Must-execute data loaded from binary file */
typedef struct must_exec_data {
    u32 n_locs;           /* Number of locations */
    u32 n_edges;          /* Total must-exec edges */
    must_exec_loc_t *locs; /* Location table */
    u32 *must_exec_indices; /* Must-exec index array */
    char *string_table;   /* String table */
    loc_hash_entry_t *hash_buckets[LOC_HASH_SIZE]; /* Hash table for lookup */
    u8 *covered;          /* Bitmap of covered locations */
} must_exec_data_t;

/* IP Cache entry - stores IP to source location mapping */
typedef struct ip_cache_entry {
    u64 ip;
    u32 bitmap_idx;
    u8  seen;
    u8  resolved;           /* 1 if addr2line resolution attempted */
    char *source_file;      /* Source file path (NULL if unresolved) */
    u32 line_number;        /* Line number (0 if unresolved) */
    struct ip_cache_entry *next;
} ip_cache_entry_t;

/* IP Cache */
typedef struct ip_cache {
    ip_cache_entry_t *buckets[IP_CACHE_SIZE];
    u32 total_ips;
} ip_cache_t;

/* Input tracking for time window */
typedef struct input_window {
    u8 **inputs;
    u32 *lengths;
    u32 count;
    u32 capacity;
} input_window_t;

/* Sampling mode: frequency-based or period-based */
typedef enum {
    PERF_SAMPLE_FREQ,           /* Sample at fixed frequency (Hz) */
    PERF_SAMPLE_PERIOD          /* Sample every N events */
} perf_sample_mode_t;

/* Perf pipeline state */
typedef struct perf_state {
    pid_t record_pid;
    pid_t script_pid;
    int   script_stdout_fd;
    char  read_buf[PERF_READ_BUF_SIZE];
    int   read_buf_pos;
    int   read_buf_len;
    u32   hz;                   /* Sampling frequency (freq mode) */
    u32   period;               /* Event count (period mode) */
    char  event[64];            /* Perf event name */
    perf_sample_mode_t sample_mode;
    u8    running;
    pid_t target_pid;           /* PID being monitored (for process-specific mode) */
    u8    use_pid_filter;       /* 1 = use -p PID, 0 = use -a (system-wide) */
    u8    use_pgrep;            /* 1 = use pgrep to find PID by binary name */
} perf_state_t;

/* addr2line subprocess state */
typedef struct addr2line_state {
    pid_t pid;
    int   stdin_fd;         /* Write IPs here */
    int   stdout_fd;        /* Read results here */
    char  read_buf[4096];
    int   read_buf_len;
    u8    running;
} addr2line_state_t;

/* Coverage mode */
typedef enum {
    COVERAGE_MODE_IP,       /* Use raw IPs (fast, no resolution) */
    COVERAGE_MODE_SOURCE    /* Resolve to source:line (slower, more accurate) */
} coverage_mode_t;

/* Main mutator data */
typedef struct perf_mutator {
    afl_state_t   *afl;
    ip_cache_t    *ip_cache;
    input_window_t *input_window;
    perf_state_t  *perf;
    addr2line_state_t *addr2line;
    must_exec_data_t *must_exec;

    /* Target binary path (full path for addr2line) */
    char *target_path;
    /* Target binary name (for filtering system-wide samples) */
    char *target_binary;

    /* Coverage mode */
    coverage_mode_t coverage_mode;
    u8 must_exec_enabled;  /* 1 if must-execute expansion is enabled */

    /* Time-based scheduling */
    u64 time_unit_ms;
    u64 window_start_time;
    u64 window_time_budget_ms;

    /* Coverage tracking */
    u32 new_coverage_in_window;
    u32 total_ips_seen;

    /* Stats */
    u64 total_execs;
    u64 total_perf_samples;

    /* Read frequency control - reduces overhead by not reading every execution */
    u32 read_interval;          /* Read perf data every N executions */
    u64 last_read_time_ms;      /* Last time we read perf data */
    u32 read_interval_ms;       /* Minimum ms between reads (alternative to exec count) */
    u32 execs_since_last_read;  /* Counter for execution-based interval */

    /* Debug/logging */
    FILE *log_file;
    u8 debug;
} perf_mutator_t;

/* Forward declarations */
static void save_window_inputs(perf_mutator_t *data);

/* Get current time in milliseconds */
static inline u64 get_cur_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);
}

/*
 * IP Cache functions
 */

static ip_cache_t *ip_cache_init(void) {
    ip_cache_t *cache = calloc(1, sizeof(ip_cache_t));
    if (!cache) return NULL;
    return cache;
}

static void ip_cache_destroy(ip_cache_t *cache) {
    if (!cache) return;
    for (int i = 0; i < IP_CACHE_SIZE; i++) {
        ip_cache_entry_t *entry = cache->buckets[i];
        while (entry) {
            ip_cache_entry_t *next = entry->next;
            free(entry->source_file);
            free(entry);
            entry = next;
        }
    }
    free(cache);
}

/* Returns bitmap index for IP, adds to cache if not present */
static u32 ip_cache_lookup_or_add(ip_cache_t *cache, u64 ip, u8 *is_new) {
    u32 bucket = hash_ip(ip) % IP_CACHE_SIZE;
    ip_cache_entry_t *entry = cache->buckets[bucket];

    while (entry) {
        if (entry->ip == ip) {
            *is_new = !entry->seen;
            entry->seen = 1;
            return entry->bitmap_idx;
        }
        entry = entry->next;
    }

    /* Not found, add new entry */
    /* Check if we've hit the max entries limit */
    if (cache->total_ips >= IP_CACHE_MAX_ENTRIES) {
        *is_new = 0;
        return hash_ip(ip);  /* Return hash but don't add to cache */
    }

    entry = malloc(sizeof(ip_cache_entry_t));
    if (!entry) {
        *is_new = 0;
        return 0;
    }

    entry->ip = ip;
    /* Use hash directly as bitmap index (will be % map_size when used) */
    entry->bitmap_idx = hash_ip(ip);
    entry->seen = 1;
    entry->resolved = 0;
    entry->source_file = NULL;
    entry->line_number = 0;
    entry->next = cache->buckets[bucket];
    cache->buckets[bucket] = entry;
    cache->total_ips++;

    *is_new = 1;
    return entry->bitmap_idx;
}

/* Get cache entry for an IP (for resolution) */
static ip_cache_entry_t *ip_cache_get_entry(ip_cache_t *cache, u64 ip) {
    u32 bucket = hash_ip(ip) % IP_CACHE_SIZE;
    ip_cache_entry_t *entry = cache->buckets[bucket];
    while (entry) {
        if (entry->ip == ip) return entry;
        entry = entry->next;
    }
    return NULL;
}

/*
 * addr2line subprocess functions
 */

static addr2line_state_t *addr2line_init(const char *binary_path) {
    if (!binary_path) return NULL;

    addr2line_state_t *state = calloc(1, sizeof(addr2line_state_t));
    if (!state) return NULL;

    int stdin_pipe[2], stdout_pipe[2];
    if (pipe(stdin_pipe) < 0 || pipe(stdout_pipe) < 0) {
        free(state);
        return NULL;
    }

    state->pid = fork();
    if (state->pid < 0) {
        close(stdin_pipe[0]); close(stdin_pipe[1]);
        close(stdout_pipe[0]); close(stdout_pipe[1]);
        free(state);
        return NULL;
    }

    if (state->pid == 0) {
        /* Child: addr2line process */
        close(stdin_pipe[1]);  /* Close write end of stdin pipe */
        close(stdout_pipe[0]); /* Close read end of stdout pipe */

        dup2(stdin_pipe[0], STDIN_FILENO);
        close(stdin_pipe[0]);

        dup2(stdout_pipe[1], STDOUT_FILENO);
        close(stdout_pipe[1]);

        /* Redirect stderr to /dev/null */
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }

        /* Try llvm-addr2line first (faster), then fallback to addr2line */
        execlp("llvm-addr2line", "llvm-addr2line", "-f", "-e", binary_path, NULL);
        execlp("addr2line", "addr2line", "-f", "-e", binary_path, NULL);
        _exit(1);
    }

    /* Parent */
    close(stdin_pipe[0]);   /* Close read end */
    close(stdout_pipe[1]);  /* Close write end */

    state->stdin_fd = stdin_pipe[1];
    state->stdout_fd = stdout_pipe[0];
    state->read_buf_len = 0;
    state->running = 1;

    /* Set stdout to non-blocking */
    int flags = fcntl(state->stdout_fd, F_GETFL, 0);
    fcntl(state->stdout_fd, F_SETFL, flags | O_NONBLOCK);

    return state;
}

static void addr2line_destroy(addr2line_state_t *state) {
    if (!state) return;
    if (state->running) {
        close(state->stdin_fd);
        close(state->stdout_fd);
        kill(state->pid, SIGTERM);
        waitpid(state->pid, NULL, 0);
    }
    free(state);
}

/*
 * Resolve an IP address to source file:line using addr2line.
 * Updates the cache entry with the resolved information.
 * Returns 1 if resolved successfully, 0 otherwise.
 */
static int addr2line_resolve(addr2line_state_t *state, ip_cache_entry_t *entry) {
    if (!state || !state->running || !entry || entry->resolved) return 0;

    entry->resolved = 1;  /* Mark as attempted */

    /* Send IP to addr2line */
    char ip_str[32];
    int len = snprintf(ip_str, sizeof(ip_str), "0x%llx\n", (unsigned long long)entry->ip);
    if (write(state->stdin_fd, ip_str, len) != len) {
        return 0;
    }

    /* Read response (function name + file:line) */
    /* addr2line outputs two lines: function name, then file:line */
    char response[1024];
    int total_read = 0;
    int newlines = 0;
    int retries = 0;
    const int max_retries = 100;  /* 100ms total timeout */

    while (newlines < 2 && retries < max_retries) {
        int n = read(state->stdout_fd, response + total_read,
                     sizeof(response) - total_read - 1);
        if (n > 0) {
            total_read += n;
            response[total_read] = '\0';
            /* Count newlines */
            for (int i = total_read - n; i < total_read; i++) {
                if (response[i] == '\n') newlines++;
            }
        } else if (n < 0 && errno == EAGAIN) {
            /* No data available, wait a bit */
            usleep(1000);  /* 1ms */
            retries++;
        } else {
            break;
        }
    }

    if (newlines < 2) return 0;

    /* Parse response: skip function name (first line), parse file:line (second line) */
    char *second_line = strchr(response, '\n');
    if (!second_line) return 0;
    second_line++;  /* Skip newline */

    /* Check for "??:0" or "??:?" which means unresolved */
    if (strncmp(second_line, "??:", 3) == 0) return 0;

    /* Parse file:line */
    char *colon = strrchr(second_line, ':');
    if (!colon) return 0;

    /* Extract line number */
    char *endptr;
    long line = strtol(colon + 1, &endptr, 10);
    if (line <= 0 || line > INT_MAX) return 0;

    /* Extract file path */
    *colon = '\0';
    char *newline = strchr(second_line, '\n');
    if (newline) *newline = '\0';

    /* Trim leading/trailing whitespace */
    while (*second_line == ' ' || *second_line == '\t') second_line++;
    char *end = second_line + strlen(second_line) - 1;
    while (end > second_line && (*end == ' ' || *end == '\t' || *end == '\n'))
        *end-- = '\0';

    if (strlen(second_line) == 0) return 0;

    /* Store resolved information */
    entry->source_file = strdup(second_line);
    entry->line_number = (u32)line;

    return entry->source_file != NULL;
}

/*
 * Resolve IP to source:line and compute bitmap index based on source location.
 * This provides more stable coverage (same source line = same bitmap slot).
 */
static u32 resolve_ip_to_source_idx(perf_mutator_t *data, u64 ip, u8 *is_new) {
    if (!data || !data->ip_cache) {
        *is_new = 0;
        return 0;
    }

    /* First, do the normal IP lookup */
    u32 idx = ip_cache_lookup_or_add(data->ip_cache, ip, is_new);

    /* If not in source mode, just return the IP-based index */
    if (data->coverage_mode != COVERAGE_MODE_SOURCE) {
        return idx;
    }

    /* Get the cache entry for resolution */
    ip_cache_entry_t *entry = ip_cache_get_entry(data->ip_cache, ip);
    if (!entry) return idx;

    /* Resolve if not already done */
    if (!entry->resolved && data->addr2line && data->addr2line->running) {
        addr2line_resolve(data->addr2line, entry);
    }

    /* If resolved, compute index from source location */
    if (entry->source_file && entry->line_number > 0) {
        /* Hash file:line to get bitmap index */
        u32 hash = 2166136261u;  /* FNV-1a */
        for (const char *p = entry->source_file; *p; p++) {
            hash ^= (u8)*p;
            hash *= 16777619u;
        }
        hash ^= entry->line_number;
        hash *= 16777619u;

        entry->bitmap_idx = hash;
        return hash;
    }

    return idx;  /* Fall back to IP-based index */
}

/*
 * Must-Execute Data Functions
 */

static must_exec_data_t *must_exec_load(const char *path) {
    if (!path) return NULL;

    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "[PERF] Warning: Cannot open must-execute file: %s\n", path);
        return NULL;
    }

    /* Read and verify header */
    char magic[4];
    u32 version, n_locs, n_edges;

    if (fread(magic, 1, 4, f) != 4 || memcmp(magic, MUST_EXEC_MAGIC, 4) != 0) {
        fprintf(stderr, "[PERF] Error: Invalid must-execute file magic\n");
        fclose(f);
        return NULL;
    }

    if (fread(&version, 4, 1, f) != 1 || version != MUST_EXEC_VERSION) {
        fprintf(stderr, "[PERF] Error: Unsupported must-execute file version: %u\n", version);
        fclose(f);
        return NULL;
    }

    if (fread(&n_locs, 4, 1, f) != 1 || fread(&n_edges, 4, 1, f) != 1) {
        fprintf(stderr, "[PERF] Error: Failed to read must-execute header\n");
        fclose(f);
        return NULL;
    }

    /* Allocate main structure */
    must_exec_data_t *me = calloc(1, sizeof(must_exec_data_t));
    if (!me) {
        fclose(f);
        return NULL;
    }

    me->n_locs = n_locs;
    me->n_edges = n_edges;

    /* Allocate location table */
    me->locs = malloc(sizeof(must_exec_loc_t) * n_locs);
    if (!me->locs) goto fail;

    /* Read location table */
    for (u32 i = 0; i < n_locs; i++) {
        if (fread(&me->locs[i].file_offset, 4, 1, f) != 1 ||
            fread(&me->locs[i].line, 4, 1, f) != 1 ||
            fread(&me->locs[i].cluster_id, 4, 1, f) != 1 ||
            fread(&me->locs[i].n_must_exec, 4, 1, f) != 1 ||
            fread(&me->locs[i].must_exec_offset, 4, 1, f) != 1) {
            goto fail;
        }
    }

    /* Allocate and read must-exec index array */
    me->must_exec_indices = malloc(sizeof(u32) * n_edges);
    if (!me->must_exec_indices) goto fail;

    for (u32 i = 0; i < n_edges; i++) {
        if (fread(&me->must_exec_indices[i], 4, 1, f) != 1) {
            goto fail;
        }
    }

    /* Read string table (read rest of file) */
    long pos = ftell(f);
    fseek(f, 0, SEEK_END);
    long end = ftell(f);
    size_t str_table_size = end - pos;
    fseek(f, pos, SEEK_SET);

    me->string_table = malloc(str_table_size + 1);
    if (!me->string_table) goto fail;

    if (fread(me->string_table, 1, str_table_size, f) != str_table_size) {
        goto fail;
    }
    me->string_table[str_table_size] = '\0';

    fclose(f);

    /* Allocate covered bitmap */
    me->covered = calloc((n_locs + 7) / 8, 1);
    if (!me->covered) goto fail_after_close;

    /* Build hash table for file:line -> loc_idx lookup */
    for (u32 i = 0; i < n_locs; i++) {
        const char *file = me->string_table + me->locs[i].file_offset;
        u32 line = me->locs[i].line;
        u32 bucket = hash_file_line(file, line) % LOC_HASH_SIZE;

        loc_hash_entry_t *entry = malloc(sizeof(loc_hash_entry_t));
        if (!entry) continue;  /* Skip on allocation failure */

        entry->file = file;
        entry->line = line;
        entry->loc_idx = i;
        entry->next = me->hash_buckets[bucket];
        me->hash_buckets[bucket] = entry;
    }

    fprintf(stderr, "[PERF] Loaded must-execute data: %u locations, %u edges\n",
            n_locs, n_edges);
    return me;

fail:
    fclose(f);
fail_after_close:
    if (me->locs) free(me->locs);
    if (me->must_exec_indices) free(me->must_exec_indices);
    if (me->string_table) free(me->string_table);
    if (me->covered) free(me->covered);
    free(me);
    return NULL;
}

static void must_exec_destroy(must_exec_data_t *me) {
    if (!me) return;

    /* Free hash table entries */
    for (int i = 0; i < LOC_HASH_SIZE; i++) {
        loc_hash_entry_t *entry = me->hash_buckets[i];
        while (entry) {
            loc_hash_entry_t *next = entry->next;
            free(entry);
            entry = next;
        }
    }

    free(me->locs);
    free(me->must_exec_indices);
    free(me->string_table);
    free(me->covered);
    free(me);
}

/*
 * Look up file:line in must-execute data.
 * Returns location index, or -1 if not found.
 */
static int must_exec_lookup(must_exec_data_t *me, const char *file, u32 line) {
    if (!me || !file) return -1;

    u32 bucket = hash_file_line(file, line) % LOC_HASH_SIZE;
    loc_hash_entry_t *entry = me->hash_buckets[bucket];

    while (entry) {
        if (entry->line == line && strcmp(entry->file, file) == 0) {
            return (int)entry->loc_idx;
        }
        entry = entry->next;
    }

    return -1;  /* Not found */
}

/*
 * Mark a location and all its must-execute locations as covered.
 * Also updates the AFL++ bitmap for each newly covered location.
 * Returns number of newly covered locations.
 */
static u32 must_exec_expand(must_exec_data_t *me, int loc_idx,
                            u8 *trace_bits, u32 map_size) {
    if (!me || loc_idx < 0 || loc_idx >= (int)me->n_locs) return 0;

    u32 newly_covered = 0;
    must_exec_loc_t *loc = &me->locs[loc_idx];

    /* Iterate through all must-execute locations */
    u32 offset = loc->must_exec_offset;
    for (u32 i = 0; i < loc->n_must_exec; i++) {
        u32 must_idx = me->must_exec_indices[offset + i];
        if (must_idx >= me->n_locs) continue;

        /* Check if already covered */
        u32 byte_idx = must_idx / 8;
        u8 bit_mask = 1 << (must_idx % 8);

        if (!(me->covered[byte_idx] & bit_mask)) {
            /* Mark as covered */
            me->covered[byte_idx] |= bit_mask;
            newly_covered++;

            /* Update trace_bits with coverage for this location */
            if (trace_bits && map_size > 0) {
                must_exec_loc_t *must_loc = &me->locs[must_idx];
                const char *file = me->string_table + must_loc->file_offset;
                u32 line = must_loc->line;

                /* Hash file:line to bitmap index */
                u32 bitmap_idx = hash_file_line(file, line) % map_size;
                trace_bits[bitmap_idx]++;
            }
        }
    }

    return newly_covered;
}

/*
 * Process a perf sample with must-execute expansion.
 * Given a resolved source file:line, mark all must-execute locations as covered.
 * Returns number of newly covered locations.
 */
static u32 process_sample_with_must_exec(perf_mutator_t *data,
                                          const char *file, u32 line) {
    if (!data || !data->must_exec || !data->must_exec_enabled) return 0;

    /* Look up the location */
    int loc_idx = must_exec_lookup(data->must_exec, file, line);
    if (loc_idx < 0) return 0;

    /* Expand must-execute locations */
    return must_exec_expand(data->must_exec, loc_idx,
                            data->afl->fsrv.trace_bits,
                            data->afl->fsrv.map_size);
}

/*
 * Input window functions
 */

static input_window_t *input_window_init(void) {
    input_window_t *win = malloc(sizeof(input_window_t));
    if (!win) return NULL;

    win->capacity = INPUT_WINDOW_INIT_CAP;
    win->inputs = malloc(sizeof(u8*) * win->capacity);
    win->lengths = malloc(sizeof(u32) * win->capacity);
    win->count = 0;

    if (!win->inputs || !win->lengths) {
        free(win->inputs);
        free(win->lengths);
        free(win);
        return NULL;
    }

    return win;
}

static void input_window_clear(input_window_t *win) {
    if (!win) return;
    for (u32 i = 0; i < win->count; i++) {
        free(win->inputs[i]);
    }
    win->count = 0;
}

static void input_window_destroy(input_window_t *win) {
    if (!win) return;
    input_window_clear(win);
    free(win->inputs);
    free(win->lengths);
    free(win);
}

static int input_window_add(input_window_t *win, const u8 *buf, u32 len) {
    if (win->count >= win->capacity) {
        u32 new_cap = win->capacity * 2;
        u8 **new_inputs = realloc(win->inputs, sizeof(u8*) * new_cap);
        u32 *new_lengths = realloc(win->lengths, sizeof(u32) * new_cap);
        if (!new_inputs || !new_lengths) {
            return -1;
        }
        win->inputs = new_inputs;
        win->lengths = new_lengths;
        win->capacity = new_cap;
    }

    win->inputs[win->count] = malloc(len);
    if (!win->inputs[win->count]) return -1;

    memcpy(win->inputs[win->count], buf, len);
    win->lengths[win->count] = len;
    win->count++;

    return 0;
}

/*
 * Perf pipeline functions
 */

/*
 * Find a stable PID by binary name using pgrep.
 * Takes multiple samples to ensure the PID is persistent (not a short-lived fork).
 * Similar approach to monitor.py's find_stable_pid().
 *
 * Returns: PID if found, 0 if not found or unstable
 */
static pid_t find_pid_by_name(const char *bin_name) {
    if (!bin_name || !bin_name[0]) return 0;

    /* Truncate to 15 chars (Linux process name limit) */
    char name[16];
    strncpy(name, bin_name, 15);
    name[15] = '\0';

    /* Take 3 samples with short delays to find stable PIDs */
    pid_t samples[3][32];
    int counts[3] = {0, 0, 0};

    for (int round = 0; round < 3; round++) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "pgrep -x '%s' 2>/dev/null", name);

        FILE *fp = popen(cmd, "r");
        if (!fp) return 0;

        char line[32];
        while (fgets(line, sizeof(line), fp) && counts[round] < 32) {
            pid_t pid = (pid_t)atoi(line);
            if (pid > 0) {
                samples[round][counts[round]++] = pid;
            }
        }
        pclose(fp);

        if (round < 2) {
            usleep(100);  /* 100us between samples */
        }
    }

    /* Find PIDs that appear in all 3 samples (stable) */
    for (int i = 0; i < counts[0]; i++) {
        pid_t pid = samples[0][i];
        int found_in_all = 1;

        for (int round = 1; round < 3; round++) {
            int found = 0;
            for (int j = 0; j < counts[round]; j++) {
                if (samples[round][j] == pid) {
                    found = 1;
                    break;
                }
            }
            if (!found) {
                found_in_all = 0;
                break;
            }
        }

        if (found_in_all) {
            return pid;  /* Return first stable PID */
        }
    }

    return 0;  /* No stable PID found */
}

static perf_state_t *perf_init(void) {
    perf_state_t *perf = calloc(1, sizeof(perf_state_t));
    if (!perf) return NULL;
    perf->hz = PERF_DEFAULT_HZ;
    perf->period = PERF_DEFAULT_PERIOD;
    perf->sample_mode = PERF_SAMPLE_FREQ;  /* Default: frequency-based */
    strncpy(perf->event, PERF_DEFAULT_EVENT_FREQ, sizeof(perf->event) - 1);
    perf->script_stdout_fd = -1;
    perf->target_pid = 0;
    perf->use_pid_filter = 1;  /* Default: use process-specific sampling */
    return perf;
}

static int perf_start(perf_state_t *perf, pid_t target_pid) {
    int record_to_script[2];  /* pipe from record to script */
    int script_to_us[2];      /* pipe from script to us */

    if (pipe(record_to_script) < 0 || pipe(script_to_us) < 0) {
        perror("pipe");
        return -1;
    }

    /* Store target PID for potential restart */
    perf->target_pid = target_pid;

    /* Fork for perf record */
    perf->record_pid = fork();
    if (perf->record_pid < 0) {
        perror("fork record");
        return -1;
    }

    if (perf->record_pid == 0) {
        /* Child: perf record */
        close(record_to_script[0]);  /* Close read end */
        close(script_to_us[0]);
        close(script_to_us[1]);

        dup2(record_to_script[1], STDOUT_FILENO);
        close(record_to_script[1]);

        /* Redirect stderr to /dev/null to suppress perf warnings */
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }

        char pid_str[32];
        snprintf(pid_str, sizeof(pid_str), "%d", target_pid);

        /*
         * OPTIMIZATION 1: Process-specific sampling with -p PID
         *
         * We use -p PID with --inherit to sample the forkserver and all its
         * forked children (which run the actual target). Without --inherit,
         * perf would only sample the forkserver process itself.
         *
         * If target_pid is valid (>0) and use_pid_filter is enabled, use -p PID.
         * Otherwise fall back to system-wide sampling with filtering.
         */
        /*
         * PERSISTENT MODE OPTIMIZATION:
         * In persistent mode, the target runs in a loop within a single process.
         * We can use -p PID to sample just that process (no system-wide overhead).
         *
         * In regular forkserver mode, children are short-lived and -p doesn't
         * capture them reliably, so we fall back to system-wide sampling.
         */
        /*
         * Build perf record command based on sample_mode configuration.
         * Supports both frequency-based (-F hz) and period-based (-c period) sampling.
         */
        char hz_str[32], period_str[32];
        snprintf(hz_str, sizeof(hz_str), "%u", perf->hz);
        snprintf(period_str, sizeof(period_str), "%u", perf->period);

        if (perf->use_pid_filter && target_pid > 0) {
            /* Process-specific sampling WITHOUT --inherit.
             *
             * NOTE: In persistent mode, we attach directly to the persistent child
             * process (child_pid). This is the process that loops in AFL_LOOP()
             * and executes the target code. We don't need --inherit because:
             * 1. The persistent child doesn't fork new children
             * 2. --inherit can cause unexpected behavior with perf
             * 3. monitor.py (which works) doesn't use --inherit
             *
             * For non-persistent mode, system-wide sampling (-a) is used instead.
             */
            if (perf->sample_mode == PERF_SAMPLE_PERIOD) {
                /* Period mode: sample every N events */
                execlp("perf", "perf", "record",
                       "--no-buffering",
                       "--call-graph", "fp",
                       "-p", pid_str,
                       "-e", perf->event,
                       "-c", period_str,
                       "-o", "-",
                       NULL);
            } else {
                /* Frequency mode: sample at fixed Hz */
                execlp("perf", "perf", "record",
                       "--no-buffering",
                       "--call-graph", "fp",
                       "-p", pid_str,
                       "-e", perf->event,
                       "-F", hz_str,
                       "-o", "-",
                       NULL);
            }
            /* If execlp fails, we won't reach here */
        }
        /* Fallback: system-wide sampling (for non-persistent mode) */
        if (perf->sample_mode == PERF_SAMPLE_PERIOD) {
            execlp("perf", "perf", "record",
                   "--no-buffering",
                   "--call-graph", "fp",
                   "-a",
                   "-e", perf->event,
                   "-c", period_str,
                   "-o", "-",
                   NULL);
        } else {
            execlp("perf", "perf", "record",
                   "--no-buffering",
                   "--call-graph", "fp",
                   "-a",
                   "-e", perf->event,
                   "-F", hz_str,
                   "-o", "-",
                   NULL);
        }
        perror("execlp perf record");
        _exit(1);
    }

    /* Parent continues... */
    close(record_to_script[1]);  /* Close write end */

    /* Fork for perf script */
    perf->script_pid = fork();
    if (perf->script_pid < 0) {
        perror("fork script");
        kill(perf->record_pid, SIGTERM);
        return -1;
    }

    if (perf->script_pid == 0) {
        /* Child: perf script */
        close(script_to_us[0]);  /* Close read end */

        dup2(record_to_script[0], STDIN_FILENO);
        close(record_to_script[0]);

        dup2(script_to_us[1], STDOUT_FILENO);
        close(script_to_us[1]);

        execlp("perf", "perf", "script", "-i", "-", NULL);
        perror("execlp perf script");
        _exit(1);
    }

    /* Parent */
    close(record_to_script[0]);
    close(script_to_us[1]);

    /* Wait a bit and check if children started successfully */
    /* usleep removed - was causing issues with persistent mode */

    int status;
    pid_t wpid = waitpid(perf->record_pid, &status, WNOHANG);
    if (wpid == perf->record_pid) {
        /* perf record exited immediately - likely permission error */
        close(script_to_us[0]);
        kill(perf->script_pid, SIGTERM);
        waitpid(perf->script_pid, NULL, 0);
        perf->record_pid = 0;
        perf->script_pid = 0;
        return -1;
    }

    wpid = waitpid(perf->script_pid, &status, WNOHANG);
    if (wpid == perf->script_pid) {
        /* perf script exited immediately */
        close(script_to_us[0]);
        kill(perf->record_pid, SIGTERM);
        waitpid(perf->record_pid, NULL, 0);
        perf->record_pid = 0;
        perf->script_pid = 0;
        return -1;
    }

    /* Set non-blocking on our read end */
    int flags = fcntl(script_to_us[0], F_GETFL, 0);
    fcntl(script_to_us[0], F_SETFL, flags | O_NONBLOCK);

    perf->script_stdout_fd = script_to_us[0];
    perf->running = 1;

    /*
     * Give perf a brief moment to start. The streaming pipeline needs
     * some time before it starts producing output, but a long delay here
     * interferes with AFL++ calibration timing. Use a short delay and
     * accept that the first few reads may return empty.
     */
    usleep(10000);  /* 10ms - just enough for process startup */

    return 0;
}

static void perf_stop(perf_state_t *perf) {
    if (!perf->running) return;

    if (perf->record_pid > 0) {
        kill(perf->record_pid, SIGTERM);
        waitpid(perf->record_pid, NULL, 0);
    }
    if (perf->script_pid > 0) {
        kill(perf->script_pid, SIGTERM);
        waitpid(perf->script_pid, NULL, 0);
    }
    if (perf->script_stdout_fd >= 0) {
        close(perf->script_stdout_fd);
        perf->script_stdout_fd = -1;
    }

    perf->running = 0;
}

static void perf_destroy(perf_state_t *perf) {
    if (!perf) return;
    perf_stop(perf);
    free(perf);
}

/*
 * Check if a line matches our target binary
 * Format: "binary 12345 12345.678901: 1234 cycles: ip func+0x10 (/path/to/bin)"
 * Check process name (first field) OR binary path (in parentheses)
 * Note: forkserver children may show "(/ (deleted))" for binary path
 */
static int line_matches_target(const char *line, const char *target_binary) {
    if (!target_binary || !*target_binary) return 1;  /* No filter */

    /* Skip leading whitespace and get process name (first field) */
    const char *p = line;
    while (*p == ' ') p++;
    const char *proc_start = p;
    while (*p && *p != ' ') p++;
    size_t proc_len = p - proc_start;

    /* Check if process name starts with target (may be truncated) */
    size_t target_len = strlen(target_binary);
    size_t compare_len = proc_len < target_len ? proc_len : target_len;
    if (compare_len >= 8 && strncmp(proc_start, target_binary, compare_len) == 0) {
        return 1;  /* Process name matches */
    }

    /* Also check binary path in parentheses at the end */
    const char *paren = strrchr(line, '(');
    if (!paren) return 0;

    paren++;  /* Skip '(' */
    const char *end = strchr(paren, ')');
    if (!end) return 0;

    /* Skip "(/ (deleted))" which is common for forkserver children */
    if (strncmp(paren, "/ (deleted)", 11) == 0) return 0;

    /* Extract just the basename for comparison */
    const char *slash = strrchr(paren, '/');
    const char *binary_start = slash ? slash + 1 : paren;

    size_t binary_len = end - binary_start;

    /* Compare basename */
    if (binary_len != target_len) return 0;
    return strncmp(binary_start, target_binary, binary_len) == 0;
}

/*
 * Parse IP from perf script line
 *
 * Format:
 * "proc PID timestamp: count event:ppp: IP symbol (binary)"
 *
 * Example:
 * "libxml2_fuzz_no  453663 1907301.659194:     100000 task-clock:ppp:      7ffff7fd6534 ..."
 *
 * The IP is always after the event field suffix (":ppp:") followed by whitespace.
 * Strategy: Find ":ppp:" and extract the hex number after it.
 */
static u64 parse_ip_from_line(const char *line) {
    const char *p;

    /* Look for ":ppp:" which marks the end of the event field */
    p = strstr(line, ":ppp:");
    if (!p) {
        /* Try other common event suffixes */
        p = strstr(line, ":pp:");
        if (!p) {
            p = strstr(line, ":p:");
            if (!p) {
                /* Last resort: look for "clock:" pattern and skip past it */
                p = strstr(line, "clock:");
                if (p) {
                    while (*p && *p != ' ') p++;
                } else {
                    return 0;
                }
            }
        }
    }

    if (!p) return 0;

    /* Skip past the event suffix (e.g., ":ppp:") */
    while (*p && *p != ' ') p++;

    /* Skip whitespace to get to the IP */
    while (*p == ' ' || *p == '\t') p++;

    if (!*p) return 0;

    /* The IP should start with a hex digit */
    if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F'))) {
        return 0;
    }

    /* Parse hex IP */
    u64 ip = 0;
    while (*p && *p != ' ') {
        char c = *p++;
        if (c >= '0' && c <= '9') {
            ip = (ip << 4) | (c - '0');
        } else if (c >= 'a' && c <= 'f') {
            ip = (ip << 4) | (c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            ip = (ip << 4) | (c - 'A' + 10);
        } else {
            break;
        }
    }

    /* Sanity check: valid IPs should be large enough (kernel 0xffff... or user 0x7fff...) */
    if (ip < 0x10000) return 0;

    return ip;
}

/*
 * Read and process perf samples (batch processing version)
 *
 * OPTIMIZATION 3: Batch processing
 * - Process multiple lines at once instead of one at a time
 * - Use larger read buffer (16KB)
 * - Limit lines processed per call to avoid blocking
 * - Skip filtering when using process-specific sampling (-p PID)
 *
 * Returns number of new IPs found
 */
static u32 perf_read_samples(perf_mutator_t *data) {
    if (!data || !data->ip_cache) return 0;
    perf_state_t *perf = data->perf;
    if (!perf || !perf->running || perf->script_stdout_fd < 0) return 0;

    u32 new_ips = 0;
    u32 lines_processed = 0;

    /* Ensure buffer state is valid */
    if (perf->read_buf_len < 0 || perf->read_buf_len >= PERF_READ_BUF_SIZE) {
        perf->read_buf_len = 0;
    }

    /*
     * OPTIMIZATION: When using -p PID mode, we don't need to filter by binary name
     * since all samples are already from the target process.
     */
    int skip_binary_filter = perf->use_pid_filter && perf->target_pid > 0;

    /* Read available data in batches */
    int max_reads = 20;  /* Allow more reads per call for batch processing */
    while (max_reads-- > 0 && lines_processed < MAX_LINES_PER_BATCH) {
        int available = PERF_READ_BUF_SIZE - perf->read_buf_len - 1;
        if (available <= 0) {
            /* Buffer full, reset to prevent overflow */
            perf->read_buf_len = 0;
            available = PERF_READ_BUF_SIZE - 1;
        }

        ssize_t n = read(perf->script_stdout_fd,
                        perf->read_buf + perf->read_buf_len,
                        available);

        if (n <= 0) break;
        perf->read_buf_len += n;
        perf->read_buf[perf->read_buf_len] = '\0';

        /* Process complete lines in batch */
        char *start = perf->read_buf;
        char *newline;

        while ((newline = strchr(start, '\n')) != NULL && lines_processed < MAX_LINES_PER_BATCH) {
            *newline = '\0';
            lines_processed++;

            /* Filter by target binary if specified (skip if using -p PID mode) */
            int matches = skip_binary_filter ? 1 : line_matches_target(start, data->target_binary);

            /* Debug: log first few lines and matching lines */
            static int debug_lines = 0;
            static int match_lines = 0;
            if (data->debug && data->log_file && strlen(start) > 5) {
                /* Extract process name for debug */
                const char *p = start;
                while (*p == ' ') p++;
                char proc_buf[32] = {0};
                int i = 0;
                while (*p && *p != ' ' && i < 31) proc_buf[i++] = *p++;

                /* Log first 20 non-matching and first 20 matching */
                if ((matches && match_lines < 20) || (!matches && debug_lines < 20)) {
                    fprintf(data->log_file, "[RAW%s] proc='%s' line=%s\n",
                            matches ? "*" : "", proc_buf, start);
                    fflush(data->log_file);
                    if (matches) match_lines++;
                    else debug_lines++;
                }
            }

            if (!matches) {
                start = newline + 1;
                continue;
            }

            /* Parse this line */
            u64 ip = parse_ip_from_line(start);
            if (ip != 0) {
                u8 is_new = 0;
                u32 bitmap_idx;

                /* Use source resolution if in source mode, otherwise use IP-based */
                if (data->coverage_mode == COVERAGE_MODE_SOURCE) {
                    bitmap_idx = resolve_ip_to_source_idx(data, ip, &is_new);
                } else {
                    bitmap_idx = ip_cache_lookup_or_add(data->ip_cache, ip, &is_new);
                }

                /* Always update trace_bits for perf samples (not just new IPs) */
                u32 map_size = data->afl->fsrv.map_size;
                u8 *trace_bits = data->afl->fsrv.trace_bits;

                if (trace_bits && map_size > 0) {
                    /* Apply map_size modulo to bitmap index */
                    bitmap_idx = bitmap_idx % map_size;

                    /* Debug: log first few bitmap updates */
                    static int bitmap_debug = 0;
                    if (data->debug && data->log_file && is_new && bitmap_debug < 20) {
                        u8 virgin_val = 0;
                        if (data->afl->virgin_bits && bitmap_idx < map_size) {
                            virgin_val = data->afl->virgin_bits[bitmap_idx];
                        }
                        u8 trace_val = trace_bits[bitmap_idx];

                        /* Get source info if in source mode */
                        ip_cache_entry_t *entry = ip_cache_get_entry(data->ip_cache, ip);
                        if (entry && entry->source_file) {
                            fprintf(data->log_file,
                                    "[BITMAP] ip=0x%llx -> %s:%u idx=%u trace=%u virgin=%u\n",
                                    (unsigned long long)ip, entry->source_file,
                                    entry->line_number, bitmap_idx, trace_val, virgin_val);
                        } else {
                            fprintf(data->log_file,
                                    "[BITMAP] ip=0x%llx idx=%u trace=%u virgin=%u\n",
                                    (unsigned long long)ip, bitmap_idx, trace_val, virgin_val);
                        }
                        fflush(data->log_file);
                        bitmap_debug++;
                    }

                    trace_bits[bitmap_idx]++;

                    /* Must-execute expansion (only in source mode with resolved file:line) */
                    if (data->must_exec_enabled) {
                        ip_cache_entry_t *me_entry = ip_cache_get_entry(data->ip_cache, ip);
                        if (me_entry && me_entry->source_file && me_entry->line_number > 0) {
                            u32 expanded = process_sample_with_must_exec(data,
                                                                          me_entry->source_file,
                                                                          me_entry->line_number);
                            if (expanded > 0 && data->debug && data->log_file) {
                                static int me_debug = 0;
                                if (me_debug < 10) {
                                    fprintf(data->log_file,
                                            "[MUST_EXEC] %s:%u expanded %u additional locations\n",
                                            me_entry->source_file, me_entry->line_number, expanded);
                                    fflush(data->log_file);
                                    me_debug++;
                                }
                            }
                            /* Count expanded locations as new coverage */
                            if (expanded > 0) {
                                new_ips += expanded;
                            }
                        }
                    }
                }

                if (is_new) {
                    new_ips++;
                    data->total_ips_seen++;
                }

                data->total_perf_samples++;
            }

            start = newline + 1;
        }

        /* Move remaining data to start of buffer */
        /* Calculate how much of the buffer was consumed */
        size_t consumed = start - perf->read_buf;
        if (consumed > (size_t)perf->read_buf_len) {
            /* Shouldn't happen, but reset if it does */
            perf->read_buf_len = 0;
        } else {
            int remaining = perf->read_buf_len - consumed;
            if (remaining > 0 && remaining < PERF_READ_BUF_SIZE - 1) {
                memmove(perf->read_buf, start, remaining);
                perf->read_buf_len = remaining;
            } else {
                perf->read_buf_len = 0;
            }
        }
    }

    return new_ips;
}

/*
 * AFL++ Custom Mutator API
 */

perf_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {
    (void)seed;

    perf_mutator_t *data = calloc(1, sizeof(perf_mutator_t));
    if (!data) {
        perror("afl_custom_init alloc");
        return NULL;
    }

    data->afl = afl;

    /* Force a larger map size for perf-based coverage */
    /* This is needed because non-instrumented binaries may have small map_size */
    if (afl->fsrv.map_size < 65536) {
        /* Note: This might not work if map_size is set after our init */
        /* Log a warning for now */
        fprintf(stderr, "[PERF] Warning: map_size=%u is small, coverage may collide\n",
                afl->fsrv.map_size);
    }

    /* Initialize IP cache */
    data->ip_cache = ip_cache_init();
    if (!data->ip_cache) {
        free(data);
        return NULL;
    }

    /* Initialize input window */
    data->input_window = input_window_init();
    if (!data->input_window) {
        ip_cache_destroy(data->ip_cache);
        free(data);
        return NULL;
    }

    /* Initialize perf state */
    data->perf = perf_init();
    if (!data->perf) {
        input_window_destroy(data->input_window);
        ip_cache_destroy(data->ip_cache);
        free(data);
        return NULL;
    }

    /* Set time unit (default 0.1s = 100ms) */
    data->time_unit_ms = DEFAULT_TIME_UNIT_MS;

    /* Determine coverage mode from environment */
    char *mode_env = getenv("AFL_PERF_COVERAGE_MODE");
    if (mode_env && strcmp(mode_env, "source") == 0) {
        data->coverage_mode = COVERAGE_MODE_SOURCE;
    } else {
        data->coverage_mode = COVERAGE_MODE_IP;  /* Default: IP mode (faster) */
    }

    /* Extract target binary name and path for filtering perf samples */
    /* Try environment variable first, then fsrv.target_path, then argv */
    char *target_env = getenv("AFL_PERF_TARGET");
    if (target_env) {
        data->target_path = strdup(target_env);
        const char *slash = strrchr(target_env, '/');
        data->target_binary = strdup(slash ? slash + 1 : target_env);
    } else if (afl->fsrv.target_path && afl->fsrv.target_path[0]) {
        /* Cast u8* to char* for string functions */
        const char *path = (const char *)afl->fsrv.target_path;
        data->target_path = strdup(path);
        const char *slash = strrchr(path, '/');
        data->target_binary = strdup(slash ? slash + 1 : path);
    } else if (afl->argv && afl->argv[0]) {
        /* Try to get from command line arguments */
        data->target_path = strdup(afl->argv[0]);
        const char *slash = strrchr(afl->argv[0], '/');
        data->target_binary = strdup(slash ? slash + 1 : afl->argv[0]);
    }

    /* Initialize addr2line if in source mode */
    if (data->coverage_mode == COVERAGE_MODE_SOURCE && data->target_path) {
        data->addr2line = addr2line_init(data->target_path);
        if (!data->addr2line) {
            fprintf(stderr, "[PERF] Warning: Failed to start addr2line, falling back to IP mode\n");
            data->coverage_mode = COVERAGE_MODE_IP;
        }
    }

    /* Check for environment variable overrides */
    char *hz_env = getenv("AFL_PERF_HZ");
    if (hz_env) {
        data->perf->hz = atoi(hz_env);
        if (data->perf->hz < 1) data->perf->hz = PERF_DEFAULT_HZ;
    }

    /* Sampling mode configuration */
    char *sample_mode_env = getenv("AFL_PERF_SAMPLE_MODE");
    if (sample_mode_env && strcmp(sample_mode_env, "period") == 0) {
        data->perf->sample_mode = PERF_SAMPLE_PERIOD;
        /* Default event for period mode is instructions (requires PMU) */
        strncpy(data->perf->event, PERF_DEFAULT_EVENT_PERIOD, sizeof(data->perf->event) - 1);
    } else {
        data->perf->sample_mode = PERF_SAMPLE_FREQ;
        /* Default event for freq mode is task-clock (works without PMU) */
        strncpy(data->perf->event, PERF_DEFAULT_EVENT_FREQ, sizeof(data->perf->event) - 1);
    }

    char *period_env = getenv("AFL_PERF_PERIOD");
    if (period_env) {
        data->perf->period = (u32)atoi(period_env);
        if (data->perf->period < 1) data->perf->period = PERF_DEFAULT_PERIOD;
    }

    char *event_env = getenv("AFL_PERF_EVENT");
    if (event_env && event_env[0]) {
        strncpy(data->perf->event, event_env, sizeof(data->perf->event) - 1);
        data->perf->event[sizeof(data->perf->event) - 1] = '\0';
    }

    char *time_unit_env = getenv("AFL_PERF_TIME_UNIT_MS");
    if (time_unit_env) {
        data->time_unit_ms = atoi(time_unit_env);
        if (data->time_unit_ms < 1) data->time_unit_ms = DEFAULT_TIME_UNIT_MS;
    }

    /*
     * OPTIMIZATION 2: Read frequency control
     * Don't read perf pipe on every execution - read periodically instead.
     * This significantly reduces the overhead of pipe I/O and parsing.
     *
     * AFL_PERF_READ_INTERVAL: Read every N executions (default: 100)
     * AFL_PERF_READ_INTERVAL_MS: Or every N milliseconds (default: 50)
     * AFL_PERF_USE_PID_FILTER: Use -p PID instead of -a (default: 1 = enabled)
     */
    data->read_interval = DEFAULT_READ_INTERVAL;
    data->read_interval_ms = DEFAULT_READ_INTERVAL_MS;
    data->last_read_time_ms = 0;
    data->execs_since_last_read = 0;

    char *read_interval_env = getenv("AFL_PERF_READ_INTERVAL");
    if (read_interval_env) {
        int val = atoi(read_interval_env);
        if (val >= 1) data->read_interval = val;
    }

    char *read_interval_ms_env = getenv("AFL_PERF_READ_INTERVAL_MS");
    if (read_interval_ms_env) {
        int val = atoi(read_interval_ms_env);
        if (val >= 1) data->read_interval_ms = val;
    }

    /* Process-specific sampling control (default enabled for better performance) */
    char *pid_filter_env = getenv("AFL_PERF_USE_PID_FILTER");
    if (pid_filter_env && pid_filter_env[0] == '0') {
        data->perf->use_pid_filter = 0;  /* Disable, use system-wide */
    }

    /* Use pgrep to find PID by binary name (like monitor.py does) */
    char *pgrep_env = getenv("AFL_PERF_USE_PGREP");
    if (pgrep_env && pgrep_env[0] == '1') {
        data->perf->use_pgrep = 1;
    }

    char *debug_env = getenv("AFL_PERF_DEBUG");
    if (debug_env && debug_env[0] == '1') {
        data->debug = 1;
        char log_path[256];
        snprintf(log_path, sizeof(log_path), "%s/perf_mutator.log", afl->out_dir);
        data->log_file = fopen(log_path, "w");
    }

    /* Load must-execute data if specified (only useful in source mode) */
    char *must_exec_env = getenv("AFL_PERF_MUST_EXEC");
    if (must_exec_env && must_exec_env[0]) {
        if (data->coverage_mode != COVERAGE_MODE_SOURCE) {
            fprintf(stderr, "[PERF] Warning: Must-execute expansion requires source mode "
                    "(set AFL_PERF_COVERAGE_MODE=source)\n");
        } else {
            data->must_exec = must_exec_load(must_exec_env);
            if (data->must_exec) {
                data->must_exec_enabled = 1;
            } else {
                fprintf(stderr, "[PERF] Warning: Failed to load must-execute file: %s\n",
                        must_exec_env);
            }
        }
    }

    if (data->debug && data->log_file) {
        fprintf(data->log_file, "[INIT] sample_mode=%s, event=%s, hz=%u, period=%u, target=%s, mode=%s, must_exec=%s\n",
                data->perf->sample_mode == PERF_SAMPLE_PERIOD ? "period" : "freq",
                data->perf->event, data->perf->hz, data->perf->period,
                data->target_binary ? data->target_binary : "(none)",
                data->coverage_mode == COVERAGE_MODE_SOURCE ? "source" : "ip",
                data->must_exec_enabled ? "enabled" : "disabled");
        fprintf(data->log_file, "[INIT] OPTIMIZATIONS: read_interval=%u, read_interval_ms=%u, pid_filter=%s\n",
                data->read_interval, data->read_interval_ms,
                data->perf->use_pid_filter ? "enabled" : "disabled");
        fflush(data->log_file);
    }

    fprintf(stderr, "[PERF] Initialized with optimizations: "
            "read_interval=%u execs, read_interval_ms=%u ms, pid_filter=%s\n",
            data->read_interval, data->read_interval_ms,
            data->perf->use_pid_filter ? "enabled" : "disabled");

    return data;
}

/*
 * Called after each execution
 */
void afl_custom_post_run(perf_mutator_t *data) {
    data->total_execs++;

    /* Lazy initialization of target binary name and addr2line */
    if (!data->target_binary && data->total_execs == 1) {
        /* Try argv first (now populated) */
        if (data->afl->argv && data->afl->argv[0]) {
            data->target_path = strdup(data->afl->argv[0]);
            const char *slash = strrchr(data->afl->argv[0], '/');
            data->target_binary = strdup(slash ? slash + 1 : data->afl->argv[0]);
        } else if (data->afl->fsrv.target_path && data->afl->fsrv.target_path[0]) {
            const char *path = (const char *)data->afl->fsrv.target_path;
            data->target_path = strdup(path);
            const char *slash = strrchr(path, '/');
            data->target_binary = strdup(slash ? slash + 1 : path);
        }

        /* Start addr2line if in source mode and target is now known */
        if (data->coverage_mode == COVERAGE_MODE_SOURCE && data->target_path && !data->addr2line) {
            data->addr2line = addr2line_init(data->target_path);
            if (!data->addr2line) {
                if (data->debug && data->log_file) {
                    fprintf(data->log_file, "[WARN] Failed to start addr2line, falling back to IP mode\n");
                    fflush(data->log_file);
                }
                data->coverage_mode = COVERAGE_MODE_IP;
            } else {
                if (data->debug && data->log_file) {
                    fprintf(data->log_file, "[LAZY_INIT] addr2line started for %s\n", data->target_path);
                    fflush(data->log_file);
                }
            }
        }

        if (data->debug && data->log_file) {
            fprintf(data->log_file, "[LAZY_INIT] target=%s, path=%s, mode=%s\n",
                    data->target_binary ? data->target_binary : "(none)",
                    data->target_path ? data->target_path : "(none)",
                    data->coverage_mode == COVERAGE_MODE_SOURCE ? "source" : "ip");
            fflush(data->log_file);
        }
    }

    /* Debug: log trace_bits status on first call */
    if (data->debug && data->log_file && data->total_execs == 1) {
        fprintf(data->log_file, "[DEBUG] trace_bits=%p, map_size=%u, child_pid=%d, fsrv_pid=%d\n",
                (void*)data->afl->fsrv.trace_bits,
                data->afl->fsrv.map_size,
                data->afl->fsrv.child_pid,
                data->afl->fsrv.fsrv_pid);
        fflush(data->log_file);
    }

    /*
     * NOTE: Dummy bitmap writes removed.
     * The persistent mode binary already has instrumentation that fills trace_bits.
     * Adding fake coverage during calibration interferes with AFL++'s map size detection.
     */

    /* Start perf if not running (need target PID) */
    /*
     * IMPORTANT: Use child_pid (the actual executing process) instead of fsrv_pid.
     * In persistent mode, child_pid is the long-running process that loops.
     * The forkserver (fsrv_pid) just waits for signals and doesn't execute target code.
     *
     * If AFL_PERF_USE_PGREP=1, use pgrep to find the target PID by binary name.
     * This is more reliable and matches the approach used by monitor.py.
     *
     * Also delay perf start until after calibration (first ~100 execs) to avoid
     * interfering with AFL++'s timing measurements.
     */
    /* Delay perf start until after calibration phase */
    u32 perf_start_delay = 100;  /* Start after 100 execs (calibration) */
    char *delay_env = getenv("AFL_PERF_START_DELAY");
    if (delay_env) {
        perf_start_delay = (u32)atoi(delay_env);
    }

    /* Only do PID selection when we're actually going to start perf */
    if (!data->perf->running && data->total_execs >= perf_start_delay) {
        /*
         * PID selection priority:
         * 1. child_pid (the actual executing child in persistent mode) - BEST
         * 2. pgrep result (if enabled and child_pid not available)
         * 3. fsrv_pid (forkserver - last resort, usually won't give good samples)
         *
         * Note: pgrep often finds the forkserver (parent) not the child, so child_pid
         * is preferred when available.
         */
        pid_t target_pid = 0;

        /* Prefer child_pid - it's the actual executing process in persistent mode */
        if (data->afl->fsrv.child_pid > 0) {
            target_pid = data->afl->fsrv.child_pid;
        } else if (data->perf->use_pgrep && data->target_binary) {
            /* Fallback to pgrep if child_pid not available */
            target_pid = find_pid_by_name(data->target_binary);
            if (target_pid > 0 && data->debug && data->log_file) {
                fprintf(data->log_file, "[PGREP] Found PID %d for binary '%s' (child_pid not available)\n",
                        target_pid, data->target_binary);
                fflush(data->log_file);
            }
        } else if (data->afl->fsrv.fsrv_pid > 0) {
            /* Last resort: forkserver PID */
            target_pid = data->afl->fsrv.fsrv_pid;
        }

        if (target_pid > 0) {
        if (data->debug && data->log_file) {
            fprintf(data->log_file, "[PERF] Starting perf at exec %llu (delay=%u), child_pid=%d, fsrv_pid=%d, using=%d\n",
                    (unsigned long long)data->total_execs, perf_start_delay,
                    data->afl->fsrv.child_pid, data->afl->fsrv.fsrv_pid, target_pid);
            fflush(data->log_file);
        }
        if (perf_start(data->perf, target_pid) < 0) {
            if (data->debug && data->log_file) {
                fprintf(data->log_file, "[ERROR] Failed to start perf for pid %d (pid_filter=%s)\n",
                        target_pid, data->perf->use_pid_filter ? "on" : "off");
                fflush(data->log_file);
            }
            /*
             * If process-specific sampling failed, try system-wide as fallback.
             * This can happen if the forkserver PID is not valid for -p.
             */
            if (data->perf->use_pid_filter) {
                data->perf->use_pid_filter = 0;
                if (perf_start(data->perf, target_pid) == 0) {
                    if (data->debug && data->log_file) {
                        fprintf(data->log_file, "[PERF] Fallback to system-wide sampling succeeded\n");
                        fflush(data->log_file);
                    }
                    fprintf(stderr, "[PERF] Warning: Process-specific sampling failed, "
                            "using system-wide (slower)\n");
                }
            }
        } else {
            if (data->debug && data->log_file) {
                fprintf(data->log_file, "[PERF] Started perf for pid %d (pid_filter=%s)\n",
                        target_pid, data->perf->use_pid_filter ? "on" : "off");
                fflush(data->log_file);
            }
        }

        /* Initialize window timing */
        data->window_start_time = get_cur_time_ms();
        data->last_read_time_ms = data->window_start_time;

        /* NOTE: usleep removed - was causing issues with persistent mode.
         * Early reads may return no samples, but that's OK - we retry later. */
        }  /* if (target_pid > 0) */
    }

    /*
     * OPTIMIZATION 2: Reduce read frequency
     *
     * Instead of reading the perf pipe on every execution (which is expensive),
     * we read periodically based on:
     *   1. Execution count: every read_interval executions
     *   2. Time elapsed: every read_interval_ms milliseconds
     *
     * Whichever comes first triggers a read. This batches multiple samples
     * together and significantly reduces I/O overhead.
     */
    data->execs_since_last_read++;
    u64 cur_time = get_cur_time_ms();
    u64 time_since_last_read = cur_time - data->last_read_time_ms;

    /* Always read samples during calibration (first 100 execs) to ensure
     * AFL++ sees our coverage during dry run. After calibration, batch reads
     * for better performance. */
    int should_read = (data->total_execs < 100) ||  /* Always read during calibration */
                      (data->execs_since_last_read >= data->read_interval) ||
                      (time_since_last_read >= data->read_interval_ms);

    u32 new_ips = 0;

    if (should_read && data->perf && data->perf->running) {
        /* Read and process perf samples */
        if (data->debug && data->log_file && data->total_execs <= 5) {
            fprintf(data->log_file, "[DEBUG] Before perf_read_samples, exec=%llu, "
                    "execs_since_read=%u, time_since_read=%llu ms\n",
                    (unsigned long long)data->total_execs,
                    data->execs_since_last_read,
                    (unsigned long long)time_since_last_read);
            fflush(data->log_file);
        }

        new_ips = perf_read_samples(data);
        data->new_coverage_in_window += new_ips;

        /* Reset counters */
        data->execs_since_last_read = 0;
        data->last_read_time_ms = cur_time;

        if (data->debug && data->log_file && data->total_execs <= 5) {
            fprintf(data->log_file, "[DEBUG] After perf_read_samples, new_ips=%u\n", new_ips);
            fflush(data->log_file);
        }
    }

    /* Save inputs when new coverage is found */
    if (new_ips > 0 && data->input_window && data->input_window->count > 0) {
        save_window_inputs(data);
    }

    /* Debug logging */
    if (data->debug && data->log_file && data->total_execs % 1000 == 0) {
        fprintf(data->log_file,
                "[STATS] execs=%llu, perf_samples=%llu, ips_seen=%u, window_new=%u\n",
                (unsigned long long)data->total_execs,
                (unsigned long long)data->total_perf_samples,
                data->total_ips_seen,
                data->new_coverage_in_window);
        fflush(data->log_file);
    }
}

/*
 * Time-based scheduling: Calculate how many iterations to run for this seed
 * Formula: time_budget_ms = (perf_score / (100 * havoc_div)) * time_unit_ms
 *
 * Called before fuzzing a queue entry to determine iteration count.
 * Returns the number of iterations to perform (based on time budget estimate).
 */
u32 disabled_afl_custom_fuzz_count(perf_mutator_t *data, const u8 *buf, size_t buf_size) {
    (void)buf;
    (void)buf_size;

    if (!data || !data->afl) return 0;

    /* Check if time-based scheduling is enabled */
    char *time_based_env = getenv("AFL_PERF_TIME_BASED");
    if (!time_based_env || time_based_env[0] != '1') {
        /* Not using time-based scheduling, let AFL++ use default */
        return 0;
    }

    afl_state_t *afl = data->afl;

    /* Get current seed's perf_score and havoc_div */
    u32 perf_score = afl->queue_cur ? afl->queue_cur->perf_score : 100;
    u32 havoc_div = afl->havoc_div > 0 ? afl->havoc_div : 1;

    /* Calculate time budget in milliseconds */
    /* time_budget = (perf_score / (100 * havoc_div)) * time_unit_ms */
    u64 time_budget_ms = (perf_score * data->time_unit_ms) / (100 * havoc_div);
    if (time_budget_ms < 10) time_budget_ms = 10;  /* Minimum 10ms */

    /* Store the time budget for this window */
    data->window_time_budget_ms = time_budget_ms;
    data->window_start_time = get_cur_time_ms();
    data->new_coverage_in_window = 0;

    /* Estimate iterations based on typical exec speed */
    /* Assume ~1000 exec/s initially, adjust based on actual stats */
    u32 estimated_execs_per_sec = 1000;
    if (afl->fsrv.total_execs > 1000 && afl->prev_run_time > 0) {
        estimated_execs_per_sec = (afl->fsrv.total_execs * 1000) / afl->prev_run_time;
        if (estimated_execs_per_sec < 100) estimated_execs_per_sec = 100;
        if (estimated_execs_per_sec > 100000) estimated_execs_per_sec = 100000;
    }

    u32 estimated_iters = (time_budget_ms * estimated_execs_per_sec) / 1000;
    if (estimated_iters < 16) estimated_iters = 16;  /* Minimum iterations */
    if (estimated_iters > 1000000) estimated_iters = 1000000;  /* Cap at 1M */

    if (data->debug && data->log_file) {
        fprintf(data->log_file,
                "[TIME] seed=%u, perf_score=%u, havoc_div=%u, time_budget=%llums, est_iters=%u\n",
                afl->current_entry, perf_score, havoc_div,
                (unsigned long long)time_budget_ms, estimated_iters);
        fflush(data->log_file);
    }

    return estimated_iters;
}

/*
 * Called when a queue entry is selected (optional hook for time tracking)
 * Returns 1 to use this entry, 0 to skip
 */
u8 afl_custom_queue_get(perf_mutator_t *data, const u8 *filename) {
    (void)filename;

    if (!data) return 1;

    /* Reset time window for new seed */
    data->window_start_time = get_cur_time_ms();
    data->new_coverage_in_window = 0;

    /* Clear input window (if tracking inputs) */
    if (data->input_window) {
        input_window_clear(data->input_window);
    }

    return 1;  /* Accept this queue entry */
}

/*
 * Called before each execution with the input buffer.
 * We use this to track all inputs in the current time window.
 */
void afl_custom_fuzz_send(perf_mutator_t *data, const u8 *buf, size_t buf_size) {
    if (!data || !data->input_window || !buf || buf_size == 0) return;

    /* Check if input tracking is enabled */
    static int input_tracking_checked = 0;
    static int input_tracking_enabled = 0;
    if (!input_tracking_checked) {
        char *env = getenv("AFL_PERF_TRACK_INPUTS");
        input_tracking_enabled = (env && env[0] == '1');
        input_tracking_checked = 1;
    }
    if (!input_tracking_enabled) return;

    /* Limit window size to prevent memory exhaustion */
    if (data->input_window->count >= 10000) {
        /* Window full, stop tracking (could also use circular buffer) */
        return;
    }

    /* Add input to window */
    if (input_window_add(data->input_window, buf, (u32)buf_size) < 0) {
        if (data->debug && data->log_file) {
            fprintf(data->log_file, "[WARN] Failed to add input to window\n");
            fflush(data->log_file);
        }
    }
}

/*
 * Helper: Save an input to the AFL++ queue
 * Returns 0 on success, -1 on failure
 */
static int save_input_to_queue(perf_mutator_t *data, const u8 *buf, u32 len) {
    if (!data || !data->afl || !buf || len == 0) return -1;

    afl_state_t *afl = data->afl;

    /* Generate unique filename */
    static u32 saved_count = 0;
    char fname[256];
    snprintf(fname, sizeof(fname), "%s/queue/id:%06u,perf_window",
             afl->out_dir, afl->queued_items + saved_count);
    saved_count++;

    /* Write to file */
    int fd = open(fname, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        /* File might exist, try with timestamp */
        snprintf(fname, sizeof(fname), "%s/queue/id:%06u,perf_window,%llu",
                 afl->out_dir, afl->queued_items + saved_count,
                 (unsigned long long)get_cur_time_ms());
        fd = open(fname, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd < 0) return -1;
    }

    ssize_t written = write(fd, buf, len);
    close(fd);

    if (written != (ssize_t)len) {
        unlink(fname);
        return -1;
    }

    return 0;
}

/*
 * Save all inputs from the current window to the queue.
 * Called when new coverage is detected.
 */
static void save_window_inputs(perf_mutator_t *data) {
    if (!data || !data->input_window || data->input_window->count == 0) return;

    u32 saved = 0;
    for (u32 i = 0; i < data->input_window->count; i++) {
        if (save_input_to_queue(data, data->input_window->inputs[i],
                                data->input_window->lengths[i]) == 0) {
            saved++;
        }
    }

    if (data->debug && data->log_file) {
        fprintf(data->log_file, "[WINDOW] Saved %u/%u inputs from window\n",
                saved, data->input_window->count);
        fflush(data->log_file);
    }

    /* Clear window after saving */
    input_window_clear(data->input_window);
}

/*
 * Called when fuzzer is done
 */
void afl_custom_deinit(perf_mutator_t *data) {
    if (!data) return;

    if (data->debug && data->log_file) {
        fprintf(data->log_file,
                "[DEINIT] total_execs=%llu, total_perf_samples=%llu, total_ips=%u\n",
                (unsigned long long)data->total_execs,
                (unsigned long long)data->total_perf_samples,
                data->total_ips_seen);
        fclose(data->log_file);
    }

    perf_destroy(data->perf);
    addr2line_destroy(data->addr2line);
    must_exec_destroy(data->must_exec);
    input_window_destroy(data->input_window);
    ip_cache_destroy(data->ip_cache);
    free(data->target_path);
    free(data->target_binary);
    free(data);
}
