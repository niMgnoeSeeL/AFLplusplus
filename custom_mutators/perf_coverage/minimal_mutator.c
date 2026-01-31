/*
 * Minimal custom mutator - does nothing, just tests if custom mutators work
 */

#include "afl-fuzz.h"

typedef struct {
    afl_state_t *afl;
    unsigned int count;
} minimal_t;

minimal_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {
    (void)seed;
    minimal_t *data = calloc(1, sizeof(minimal_t));
    if (!data) return NULL;
    data->afl = afl;
    fprintf(stderr, "[MINIMAL] init called\n");
    return data;
}

void afl_custom_deinit(minimal_t *data) {
    fprintf(stderr, "[MINIMAL] deinit called, count=%u\n", data ? data->count : 0);
    free(data);
}

void afl_custom_post_run(minimal_t *data) {
    if (data) {
        data->count++;
        if (data->count <= 5 || data->count % 1000 == 0) {
            fprintf(stderr, "[MINIMAL] post_run count=%u\n", data->count);
        }
    }
}
