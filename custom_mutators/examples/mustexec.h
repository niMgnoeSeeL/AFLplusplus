#pragma once
#define ENV_BBINFO_PATH "ST_BBINFO_PATH"
#define ENV_MUSTEXECINFO_PATH "ST_MUSTEXECINFO_PATH"

void init_random();

cJSON *load_json(const char *filepath);

typedef struct Key2LinesCacheEntry Key2LinesCacheEntry;
typedef struct Key2LinesCacheTable Key2LinesCacheTable;
typedef struct LineSetsEntry       LineSetsEntry;
typedef struct LineSetsTable       LineSetsTable;

const char  *get_line_prof(Key2LinesCacheTable **ptab, cJSON *bbinfo, int key);
const char **get_bb_prof(LineSetsTable **ptab, cJSON *mustexecinfo,
                         const char *line);
const char **get_intra_prof(LineSetsTable **ptab, cJSON *mustexecinfo,
                            const char *line);
const char **get_inter_prof(LineSetsTable **ptab, cJSON *mustexecinfo,
                            const char *line);

void clear_line_cache(Key2LinesCacheTable *tab);
void clear_linesets_cache(LineSetsTable *tab);