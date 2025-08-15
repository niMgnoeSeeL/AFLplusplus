#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "cJSON.h"
#include "uthash.h"

// For random number generation.
#include <time.h>

void init_random(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  unsigned seed = (unsigned)(ts.tv_sec ^ ts.tv_nsec);
  // FILE *f = fopen("/tmp/ft_profile.log", "a");
  // if (f == NULL) {
  //   perror("ERROR: Could not open profile log file!");
  //   return;
  // }
  // fprintf(f, "Random seed initialized: %u\n", seed);
  // fclose(f);
  srand(seed);
}

cJSON *load_json(const char *filepath) {
  FILE *file = fopen(filepath, "r");
  if (!file) {
    perror("fopen");
    return NULL;
  }
  fseek(file, 0, SEEK_END);
  long size = ftell(file);
  fseek(file, 0, SEEK_SET);
  char *data = (char *)malloc(size + 1);
  fread(data, 1, size, file);
  data[size] = '\0';
  fclose(file);
  cJSON *json = cJSON_Parse(data);
  free(data);
  if (!json) {
    fprintf(stderr, "Error before: [%s]\n", cJSON_GetErrorPtr());
    return NULL;
  }
  return json;
}

/*
cJSON *bbinfo:
{
  "basic_blocks": [
    {
      "id": 0,
      "file": "/home/benchmark/tcas-home/tcas.c",
      "function": "initialize",
      "lines": [
        56,
        57,
        58,
        59,
        60
      ]
    },
    ...
*/

typedef struct Key2LinesCacheEntry {
  int            key;
  char          *func;
  int           *lines;
  int            n;
  UT_hash_handle hh;
} Key2LinesCacheEntry;

typedef struct Key2LinesCacheTable {
  Key2LinesCacheEntry *head;
} Key2LinesCacheTable;

static Key2LinesCacheEntry *cache_find(Key2LinesCacheTable *tab, int key) {
  Key2LinesCacheEntry *e = NULL;
  if (!tab) return NULL;
  HASH_FIND_INT(tab->head, &key, e);
  return e;
}

static char *xstrdup_local(const char *s) {
  if (!s) return NULL;
  size_t n = strlen(s) + 1;
  char  *p = (char *)malloc(n);
  if (p) memcpy(p, s, n);
  return p;
}

static Key2LinesCacheEntry *cache_insert_from_json(Key2LinesCacheTable **ptab,
                                                   cJSON *bbinfo, int key) {
  if (!*ptab) {
    *ptab = calloc(1, sizeof(**ptab));
    if (!*ptab) return NULL;
  }

  cJSON *bb_array = cJSON_GetObjectItem(bbinfo, "basic_blocks");
  if (!bb_array || !cJSON_IsArray(bb_array)) return NULL;

  for (cJSON *bb_item = bb_array->child; bb_item; bb_item = bb_item->next) {
    cJSON *id = cJSON_GetObjectItem(bb_item, "id");
    if (!id || !cJSON_IsNumber(id) || id->valueint != key) continue;

    cJSON *function = cJSON_GetObjectItem(bb_item, "function");
    cJSON *lines = cJSON_GetObjectItem(bb_item, "lines");
    if (!function || !cJSON_IsString(function) || !lines ||
        !cJSON_IsArray(lines))
      return NULL;

    int n = cJSON_GetArraySize(lines);
    if (n <= 0) return NULL;

    Key2LinesCacheEntry *e =
        (Key2LinesCacheEntry *)calloc(1, sizeof(Key2LinesCacheEntry));
    if (!e) return NULL;

    e->key = key;
    e->func = xstrdup_local(function->valuestring);
    e->lines = malloc(n * sizeof(int));
    e->n = n;
    if (!e->func || !e->lines) {
      free(e->func);
      free(e->lines);
      free(e);
      return NULL;
    }
    for (int i = 0; i < n; i++) {
      cJSON *line = cJSON_GetArrayItem(lines, i);
      if (!line || !cJSON_IsNumber(line)) {
        free(e->func);
        free(e->lines);
        free(e);
        return NULL;
      }
      e->lines[i] = line->valueint;
    }

    HASH_ADD_INT((*ptab)->head, key, e);
    return e;
  }

  return NULL;
}

void clear_line_cache(Key2LinesCacheTable *tab) {
  if (!tab) return;
  Key2LinesCacheEntry *cur, *tmp;
  HASH_ITER(hh, tab->head, cur, tmp) {
    HASH_DEL(tab->head, cur);
    free(cur->func);
    free(cur->lines);
    free(cur);
  }
  free(tab);
}

const char *get_line_prof(Key2LinesCacheTable **ptab, cJSON *bbinfo, int key) {
  // should return "<function>-<line>"
  Key2LinesCacheEntry *e = cache_find(*ptab, key);
  if (!e) e = cache_insert_from_json(ptab, bbinfo, key);
  if (!e) return NULL;
  int         line_index = rand() % e->n;
  int         line = e->lines[line_index];
  static char buf[256];
  snprintf(buf, sizeof(buf), "%s-L%d", e->func, line);
  return buf;
}

/*
cJSON *mustexecinfo:
{
  "ALIM-L64": {
    "bbs": [
      "ALIM-B0"
    ],
    "intra": [
      "ALIM-B0"
    ],
    "inter": [
      "ALIM-B0",
      "Inhibit_Biased_Climb-B0",
      "Inhibit_Biased_Climb-B8",
      "Non_Crossing_Biased_Climb-B0",
      "Non_Crossing_Biased_Climb-B10",
      ...
    ]
  },
  ...
*/

/* ----- mustexecinfo: line(string) -> {bbs[], intra[], inter[]} cache ----- */
typedef struct LineSetsEntry {
  char          *line_key; /* hash key (strdup) */
  char         **bbs;
  int            nbbs;
  char         **intra;
  int            nintra;
  char         **inter;
  int            ninter;
  UT_hash_handle hh;
} LineSetsEntry;

typedef struct LineSetsTable {
  LineSetsEntry *head;
} LineSetsTable;

static LineSetsEntry *linesets_find(LineSetsTable *tab, const char *line) {
  if (!tab || !line) return NULL;
  LineSetsEntry *e = NULL;
  HASH_FIND_STR(tab->head, line, e);
  return e;
}

static char **dup_string_array_from_json(cJSON *arr, int *out_n) {
  if (!arr || !cJSON_IsArray(arr)) {
    if (out_n) *out_n = 0;
    return NULL;
  }
  int n = cJSON_GetArraySize(arr);
  if (n <= 0) {
    if (out_n) *out_n = 0;
    return NULL;
  }
  char **vec = (char **)calloc((size_t)n + 1, sizeof(char *)); /* +1 for NULL */
  if (!vec) {
    if (out_n) *out_n = 0;
    return NULL;
  }
  for (int i = 0; i < n; i++) {
    cJSON *it = cJSON_GetArrayItem(arr, i);
    if (!it || !cJSON_IsString(it) || !it->valuestring) {
      vec[i] = NULL;
      continue;
    }
    vec[i] = xstrdup_local(it->valuestring); /* own our copy */
  }
  vec[n] = NULL;
  if (out_n) *out_n = n;
  return vec;
}

static LineSetsEntry *linesets_insert_from_json(LineSetsTable **ptab,
                                                cJSON          *mustexecinfo,
                                                const char     *line) {
  if (!mustexecinfo || !line) return NULL;
  if (!*ptab) {
    *ptab = (LineSetsTable *)calloc(1, sizeof(**ptab));
    if (!*ptab) return NULL;
  }
  cJSON *line_item = cJSON_GetObjectItem(mustexecinfo, line);
  if (!line_item) return NULL;

  cJSON *bbs = cJSON_GetObjectItem(line_item, "bbs");
  cJSON *intra = cJSON_GetObjectItem(line_item, "intra");
  cJSON *inter = cJSON_GetObjectItem(line_item, "inter");

  LineSetsEntry *e = (LineSetsEntry *)calloc(1, sizeof(*e));
  if (!e) return NULL;

  e->line_key = xstrdup_local(line);
  e->bbs = dup_string_array_from_json(bbs, &e->nbbs);
  e->intra = dup_string_array_from_json(intra, &e->nintra);
  e->inter = dup_string_array_from_json(inter, &e->ninter);

  /* if all three are empty, drop the entry */
  if ((!e->bbs || e->nbbs == 0) && (!e->intra || e->nintra == 0) &&
      (!e->inter || e->ninter == 0)) {
    free(e->line_key);
    free(e->bbs); /* note: arrays may be NULL */
    free(e->intra);
    free(e->inter);
    free(e);
    return NULL;
  }

  HASH_ADD_KEYPTR(hh, (*ptab)->head, e->line_key, strlen(e->line_key), e);
  return e;
}

void clear_linesets_cache(LineSetsTable *tab) {
  if (!tab) return;
  LineSetsEntry *cur, *tmp;
  HASH_ITER(hh, tab->head, cur, tmp) {
    HASH_DEL(tab->head, cur);
    if (cur->bbs) {
      for (int i = 0; i < cur->nbbs; ++i)
        free(cur->bbs[i]);
      free(cur->bbs);
    }
    if (cur->intra) {
      for (int i = 0; i < cur->nintra; ++i)
        free(cur->intra[i]);
      free(cur->intra);
    }
    if (cur->inter) {
      for (int i = 0; i < cur->ninter; ++i)
        free(cur->inter[i]);
      free(cur->inter);
    }
    free(cur->line_key);
    free(cur);
  }
  free(tab);
}

const char **get_bb_prof(LineSetsTable **ptab, cJSON *mustexecinfo,
                         const char *line) {
  LineSetsEntry *e = linesets_find(*ptab, line);
  if (!e) e = linesets_insert_from_json(ptab, mustexecinfo, line);
  if (!e || !e->bbs || e->nbbs == 0) return NULL;
  return (const char **)e->bbs; /* cache-owned; do not free strings */
}

const char **get_intra_prof(LineSetsTable **ptab, cJSON *mustexecinfo,
                            const char *line) {
  LineSetsEntry *e = linesets_find(*ptab, line);
  if (!e) e = linesets_insert_from_json(ptab, mustexecinfo, line);
  if (!e || !e->intra || e->nintra == 0) return NULL;
  return (const char **)e->intra;
}

const char **get_inter_prof(LineSetsTable **ptab, cJSON *mustexecinfo,
                            const char *line) {
  LineSetsEntry *e = linesets_find(*ptab, line);
  if (!e) e = linesets_insert_from_json(ptab, mustexecinfo, line);
  if (!e || !e->inter || e->ninter == 0) return NULL;
  return (const char **)e->inter;
}

// const char **get_bb_prof(cJSON *mustexecinfo, const char *line) {
//   // should return a NULL-terminated array of basic blocks
//   cJSON *line_item = cJSON_GetObjectItem(mustexecinfo, line);
//   if (line_item) {
//     cJSON *bbs = cJSON_GetObjectItem(line_item, "bbs");
//     if (bbs) {
//       int          n_bbs = cJSON_GetArraySize(bbs);
//       const char **res = (const char **)malloc((n_bbs + 1) * sizeof(char *));
//       for (int i = 0; i < n_bbs; i++) {
//         cJSON *bb = cJSON_GetArrayItem(bbs, i);
//         if (bb) { res[i] = bb->valuestring; }
//       }
//       res[n_bbs] = NULL;
//       return res;
//     }
//   }
//   return NULL;
// }

// const char **get_intra_prof(cJSON *mustexecinfo, const char *line) {
//   // should return a NULL-terminated array of intra-procedural functions
//   cJSON *line_item = cJSON_GetObjectItem(mustexecinfo, line);
//   if (line_item) {
//     cJSON *intra = cJSON_GetObjectItem(line_item, "intra");
//     if (intra) {
//       int          n_intra = cJSON_GetArraySize(intra);
//       const char **res = (const char **)malloc((n_intra + 1) * sizeof(char
//       *)); for (int i = 0; i < n_intra; i++) {
//         cJSON *func = cJSON_GetArrayItem(intra, i);
//         if (func) { res[i] = func->valuestring; }
//       }
//       res[n_intra] = NULL;
//       return res;
//     }
//   }
//   return NULL;
// }

// const char **get_inter_prof(cJSON *mustexecinfo, const char *line) {
//   // should return a NULL-terminated array of inter-procedural functions
//   cJSON *line_item = cJSON_GetObjectItem(mustexecinfo, line);
//   if (line_item) {
//     cJSON *inter = cJSON_GetObjectItem(line_item, "inter");
//     if (inter) {
//       int          n_inter = cJSON_GetArraySize(inter);
//       const char **res = (const char **)malloc((n_inter + 1) * sizeof(char
//       *)); for (int i = 0; i < n_inter; i++) {
//         cJSON *func = cJSON_GetArrayItem(inter, i);
//         if (func) { res[i] = func->valuestring; }
//       }
//       res[n_inter] = NULL;
//       return res;
//     }
//   }
//   return NULL;
// }