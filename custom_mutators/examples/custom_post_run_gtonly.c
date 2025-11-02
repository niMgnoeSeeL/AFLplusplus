//
// This is an example on how to use afl_custom_post_run
// It executes custom code each time after AFL++ executes the target
//
// cc -O3 -fPIC -shared -g -o custom_post_run.so -I../../include
// custom_post_run.c cd ../.. afl-cc -o test-instr test-instr.c
// AFL_CUSTOM_MUTATOR_LIBRARY=custom_mutators/examples/custom_post_run.so \
//   afl-fuzz -i in -o out -- ./test-instr -f /tmp/foo
//

#include "afl-fuzz.h"
#include "common.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <math.h>
#include "set.h"

typedef struct record {
  // stats
  long long unsigned int time_ms;
  long long unsigned int samples;  // if afl->sample_interval == 0, then
                                    // samples == execs
                                    // else samples is number of samples taken
  long long unsigned int execs;
  u32                    n_seeds;
  // total
  long unsigned int n_covered_total;
  #ifndef IGNORE_FINDS
  // reset
  long unsigned int n_covered_reset;
  long unsigned int n_sglt_clusts_reset;
  long unsigned int n_singletons_reset;
  // mean local estimator
  double n_ml_sglt;
  double n_ml_sglt_clusts;
  u32    n_items;
  double remain_weight;
  double lesti_min;
  double lesti_mean;
  double lesti_max;
  u32    lesti_min_id;
  u32    lesti_max_id;
#endif

  // for ground truth computation
  SimpleSet             *covered;
  long long unsigned int n_found_new;
  bool                   check_new;

  // was it recorded because there was a change in the singleton set?
  bool is_update;

  struct record *prev;
  struct record *next;
} record_t;

typedef struct setofset {
  SimpleSet       *set;
  struct setofset *next;
} setofset_t;

typedef struct covmanager {
  u32         n_samples;
  u32         n_execs;
  SimpleSet  *covered_prev;

  SimpleSet  *curr_covered; // used during ground truth computation
} covmanager_t;

// queue_entry is defined in afl-fuzz.h
typedef struct queue_entry queue_entry_t;

typedef struct item2manager {
  u32           *id_list;
  covmanager_t **covman_list;
  u32            n_items;
} item2manager_t;

typedef struct my_mutator {
  afl_state_t *afl;

  // blackbox estimator
  covmanager_t *covman_total;
#ifndef IGNORE_FINDS
  // reset estimator
  covmanager_t *covman_reset;
  u32           n_prev_seeds;
  // mean local estimator
  item2manager_t *item2man;
#endif

  record_t *records;
  u32       records_len;
  u64       last_record_add_time; // last time we added a new record

  bool force_save;
  bool reset_after_tmin;
  u32  tmin;
  u64  last_record_write_time;    // last time we wrote records to disk

} my_mutator_t;

#ifndef IGNORE_FINDS
typedef struct ml_stat {
  double esti;
  double remain_weight;
  double lesti_min;
  double lesti_mean;
  double lesti_max;
  u32    lesti_min_id;
  u32    lesti_max_id;
} ml_stat_t;
#endif

inline u64 get_cur_time(void) {
  struct timeval  tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);
}

covmanager_t *covmanager_init(void) {
  covmanager_t *covman = (covmanager_t *)malloc(sizeof(covmanager_t));
  covman->n_samples = 0;
  covman->n_execs = 0;
  covman->covered_prev = (SimpleSet *)malloc(sizeof(SimpleSet));
  set_init(covman->covered_prev);
  covman->curr_covered = NULL;
  return covman;
}

u32 compute_record_memory(record_t *record) {
  u32 size = 0;
  size += sizeof(record_t);
  size += set_memory(record->covered);
  return size;
}

u32 compute_covmanager_memory(covmanager_t *covman) {
  u32 size = 0;
  size += sizeof(covmanager_t);  // The covmanager struct itself

  // The 'covered_prev' set
  size += set_memory(covman->covered_prev);

  if (covman->curr_covered) {
    size += set_memory(covman->curr_covered);
  }

  return size;
}

void reset_covmanager(covmanager_t *covman) {
  // Note. we do not reset n_execs
  set_clear(covman->covered_prev);
  
  if (covman->curr_covered) {
    set_destroy(covman->curr_covered);
    covman->curr_covered = NULL;
  }
}

void destroy_covmanager(covmanager_t *covman) {
  set_destroy(covman->covered_prev);
  if (covman->curr_covered) {
    set_destroy(covman->curr_covered);
  }
  free(covman);
}

#ifndef IGNORE_FINDS
covmanager_t *get_covmanager(item2manager_t *item2man, u32 id) {
  // check if item
  for (u32 i = 0; i < item2man->n_items; ++i) {
    if (item2man->id_list[i] == id) { return item2man->covman_list[i]; }
  }
  return NULL;
}

void add_item2manager(item2manager_t *item2man, u32 id) {
  item2man->id_list =
      (u32 *)realloc(item2man->id_list, (item2man->n_items + 1) * sizeof(u32));
  if (item2man->covman_list == NULL) {
    item2man->covman_list = (covmanager_t **)malloc(sizeof(covmanager_t *));
  } else {
    item2man->covman_list = (covmanager_t **)realloc(
        item2man->covman_list,
        (item2man->n_items + 1) * sizeof(covmanager_t *));
  }
  item2man->id_list[item2man->n_items] = id;
  item2man->covman_list[item2man->n_items] = covmanager_init();
  item2man->n_items++;
}
#endif

my_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {
  my_mutator_t *data = calloc(1, sizeof(my_mutator_t));
  if (!data) {
    perror("afl_custom_init alloc");
    return NULL;
  }

  data->afl = afl;

  data->covman_total = covmanager_init();
#ifndef IGNORE_FINDS
  // reset estimator
  data->covman_reset = covmanager_init();
  data->n_prev_seeds = afl->queued_items;
  // mean local estimator related data
  data->item2man = (item2manager_t *)malloc(sizeof(item2manager_t));
  data->item2man->n_items = 0;
  data->item2man->id_list = NULL;
  data->item2man->covman_list = NULL;
#endif

  data->records = NULL;
  data->records_len = 0;
  data->force_save = false;
  data->last_record_add_time = get_cur_time();
  data->reset_after_tmin = true;
  data->tmin = 0;
  data->last_record_write_time = get_cur_time();

  // check if the records file exists; if so, remove it
  char *filename = (char *)alloc_printf("%s/records.csv", afl->out_dir);
  if (access(filename, F_OK) == 0) {
    if (remove(filename) == 0) {
      WARNF("Removed the existing records file\n");
    } else {
      FATAL("Error removing the existing records file");
    }
  }

  return data;
}

void reset_entire_data(my_mutator_t *data) {
  destroy_covmanager(data->covman_total);
  data->covman_total = covmanager_init();

#ifndef IGNORE_FINDS
  // reset the reset estimator
  destroy_covmanager(data->covman_reset);
  data->covman_reset = covmanager_init();
  data->n_prev_seeds = data->afl->queued_items;
  // reset the item2manager
  for (u32 i = 0; i < data->item2man->n_items; ++i) {
    destroy_covmanager(data->item2man->covman_list[i]);
  }
  data->item2man->n_items = 0;
  data->item2man->id_list = NULL;
  data->item2man->covman_list = NULL;
#endif

  data->records = NULL;
  data->records_len = 0;
  data->force_save = false;
  data->last_record_add_time = get_cur_time();
  data->last_record_write_time = get_cur_time();
}

const char *idx_to_str(u32 idx) {
  static char buf[32];
  snprintf(buf, sizeof(buf), "%u", idx);
  return buf;
}

bool update_covmanager(covmanager_t *covman, const char *key) {
  set_add(covman->curr_covered, key); // maintain the covered set during the
                                      // sampling period for the ground truth 
                                      // computation. This will be reset every
                                      // update_singleton_clusters call, where
                                      // sampling period ends and samples are
                                      // gathered.
  bool add_new_record = false;
  if (set_contains(covman->covered_prev, key) == SET_FALSE) {
    add_new_record = true;
  }
  return add_new_record;
}

void update_singleton_clusters(covmanager_t *covman, 
                               record_t *curr_record, record_t *stop_record) {
  // each time this function is called, we have a new sample
  covman->n_samples++;
  // For ground truth computation, we update the record's n_found_new based on
  // what are covered until the record vs what's in covman->curr_covered
  if (curr_record) {
    record_t *iter_record = curr_record;
    while (iter_record) {
      if (iter_record == stop_record) { break; }
      if (iter_record->check_new && 
          set_is_subset(covman->curr_covered,
                        iter_record->covered) == SET_FALSE) {
          iter_record->n_found_new++;
          iter_record->check_new = false;
      }
      iter_record = iter_record->prev;
    }
  }
  for (u32 i = 0; i < covman->curr_covered->number_nodes; ++i) {
    if (covman->curr_covered->nodes[i] != NULL) {
      set_add(covman->covered_prev,
              covman->curr_covered->nodes[i]->_key);
    }
  }
  // reset covman->curr_covered for the next sampling period
  set_destroy(covman->curr_covered);
  covman->curr_covered = NULL;
}

#ifndef IGNORE_FINDS
void compute_alias_weights(double *alias_probability, u32 *alias_table, u32 N,
                           double *weight) {
  // check if alias_probability and alias_table are valid
  if (alias_probability == NULL || alias_table == NULL) {
    // return equal weights
    for (u32 i = 0; i < N; i++) {
      weight[i] = 1.0 / N;
    }
    return;
  }
  // sometimes alias_probability has weird values
  double *_alias_probability = (double *)malloc(N * sizeof(double));
  for (u32 i = 0; i < N; i++) {
    if (alias_probability[i] < 0.0 || alias_probability[i] > 1.0) {
      _alias_probability[i] = 0.0;
    } else {
      _alias_probability[i] = alias_probability[i];
    }
  }
  // sometimes alias_table has weird values
  u32 *_alias_table = (u32 *)malloc(N * sizeof(u32));
  for (u32 i = 0; i < N; i++) {
    if (alias_table[i] < 0 || alias_table[i] >= N) {
      _alias_table[i] = 0;
    } else {
      _alias_table[i] = alias_table[i];
    }
  }
  // Initialize weight array to 0
  for (u32 i = 0; i < N; i++) {
    weight[i] = 0.0;
  }
  // Compute the probability for each item
  for (u32 i = 0; i < N; i++) {
    // Direct probability contribution
    weight[i] += _alias_probability[i] / N;

    // Indirect probability contribution
    if (_alias_table[i] < N) {  // Ensure _alias_table[i] is a valid index
      weight[_alias_table[i]] += (1.0 - _alias_probability[i]) / N;
    }
  }
  // Verify that the sum of weights is approximately 1
  double sum = 0.0;
  for (u32 i = 0; i < N; i++) {
    sum += weight[i];
  }
  // assert(fabs(sum - 1.0) < 1e-6);
  if (fabs(sum - 1.0) >= 0.2) {
    // for debugging purpose
    // print the _alias_probability
    for (u32 i = 0; i < N; i++) {
      // printf("SMDEBUG::compute_alias_weights::_alias_probability[%d] = %f\n",
      // i,
      //        _alias_probability[i]);
    }
    // print the _alias_table
    for (u32 i = 0; i < N; i++) {
      // printf("SMDEBUG::compute_alias_weights::_alias_table[%d] = %d\n", i,
      //        _alias_table[i]);
    }
    // print the weights
    for (u32 i = 0; i < N; i++) {
      // printf("SMDEBUG::compute_alias_weights::weight[%d] = %f\n", i,
      // weight[i]);
    }
    // print the sum
    // printf("SMDEBUG::compute_alias_weights::sum = %f\n", sum);
    FATAL("Error: sum of weights is not 1.0");
  }
  free(_alias_probability);
  free(_alias_table);
}

double compute_local_estimator(covmanager_t *covman, bool is_cluster) {
  double estimate = 0.0;
  if (covman->n_samples == 0) {
    estimate = 1.0;
  } else if (covman->n_sglt_clusts == 0) {
    estimate = 1.0 / ((double)covman->n_samples + 2.0);
  } else {
    if (is_cluster)
      estimate = (double)covman->n_sglt_clusts / (double)covman->n_samples;
    else
      estimate =
          (double)set_length(covman->singletons) / (double)covman->n_samples;
  }
  return estimate;
}

ml_stat_t *compute_mean_local_estimator(my_mutator_t *data, double *weight,
                                        bool is_cluster) {
  item2manager_t *item2man = data->item2man;
  double          mean_local_estimator = 0;
  double          lesti_max = 0.0, lesti_mean = 0.0, lesti_min = 1.0;
  u32             lesti_max_id = 0, lesti_min_id = 0;
  double          remain_weight = 1.0;
  for (u32 i = 0; i < item2man->n_items; ++i) {
    u32           id = item2man->id_list[i];
    covmanager_t *covman = get_covmanager(item2man, id);
    double        local_estimator = compute_local_estimator(covman, is_cluster);
    mean_local_estimator += weight[id] * local_estimator;

    // stats
    if (is_cluster) {
      if (local_estimator > lesti_max) {
        lesti_max = local_estimator;
        lesti_max_id = id;
      }
      if (local_estimator < lesti_min) {
        lesti_min = local_estimator;
        lesti_min_id = id;
      }
      lesti_mean += local_estimator;
    }
    remain_weight -= weight[id];
  }
  if (is_cluster) lesti_mean /= item2man->n_items;

  // for seeds that are not items, we assume the local estimator is 0.5
  // same as the case where there is no singletons.
  mean_local_estimator += remain_weight * 0.5;

  ml_stat_t *ml_stat = (ml_stat_t *)malloc(sizeof(ml_stat_t));
  ml_stat->esti = mean_local_estimator;
  if (is_cluster) {
    ml_stat->remain_weight = remain_weight;
    ml_stat->lesti_min = lesti_min;
    ml_stat->lesti_mean = lesti_mean;
    ml_stat->lesti_max = lesti_max;
    ml_stat->lesti_min_id = lesti_min_id;
    ml_stat->lesti_max_id = lesti_max_id;
  }

  return ml_stat;
}
#endif  // IGNORE_FINDS

void update_record(my_mutator_t *data, bool is_end);

void afl_custom_post_run(my_mutator_t *data) {
  if (data->reset_after_tmin &&
      get_cur_time() - data->afl->start_time > data->tmin) {
    reset_entire_data(data);
    data->reset_after_tmin = false;
  }

  if (!data->afl->record_sampling) { return; }
  data->afl->record_sampling = false;
  data->covman_total->n_execs++;
#ifndef IGNORE_FINDS
  data->covman_reset->n_execs = data->covman_total->n_execs;
#endif

  u32  i;
  bool is_update = false;

#ifndef IGNORE_FINDS
  // check whether the number of seeds has changed
  if (data->n_prev_seeds != data->afl->queued_items) {
    data->n_prev_seeds = data->afl->queued_items;
    is_update = true;
    reset_covmanager(data->covman_reset);
  }

  // find the covemanager for the current item
  queue_entry_t *queue_cur = data->afl->queue_cur;
  // check if the mother is NULL, then mid = queue_cur->id
  // otherwise, mid = queue_cur->mother->id
  u32 mid = queue_cur->id;
  if (queue_cur->mother) { mid = queue_cur->mother->id; }
  covmanager_t *covman_curr = get_covmanager(data->item2man, mid);
  if (!covman_curr) {
    add_item2manager(data->item2man, mid);
    covman_curr = get_covmanager(data->item2man, mid);
  }
  covman_curr->n_execs++;
#endif
  if (!data->covman_total->curr_covered) {
    data->covman_total->curr_covered = (SimpleSet *)malloc(sizeof(SimpleSet));
    set_init(data->covman_total->curr_covered);
  }
  
  for (i = 0; i < data->afl->fsrv.map_size; i++) {
    // if the trace bit is nonzero, then this has been covered in this run
    if (data->afl->fsrv.trace_bits[i]) {
      const char *key = idx_to_str(i);
      // update covmanager:
      // if the key was not in covered_prev, add it as a new singleton
      // if the key was in singletons, remove it from singletons
      is_update = update_covmanager(data->covman_total, key) || is_update;
#ifndef IGNORE_FINDS
      is_update = update_covmanager(data->covman_reset, key) || is_update;
      is_update = update_covmanager(covman_curr, key) || is_update;
#endif
    }
  }
  // if per execution sampling, or per interval sampling and the sampling
  // interval came, update singleton clusters
  if (data->afl->sample_interval == 0 || (
        get_cur_time() - data->last_record_add_time >=
        data->afl->sample_interval * 1000)) {
    // flag up the check_new for all records. this recording for the missing 
    // mass analysis only done until the number of executions is doubled.
    record_t *curr_record = data->records;
    record_t *iter_record = curr_record;
    while (iter_record && iter_record->execs * 2 
           >= data->covman_total->n_execs) {
      iter_record->check_new = true;
      iter_record = iter_record->prev;
    }
    record_t *stop_record = iter_record;
    update_singleton_clusters(data->covman_total, curr_record, stop_record);
#ifndef IGNORE_FINDS
    update_singleton_clusters(data->covman_reset, curr_record, stop_record);
    update_singleton_clusters(covman_curr, curr_record, stop_record);
#endif
  }

  // add_new_record: determine whether to add a new record object
  bool add_new_record = false;
  u64  time_so_far = get_cur_time() - data->afl->start_time;
  if (data->afl->sample_interval > 0) {
    // In case of per interval, add record per interval
    add_new_record = (get_cur_time() - data->last_record_add_time
                      >= data->afl->sample_interval * 1000);
  } else {
    // In case of per execution, only add record if 
    // time_so_far > previous record time * 1.05
    add_new_record =
        (!data->records) || (time_so_far * 100 >= data->records->time_ms * 105);
  }

#ifndef IGNORE_FINDS
  u32     N = data->afl->queued_items;
  double *weight = (double *)malloc(N * sizeof(double));
  compute_alias_weights(data->afl->alias_probability, data->afl->alias_table, N,
                        weight);
#endif
  if (add_new_record || data->force_save) {
    record_t *new_record = (record_t *)malloc(sizeof(record_t));
    new_record->time_ms = get_cur_time() - data->afl->start_time;
    if (!data->reset_after_tmin) { new_record->time_ms -= data->tmin; }
    new_record->samples = data->covman_total->n_samples;
    new_record->execs = data->covman_total->n_execs;
    new_record->n_seeds = data->afl->queued_items;

    new_record->n_covered_total = set_length(data->covman_total->covered_prev);
#ifndef IGNORE_FINDS
    new_record->n_covered_reset = set_length(data->covman_reset->covered_prev);
    new_record->n_sglt_clusts_reset = data->covman_reset->n_sglt_clusts;
    new_record->n_singletons_reset = set_length(data->covman_reset->singletons);

    ml_stat_t *ml_stat = compute_mean_local_estimator(data, weight, false);
    new_record->n_ml_sglt = ml_stat->esti;
    free(ml_stat);
    // scale it to the number of executions to compare with others
    // (e.g., # singletons)
    new_record->n_ml_sglt *= new_record->execs;

    ml_stat = compute_mean_local_estimator(data, weight, true);
    new_record->n_ml_sglt_clusts = ml_stat->esti;
    // scale it to the number of executions to compare with others
    // (e.g., # singletons)
    new_record->n_ml_sglt_clusts *= new_record->execs;
    new_record->remain_weight = ml_stat->remain_weight;
    new_record->lesti_min = ml_stat->lesti_min;
    new_record->lesti_mean = ml_stat->lesti_mean;
    new_record->lesti_max = ml_stat->lesti_max;
    new_record->lesti_min_id = ml_stat->lesti_min_id;
    new_record->lesti_max_id = ml_stat->lesti_max_id;
    free(ml_stat);

    new_record->n_items = data->item2man->n_items;
#endif
    SimpleSet *covered_so_far = (SimpleSet *)malloc(sizeof(SimpleSet));
    set_init(covered_so_far);
    for (uint64_t i = 0; i < data->covman_total->covered_prev->number_nodes;
         ++i) {
      if (data->covman_total->covered_prev->nodes[i] != NULL) {
        set_add(covered_so_far,
                data->covman_total->covered_prev->nodes[i]->_key);
      }
    }
    new_record->covered = covered_so_far;
    new_record->n_found_new = 0;

    new_record->prev = data->records;
    new_record->next = NULL;

    if (data->records) { data->records->next = new_record; }
    data->records = new_record;
    data->records_len++;
    data->last_record_add_time = get_cur_time();
  }

  // If per execution sampling, write record based on time threshold
  if (data->afl->sample_interval == 0) {
    int threshold = 1000;
    if (time_so_far > 60000) {  // 1 minute
      threshold = 10000;        // 10 seconds
    }
    if (time_so_far > 600000) {  // 10 minutes
      threshold = 60000;         // 1 minute
    }
    if (time_so_far > 3600000) {  // 1 hour
      threshold = 300000;         // 5 minutes
    }
    if (time_so_far > 21600000) {  // 6 hours
      threshold = 600000;          // 10 minutes
    }
    if (time_so_far > 43200000) {  // 12 hours
      threshold = 1800000;         // 30 minutes
    }
    if (get_cur_time() - data->last_record_write_time > threshold) {
      update_record(data, false); // write records to file
    }
  }
  else {
    // In case of per interval sampling, write record per interval
    if (add_new_record) {
      update_record(data, false); // write records to file
    }
  }

#ifndef IGNORE_FINDS
  free(weight);
#endif
  /* Uncomment the following lines to print the debug information:
  u32 total_memory = 0;
  total_memory += compute_covmanager_memory(data->covman_total);
  total_memory += compute_covmanager_memory(data->covman_reset);
  for (u32 i = 0; i < data->item2man->n_items; ++i) {
    total_memory +=
    compute_covmanager_memory(data->item2man->covman_list[i]);
  }
  total_memory += compute_record_memory(data->records);
  float mgb = (float)total_memory / 1024 / 1024 / 1024;
  printf("SMDEBUG::afl_custom_post_run::BitIter = %llus, AddRecord = %llus,
  WriteRecord = %llus, Total = %llus, len_records = %u, total_memory =
  %fGB\n",
         debug_time_BitIter / 1000, debug_time_AddRecord / 1000,
         debug_time_WriteRecord / 1000, debug_time_total / 1000,
         data->records_len, mgb);
  */
  return;
}

void write_header(FILE *f, bool for_done_records) {
  // header for the records file
#ifdef IGNORE_FINDS
  fprintf(f,
          "time, #samples, #execs, #seeds, "
          "#covered, #foundnew, empirical, done");
#else
  fprintf(f,
          "time, #samples, #execs, #seeds, #items, "
          "#covered, #singletons, #sglt_clusts, "
          "#coveredR, #singletonsR, #sglt_clustsR, "
          "ML_sglt, ML_sglt_clusts, "
          "remainW, lesti_mean, lesti_min, lesti_min_id, lesti_max, "
          "lesti_max_id, "
          "#foundnew, done");
#endif
  if (for_done_records) {
    fprintf(f, ", update?\n");
  } else {
    fprintf(f, "\n");
  }
}

void write_row(FILE *f, my_mutator_t *data, record_t *cur,
               bool for_done_records) {
  // write a row to the records file
#ifdef IGNORE_FINDS
  fprintf(f,
          "%llu, %llu, %llu, %u, "
          "%lu, %llu, %e, %s",
          cur->time_ms, cur->samples, cur->execs, cur->n_seeds, cur->n_covered_total,
          cur->n_found_new,
          cur->n_found_new / (float)(cur->samples),
          cur->execs * 2 < data->covman_total->n_execs ? "true" : "false");
#else
  fprintf(f,
          "%llu, %llu, %llu, %u, %u, "
          "%lu, %lu, %lu, "
          "%lu, %lu, %lu, "
          "%f, %f, "
          "%f, %f, %f, %u, %f, %u, "
          "%llu, %s",
          cur->time_ms, cur->samples, cur->execs, cur->n_seeds, cur->n_items,
          cur->n_covered_total, cur->n_singletons_total,
          cur->n_sglt_clusts_total, cur->n_covered_reset,
          cur->n_singletons_reset, cur->n_sglt_clusts_reset, cur->n_ml_sglt,
          cur->n_ml_sglt_clusts, cur->remain_weight, cur->lesti_mean,
          cur->lesti_min, cur->lesti_min_id, cur->lesti_max, cur->lesti_max_id,
          cur->n_found_new,
          cur->samples * 2 < data->covman_total->n_samples ? "true" : "false");
#endif
  if (for_done_records) {
    fprintf(f, ", %s\n", cur->is_update ? "true" : "false");
  } else {
    fprintf(f, "\n");
  }
}

/* Write records to a file */
void update_record(my_mutator_t *data, bool is_end) {
  // filename: afl->out_dir/records.csv
  char *filename = (char *)alloc_printf("%s/records.csv", data->afl->out_dir);
  FILE *f;
  // check if the file exists
  if (access(filename, F_OK) == 0) {
    // if the file exists, open it and append the records
    f = fopen(filename, "a");
  } else {
    // if the file does not exist, create it and write the header
    f = fopen(filename, "w");
    if (!f) {
      perror("fopen");
      return;
    }
    // write the header
    write_header(f, true);
  }
  record_t *cur = data->records;
  if (!cur) {
    // no records to update
    fclose(f);
    return;
  }
  // find the first record
  while (cur && cur->prev) {
    cur = cur->prev;
  }
  while (cur) {
    // check if the record is done
    if (cur->execs * 2 >= data->covman_total->n_execs) { break; }
    // write the record to the file
    write_row(f, data, cur, true);
    if (cur->next) {
      cur = cur->next;
      free(cur->prev);
      cur->prev = NULL;
      data->records_len--;
    } else {
      if (data->records_len != 1) { FATAL("Error: data->records_len != 1"); }
      free(cur);
      cur = NULL;
      data->records = NULL;
      data->records_len = 0;
    }
  }
  fclose(f);
  // write not done records to a file if it is the end
  if (is_end) {
    char *filename_not_done =
        (char *)alloc_printf("%s/records_not_done.csv", data->afl->out_dir);
    FILE *f_not_done = fopen(filename_not_done, "w");
    if (!f_not_done) {
      perror("fopen");
      return;
    }
    // write the header
    write_header(f_not_done, false);
    while (cur) {
      // write the record to the file
      write_row(f_not_done, data, cur, false);
      if (cur->next) {
        cur = cur->next;
      } else {
        break;
      }
    }
    fclose(f_not_done);
    ck_free(filename_not_done);
  }
  ck_free(filename);

  data->last_record_write_time = get_cur_time();
}

// write the records to a file
void afl_custom_end_job(my_mutator_t *data) {
  // record the last status
  data->force_save = true;
  afl_custom_post_run(data);
  // update the record
#ifndef IGNORE_FINDS
  u32     N = data->afl->queued_items;
  double *weight = (double *)malloc(N * sizeof(double));
  compute_alias_weights(data->afl->alias_probability, data->afl->alias_table, N,
                        weight);
#endif
  update_record(data, true);  // write the done records
#ifndef IGNORE_FINDS
  free(weight);
#endif
  return;
}

void afl_custom_deinit(my_mutator_t *data) {
  afl_custom_end_job(data);
  record_t *cur = data->records;
  while (cur) {
    record_t *tmp = cur;
    cur = cur->next;
    // set_destroy(tmp->covered);
    free(tmp);
  }
  destroy_covmanager(data->covman_total);
  fflush(stdout);
#ifndef IGNORE_FINDS
  destroy_covmanager(data->covman_reset);
  fflush(stdout);
  for (u32 i = 0; i < data->item2man->n_items; ++i) {
    destroy_covmanager(data->item2man->covman_list[i]);
  }
  free(data->item2man->id_list);
  free(data->item2man->covman_list);
  free(data->item2man);
#endif
  free(data);
}