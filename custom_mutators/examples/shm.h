#ifndef SHM_H
#define SHM_H

#include <stdint.h>

/* 공유 메모리 이름 */
#define SHM_NAME "/ft-cov-shm"
#define ENV_BB_COUNT "FT_BB_CNT"
#define INT64_SIZE sizeof(int64_t)
#define SHM_NAME_PROFILE "/ft_prof_shm"  // 프로파일링 공유 메모리 이름

extern int64_t *ptr_shm;
extern int64_t *ptr_shm_profile;  // 프로파일링 공유 메모리 포인터
extern int16_t llvm_bb_map_size;

/* 공유 메모리 생성 & 0으로 초기화 */
void create_shm(afl_state_t *afl);

/* 공유 메모리 초기화 */
void empty_shm(afl_state_t *afl);

/* 공유 메모리 읽기 */
void read_shm(afl_state_t *afl);

/* 공유 메모리 특정 index 읽기 */
int read_shm_index(afl_state_t *afl, int index);

/* 프로파일링 공유 메모리 읽기 */
int read_shm_profile(afl_state_t *afl);

/* 공유 메모리 삭제 */
void cleanup_shm(afl_state_t *afl);

#endif