#define _GNU_SOURCE
#include "afl-fuzz.h"
#include "shm.h"
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>

/* 공유 메모리 생성 & 0으로 초기화 */
void create_shm(afl_state_t *afl) {
  int fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
  if (fd == -1) {
    perror("shm_open");
    exit(1);
  }

  size_t bytes = afl->llvm_bb_map_size * INT64_SIZE;
  if (ftruncate(fd, bytes) == -1) {
    perror("ftruncate");
    exit(1);
  }

  afl->ptr_shm = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (afl->ptr_shm == MAP_FAILED) {
    perror("mmap");
    exit(1);
  }

  memset(afl->ptr_shm, 0, bytes);
  close(fd);
  printf("✅ Created shared memory %s with %d slots (all zeroed)\n", SHM_NAME,
         afl->llvm_bb_map_size);

  // Initialize the profile shared memory
  fd = shm_open(SHM_NAME_PROFILE, O_CREAT | O_RDWR, 0666);
  if (fd == -1) {
    perror("shm_open for profile");
    exit(1);
  }

  bytes = INT64_SIZE;
  if (ftruncate(fd, bytes) == -1) {
    perror("ftruncate for profile");
    exit(1);
  }

  afl->ptr_shm_profile =
      mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (afl->ptr_shm_profile == MAP_FAILED) {
    perror("mmap for profile");
    exit(1);
  }

  memset(afl->ptr_shm_profile, 0, bytes);
  close(fd);
  printf("✅ Created shared memory %s with 1 slot (all zeroed)\n",
         SHM_NAME_PROFILE);
}

/* 공유 메모리 초기화 */
void empty_shm(afl_state_t *afl) {
  if (afl->ptr_shm == NULL) {
    fprintf(stderr, "❌ Shared memory not initialized\n");
    return;
  }
  size_t bytes = afl->llvm_bb_map_size * INT64_SIZE;
  memset(afl->ptr_shm, 0, bytes);
  // printf("✅ Cleared shared memory %s\n", SHM_NAME);
}

/* 공유 메모리 읽기 */
void read_shm(afl_state_t *afl) {
  printf("📊 Data in %s:\n", SHM_NAME);
  for (int i = 0; i < afl->llvm_bb_map_size; i++) {
    printf("[%d] %ld\n", i, afl->ptr_shm[i]);
  }
}

/* 공유 메모리 특정 index 읽기 */
int read_shm_index(afl_state_t *afl, int index) {
  if (index < 0) {
    fprintf(stderr, "❌ Invalid index: %d\n", index);
    return -1;
  }
  if (afl->ptr_shm == NULL) {
    fprintf(stderr, "❌ Shared memory not initialized\n");
    return -1;
  }
  if (index >= 0 && index < afl->llvm_bb_map_size) {
    return afl->ptr_shm[index] > 0 ? 1 : 0;  // 0: not covered, 1: covered
  } else {
    fprintf(stderr, "❌ Index out of bounds: %d\n", index);
    return -1;
  }
}

int read_shm_profile(afl_state_t *afl) {
  if (afl->ptr_shm_profile == NULL) {
    fprintf(stderr, "❌ Profile shared memory not initialized\n");
    return -1;
  }
  return afl->ptr_shm_profile[0];  // Return the first slot for profiling
}

/* 공유 메모리 삭제 */
void cleanup_shm(afl_state_t *afl) {
  if (afl->ptr_shm == NULL) {
    fprintf(stderr, "❌ Shared memory not initialized\n");
    return;
  }
  if (munmap(afl->ptr_shm, afl->llvm_bb_map_size * INT64_SIZE) == -1) {
    perror("munmap");
    return;
  }
  afl->ptr_shm = NULL;
  if (shm_unlink(SHM_NAME) == 0) {
    printf("🗑️ Removed shared memory %s\n", SHM_NAME);
  } else {
    perror("shm_unlink");
  }
  if (munmap(afl->ptr_shm_profile, INT64_SIZE) == -1) {
    perror("munmap for profile");
    return;
  }
  afl->ptr_shm_profile = NULL;
  if (shm_unlink(SHM_NAME_PROFILE) == 0) {
    printf("🗑️ Removed shared memory %s\n", SHM_NAME_PROFILE);
  } else {
    perror("shm_unlink for profile");
  }
}
