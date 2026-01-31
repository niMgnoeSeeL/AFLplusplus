AFL_DIR ?= ../..
CC ?= gcc
CFLAGS ?= -O3 -g -fPIC -Wall -Wextra
LDFLAGS ?= -shared

INCLUDE = -I$(AFL_DIR)/include

.PHONY: all clean

all: perf_mutator.so

perf_mutator.so: perf_mutator.c
	$(CC) $(CFLAGS) $(INCLUDE) $(LDFLAGS) -o $@ $<

clean:
	rm -f perf_mutator.so
