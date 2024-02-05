/*
 * Dependency-Aware Virtual-Device Fuzzing
 *
 * Copyright Qiang Liu <cyruscyliu@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 */

#ifndef VIDEZZO_FORK_H
#define VIDEZZO_FORK_H

#include <stdint.h>
#include <sys/mman.h>

//
// VIDEZZO_FORK
//
extern uint8_t __FUZZ_COUNTERS_START;
extern uint8_t __FUZZ_COUNTERS_END;
void counter_shm_init(void);

#endif /* VIDEZZO_FORK_H */
