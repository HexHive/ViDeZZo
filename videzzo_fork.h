/*
 * Dependency-Aware Virtual-Device Fuzzing
 *
 * Copyright Qiang Liu <cyruscyliu@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 */

#ifndef VIDEZZO_FORK_H
#define VIDEZZO_FORK_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

//
// VIDEZZO_FORK
//
extern uint8_t __FUZZ_COUNTERS_START;
extern uint8_t __FUZZ_COUNTERS_END;
#ifdef __cplusplus
extern "C" {
#endif // __cplusplus
void counter_shm_init(void);
#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus

#endif /* VIDEZZO_FORK_H */
