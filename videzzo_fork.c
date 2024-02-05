/*
 * Dependency-Aware Virtual-Device Fuzzing
 *
 * Copyright Qiang Liu <cyruscyliu@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 */

#include "videzzo_fork.h"

//
// VIDEZZO_FORK
//
void counter_shm_init(void)
{
    /* Copy what's in the counter region to a temporary buffer.. */
    void *copy = malloc(&__FUZZ_COUNTERS_END - &__FUZZ_COUNTERS_START);
    memcpy(copy,
           &__FUZZ_COUNTERS_START,
           &__FUZZ_COUNTERS_END - &__FUZZ_COUNTERS_START);

    /* Map a shared region over the counter region */
    if (mmap(&__FUZZ_COUNTERS_START,
             &__FUZZ_COUNTERS_END - &__FUZZ_COUNTERS_START,
             PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED | MAP_ANONYMOUS,
             0, 0) == MAP_FAILED) {
        perror("Error: ");
        exit(1);
    }

    /* Copy the original data back to the counter-region */
    memcpy(&__FUZZ_COUNTERS_START, copy,
           &__FUZZ_COUNTERS_END - &__FUZZ_COUNTERS_START);
    free(copy);
}