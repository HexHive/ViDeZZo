/*
 Copyright (c) 2021 Qiang Liu <cyruscyliu@gmail.com>

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#ifndef CLANG_COV_DUMP_H
#define CLANG_COV_DUMP_H

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>

#define DEFAULT_PROFILE "clangcovdump.profraw"
static int duration = 0;
static char* llvm_profile_file = (char *)DEFAULT_PROFILE;
static int coverage_dump_precision = 1;
static int coverage_dump_precision_th = 600;
#ifdef __cplusplus
extern "C" void __llvm_profile_initialize_file(void);
extern "C" void __llvm_profile_set_filename(char *);
extern "C" int __llvm_profile_write_file(void);
#else
void __llvm_profile_initialize_file(void);
void __llvm_profile_set_filename(char *);
int __llvm_profile_write_file(void);
#endif

extern int __llvm_state_write_file(char *);

static int llvm_profile_dump() {
    char filename[256];
    char filename_state[256];
    time_t now;

    time(&now);
    snprintf(filename, 256, "%s-%ld", llvm_profile_file, now);
    __llvm_profile_set_filename(filename);

    snprintf(filename_state, 256, "s%s-%ld", llvm_profile_file, now);
    __llvm_state_write_file(filename_state);

    return __llvm_profile_write_file();
}

static void sig_handler(int signum) {
    switch (signum) {
    case SIGALRM:
        // following dump
        llvm_profile_dump();
        duration += coverage_dump_precision;
        if (duration > coverage_dump_precision_th && \
                duration <= coverage_dump_precision_th + coverage_dump_precision) {
            coverage_dump_precision = coverage_dump_precision_th;
        }
        alarm(coverage_dump_precision);
        break;
    }
}

static void llvm_profile_initialize_file(bool periodic) {
    static int init = 0;

    if (!init) {
        __llvm_profile_initialize_file();
        char *f = getenv("LLVM_PROFILE_FILE");
        if (f) { llvm_profile_file = f; }
        char *p = getenv("COVEARGE_DUMP_PRECISION");
        if (p) { coverage_dump_precision = atoi(p); }
        char *t = getenv("COVERAGE_DUMP_PRECISION_TH");
        if (t) { coverage_dump_precision_th = atoi(t); }
        // first dump
        llvm_profile_dump();
        if (periodic) {
            signal(SIGALRM, sig_handler);
            alarm(coverage_dump_precision);
        }
        init = 1;
    }
}
#endif /* CLANG_COV_DUMP_H */
