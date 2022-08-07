/*
 * Dependency-Aware Virtual-Device Fuzzing
 *
 * Copyright Qiang Liu <cyruscyliu@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 */

#include "videzzo.h"
#include "poc-gen.h"
#include <argp.h>
#include <string.h>

extern int get_default_input_maxsize();
static int DEFAULT_INPUT_MAXSIZE = 0x1000;

// some thing we should defined
// which means these should not be in videzzo-core
FeedbackHandler group_mutator_miss_handlers[0xff] = {};
size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize) { return 0; }
void __free_memory_blocks() {}

static size_t dump_to_file(uint8_t *Data, size_t Size, const char *output) {
    FILE *f = fopen(output, "wb");
    if (f == NULL) {
        printf("[-] %s failed to open. Exit.\n", output);
        exit(1);
    }
    return fwrite(Data, 1, Size, f);
}

int main(int argc, char **argv) {
    // Define events in poc-gen.h and this small program will generates a PoC for you.
    const char output[256] = {'\0'};
    size_t optind;
    for (optind = 1; optind < argc && argv[optind][0] == '-'; optind++) {
        switch (argv[optind][1]) {
            case 'o':
                optind++;
                strncpy(output, (char *)argv[optind], 256);
                break;
            default:
                printf("[-] Usage: %s -o output\n", argv[0]);
                exit(1);
        }
    }
    argv += optind;
    if (*argv != NULL) {
        printf("[-] Usage: %s -o output\n", argv[0]);
        exit(1);
    }
    if (output[0] == '\0') {
        printf("[-] No valid output pathname. Exit.\n");
        exit(0);
    }

    videzzo_set_merge();
    DEFAULT_INPUT_MAXSIZE = get_default_input_maxsize();

    Input *input = init_input(NULL, DEFAULT_INPUT_MAXSIZE);

    // call into poc-gen.h
    construct_poc(input);

    // serialize
    uint8_t *poc = (uint8_t *)calloc(DEFAULT_INPUT_MAXSIZE, 1);
    size_t SerializationSize = serialize(input, poc, DEFAULT_INPUT_MAXSIZE);
    free_input(input);

    // dump
    dump_to_file(poc, SerializationSize, output);
    printf("[+] Dump to %s\n", output);

    return 0;
}
