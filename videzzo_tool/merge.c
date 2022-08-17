/*
 * Dependency-Aware Virtual-Device Fuzzing
 *
 * Copyright Qiang Liu <cyruscyliu@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 */

#include "videzzo.h"
#include <argp.h>
#include <string.h>

extern int get_default_input_maxsize();
static int DEFAULT_INPUT_MAXSIZE = 0x1000;

// some thing we should defined
// which means these should not be in videzzo-core
FeedbackHandler group_mutator_miss_handlers[0xff] = {};
size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize) { return 0; }
void __free_memory_blocks() {}
uint64_t dispatch_mmio_read(Event *event) { return 0; }
uint64_t dispatch_mmio_write(Event *event) { return 0; }
uint64_t dispatch_pio_read(Event *event) { return 0; }
uint64_t dispatch_pio_write(Event *event) { return 0; }
uint64_t dispatch_mem_read(Event *event) { return 0; }
uint64_t dispatch_mem_write(Event *event) { return 0; }
uint64_t dispatch_clock_step(Event *event) { return 0; }
uint64_t dispatch_socket_write(Event *event) { return 0; }
uint64_t dispatch_mem_alloc(Event *event) { return 0; }
uint64_t dispatch_mem_free(Event *event) { return 0; }

int main(int argc, char **argv) {
    // This small program accepts a set of seed pathnames to merge them to a
    // unique seed. This tool can generate a PoC when reproducation needs
    // multiple seeds after delta-debugging.
    char output[256] = {'\0'};
    size_t optind;
    for (optind = 1; optind < argc && argv[optind][0] == '-'; optind++) {
        switch (argv[optind][1]) {
            case 'o':
                optind++;
                strncpy(output, (char *)argv[optind], 256);
                break;
            default:
                printf("[-] Usage: %s -o output PATHNAMES [PATHNAMES]\n", argv[0]);
                exit(1);
        }
    }
    argv += optind;
    if (*argv == NULL) {
        printf("[-] Nothing interesting. Exit.\n");
        exit(0);
    }
    if (output[0] == '\0') {
        printf("[-] No valid output pathname. Exit.\n");
        exit(0);
    }

    // when merging, as we do not initialize a dynamic interface list
    // we have to disable any around_ opertions that are dependent on the list
    videzzo_set_merge();
    DEFAULT_INPUT_MAXSIZE = get_default_input_maxsize();

    // load
    char *pathname;
    size_t Size, DeserializationSize, SerializationSize;
    uint8_t *Data = (uint8_t *)calloc(DEFAULT_INPUT_MAXSIZE, 1);

    int n_seeds = argc - optind;
    Input *monolithic_input = init_input(NULL, DEFAULT_INPUT_MAXSIZE * n_seeds);

    for (int i = 0; i < n_seeds; i++) {
        pathname = argv[i];
        printf("[+] %s\n", pathname);
        Size = load_from_seed(pathname, Data, DEFAULT_INPUT_MAXSIZE);
        // deserialize
        Input *input = init_input(Data, Size);
        if (!input) {
            printf("[-] Input initialization failed. Exit.\n");
            exit(1);
        }
        DeserializationSize = deserialize(input);
        if (DeserializationSize == 0) {
            printf("[-] Input deserialization failed. Exit.\n");
            exit(1);
        }
        Event *event = get_first_event(input);
        for (int j = 0; event != NULL; j++) {
            event_ops[event->type].print_event(event);
            Event *copy = (Event *)calloc(sizeof(Event), 1);
            event_ops[event->type].deep_copy(event, copy);
            append_event(monolithic_input, copy);
            event = get_next_event(event);
        }
        free_input(input);
    }

    // serialize
    uint8_t *monolith = (uint8_t *)calloc(DEFAULT_INPUT_MAXSIZE * n_seeds, 1);
    SerializationSize = serialize(monolithic_input, monolith, DEFAULT_INPUT_MAXSIZE * n_seeds);
    free_input(monolithic_input);
    free(Data);

    // dump
    dump_to_file(monolith, SerializationSize, output);
    printf("[+] Dump to %s\n", output);

    return 0;
}
