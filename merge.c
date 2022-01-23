/*
 * Type-Aware Virtual-Device Fuzzing
 *
 * Copyright Qiang Liu <cyruscyliu@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 */

#include "videzzo.h"
#include <argp.h>
#include <string.h>

int merge = 1;

static size_t load_from_seed(const char *pathname, uint8_t *buf, size_t size) {
    FILE *f = fopen(pathname, "rb");
    if (f == NULL) {
        printf("[-] %s failed to open. Exit.\n", pathname);
        exit(1);
    }
    return fread(buf, 1, size, f);
}

static size_t dump_to_file(uint8_t *Data, size_t Size, const char *output) {
    FILE *f = fopen(output, "wb");
    if (f == NULL) {
        printf("[-] %s failed to open. Exit.\n", output);
        exit(1);
    }
    return fwrite(Data, 1, Size, f);
}

int main(int argc, char **argv) {
    // This small program accepts a set of seed pathnames to merge them to a
    // unique seed. This tool can generate a PoC when reproducation needs
    // multiple seeds after delta-debugging.
    const char output[256] = {'\0'};
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
        Event *event = input->events;
        for (int j = 0; event != NULL; j++) {
            event_ops[event->type].print_event(event);
            Event *copy = (Event *)calloc(sizeof(Event), 1);
            event_ops[event->type].deep_copy(event, copy);
            append_event(monolithic_input, copy);
            event = event->next;
        }
        free_input(input);
    }

    // serialize
    uint8_t *monolith = (uint8_t *)calloc(DEFAULT_INPUT_MAXSIZE * n_seeds, 1);
    SerializationSize = serialize(monolithic_input, monolith, DEFAULT_INPUT_MAXSIZE * n_seeds);
    free_input(monolithic_input);

    // dump
    dump_to_file(monolith, SerializationSize, output);
    printf("[+] Dump to %s\n", output);

    return 0;
}
