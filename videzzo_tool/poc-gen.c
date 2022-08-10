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

static Event *parse_one_line(const char *line) {
    // we make it a regular expression engine
    // [0-9][0-9][0-9],[A-Z_],...
    // first, get interface
    printf("%s\n", line);
    while(line[0] == 0x20/*SKIP SPACE*/) line++;
    printf("%s\n", line);
}

static void input_from_text(Input *input, const char *pathname) {
    FILE *fp = fopen(pathname, "r");
    if (fp == NULL) {
        printf("[-] %s failed to open. Exit.\n", pathname);
        exit(1);
    }

    char *line = NULL;
    size_t len, n = 0;
    while ((len = getline(&line, &n, fp)) != -1) {
        // let's skip lines that are empty
        if (len == 0)
            continue;
        char sum = 0;
        for (int i = 0; i < len; i++)
            sum += line[i];
        if (sum == '\n')
            continue;
        // let's skip lines starting with #
        if (line[0] == '#')
            continue;
        parse_one_line(line);
    }

    fclose(fp);
    free(line);
}

static void input_from_binary(Input *input, const char *pathname) {
    uint8_t *poc = (uint8_t *)calloc(DEFAULT_INPUT_MAXSIZE, 1);
    size_t ret = load_from_seed(pathname, poc, DEFAULT_INPUT_MAXSIZE);
    // deserialize
    size_t DeserializationSize = deserialize(input);
    assert(ret == DeserializationSize);
}

static void output_to_text(Input *input, const char *pathname) {

}

static void output_to_binary(Input *input, const char *pathname) {
    uint8_t *poc = (uint8_t *)calloc(DEFAULT_INPUT_MAXSIZE, 1);
    // serialize
    size_t SerializationSize = serialize(input, poc, DEFAULT_INPUT_MAXSIZE);
    size_t ret = dump_to_file(poc, SerializationSize, pathname);
    assert(SerializationSize == ret);
}

int main(int argc, char **argv) {
    //
    // This program deserialize and serialize events between text and binary
    // Usage:
    //   ./poc-gen -i text -o binary path/to/input
    //   ./poc-gen -o text -i binary path/to/input
    //
    // This program maintains the text formats of events. Don't worry.
    //
    // 1) A binary input is a PoC derived from 02-dd.sh
    //
    // 2) In a text input, a line starts with # is a comment. Other non-empty lines
    //    denote virtual device messages. This format fits for both QEMU and VBox.
    //
    //    Here is a list of EVENT_TYPEs and their parameters
    //
    //    interface, EVENT_TYPE_MMIO_WRITE, addr, size, value
    //    interface, EVENT_TYPE_MMIO_READ, addr, size
    //    interface, EVENT_TYPE_CLOCK_STEP, valu
    //    interface, EVENT_TYPE_MEM_WRITE, addr, size, value
    //    interface, EVENT_TYPE_MEM_READ, addr, value

    // 0 for text, 1 for binary
    char input_format = 0, output_format = 0;
    size_t optind;
    for (optind = 1; optind < argc && argv[optind][0] == '-'; optind++) {
        switch (argv[optind][1]) {
            case 'i':
                optind++;
                if (strcmp((char *)argv[optind], "text") == 0) {
                    input_format = 0;
                } else if (strcmp((char *)argv[optind], "binary") == 0) {
                    input_format = 1;
                } else {
                    printf("[-] Format of input is missing\n");
                    exit(1);
                }
                break;
            case 'o':
                optind++;
                if (strcmp((char *)argv[optind], "text") == 0) {
                    output_format = 0;
                } else if (strcmp((char *)argv[optind], "binary") == 0) {
                    output_format = 1;
                } else {
                    printf("[-] Format of output is missing\n");
                    exit(1);
                }
                break;
            default:
                printf("[-] Usage: %s -i text|binary -o binary|text path/to/input\n", argv[0]);
                exit(1);
        }
    }
    if (input_format == output_format) {
        printf("[-] Format of input and output should be different.\n");
        exit(1);
    }
    if (argv[5] == NULL) {
        printf("[-] Path to input is missing\n");
        exit(1);
    }
    const char input_pathname[256] = {'\0'};
    strncpy(input_pathname, (char *)argv[5], 256);

    if (input_pathname[0] == '\0') {
        printf("[-] Path to input is not valid\n");
        exit(1);
    }

    videzzo_set_merge();
    DEFAULT_INPUT_MAXSIZE = get_default_input_maxsize();

    Input *input = init_input(NULL, DEFAULT_INPUT_MAXSIZE);

    if (input_format == 0) {
        input_from_text(input, input_pathname);
    } else {
        input_from_binary(input, input_pathname);
    }


    free_input(input);

    return 0;

    if (output_format == 0) {
        output_to_text(input, input_pathname);
    } else {
        output_to_binary(input, input_pathname);
    }

    free_input(input);

    return 0;
}
