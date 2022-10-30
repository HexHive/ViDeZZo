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

#define __EVENT_TYPE_IO_WRITE(interface, type, addr, size, valu) \
    event = event_ops[type].construct( \
         type, interface, addr, size, valu, NULL);

#define __EVENT_TYPE_IO_READ(interface, type, addr, size) \
    event = event_ops[type].construct( \
         type, interface, addr, size, 0, NULL);

#define __EVENT_TYPE_COCK_STEP(interface, valu) \
    event = event_ops[EVENT_TYPE_CLOCK_STEP].construct( \
         EVENT_TYPE_CLOCK_STEP, interface, 0, 0, valu, NULL);

#define __EVENT_TYPE_MEM(interface, type, addr, size, data) \
    event = event_ops[type].construct( \
            type, interface, addr, size, 0, data);

#define __EVENT_TYPE_SOCKET_WRITE(interface, size, data) \
    event = event_ops[EVENT_TYPE_SOCKET_WRITE].construct( \
            EVENT_TYPE_SOCKET_WRITE, interface, 0, size, 0, data);

#define SKIP_SPACE(line) \
    while(line[0] == 0x20) \
        line++;

#define SKIP_COMMA(line) \
    assert(line[0] == ','); \
    line++;

#define SKIP(line) \
    SKIP_SPACE(line); \
    SKIP_COMMA(line); \
    SKIP_SPACE(line);

static uint8_t *get_data(char *line, size_t len) {
    // we assume this is enough and this should be enough
    uint8_t *data = (uint8_t *)calloc(len, 1);
    char *endptr = NULL;

    char s_byte[3] = {'\0'};
    for (int i = 0; i < len; i++) {
        s_byte[0] = line[2 * i];
        s_byte[1] = line[2 * i + 1];
        data[i] = strtol(s_byte, &endptr, 16);
    }
    assert(line[len * 2] == ' ' || line[len * 2] == '\n');
    return data;
}

static size_t get_next_token(char *line, char *ret, size_t len) {
    int l_token;
    for (l_token = 0; l_token < len; l_token++) {
        if (line[l_token] == ' ' || line[l_token] == ',')
            break;
        ret[l_token] = line[l_token];
    }
    return l_token;
}

static Event *parse_line(char *line, size_t len) {
    // we make it a regular expression engine
    // [0-9][0-9][0-9],[A-Z_],...
    SKIP_SPACE(line);
    // get interface
    char s_interface[4] = {'\0'};
    int l_interface = get_next_token(line, s_interface, 4);
    line += l_interface;
    int i_interface = atoi(s_interface);
    SKIP(line);
    // get event type
    char s_event_type[32] = {'\0'};
    int l_event_type = get_next_token(line, s_event_type, 32);
    line += l_event_type;
    int i_event_type;
    for (i_event_type = 0; i_event_type < N_EVENT_TYPES; i_event_type++) {
        if (strcmp(s_event_type, EventTypeNames[i_event_type]) == 0)
            break;
    }
    SKIP(line);
    // get event parameters
    char s_addr[32] = {'\0'}, s_size[32] = {'\0'}, s_valu[32] = {'\0'};
    int l_addr, l_size, l_valu;
    unsigned long i_addr, i_valu;
    unsigned int i_size;
    uint8_t *data;
    Event *event;
    char *endptr = NULL;
    switch (i_event_type) {
        case EVENT_TYPE_MMIO_READ:
        case EVENT_TYPE_PIO_READ:
            // get addr
            l_addr = get_next_token(line, s_addr, 32);
            i_addr = strtol(s_addr, &endptr, 0);
            line += l_addr;
            SKIP(line);
            // get size
            l_size = get_next_token(line, s_size, 32);
            i_size = strtol(s_size, &endptr, 0);
            line += l_size;
            __EVENT_TYPE_IO_READ(i_interface, i_event_type, i_addr, i_size);
            break;
        case EVENT_TYPE_MMIO_WRITE:
        case EVENT_TYPE_PIO_WRITE:
            // get addr
            l_addr = get_next_token(line, s_addr, 32);
            i_addr = strtol(s_addr, &endptr, 0);
            line += l_addr;
            SKIP(line);
            // get size
            l_size = get_next_token(line, s_size, 32);
            i_size= strtol(s_size, &endptr, 0);
            line += l_size;
            SKIP(line);
            // get valu
            l_valu = get_next_token(line, s_valu, 32);
            i_valu = strtol(s_valu, &endptr, 0);
            line += l_valu;
            __EVENT_TYPE_IO_WRITE(i_interface, i_event_type, i_addr, i_size, i_valu);
            break;
        case EVENT_TYPE_MEM_READ:
            // get addr
            l_addr = get_next_token(line, s_addr, 32);
            i_addr = strtol(s_addr, &endptr, 0);
            line += l_addr;
            SKIP(line);
            // get size
            l_size = get_next_token(line, s_size, 32);
            i_size = strtol(s_size, &endptr, 0);
            line += l_size;
            data = (uint8_t *)calloc(i_size, 1);
            __EVENT_TYPE_MEM(i_interface, i_event_type, i_addr, i_size, data);
            break;
        case EVENT_TYPE_MEM_WRITE:
            // get addr
            l_addr = get_next_token(line, s_addr, 32);
            i_addr = strtol(s_addr, &endptr, 0);
            line += l_addr;
            SKIP(line);
            // get size
            l_size = get_next_token(line, s_size, 32);
            i_size = strtol(s_size, &endptr, 0);
            line += l_size;
            SKIP(line);
            // get data
            data = get_data(line, i_size);
            __EVENT_TYPE_MEM(i_interface, i_event_type, i_addr, i_size, data);
            break;
        case EVENT_TYPE_SOCKET_WRITE:
            // get size
            l_size = get_next_token(line, s_size, 32);
            i_size = strtol(s_size, &endptr, 0);
            line += l_size;
            SKIP(line);
            // get data
            data = get_data(line, i_size);
            __EVENT_TYPE_SOCKET_WRITE(i_interface, i_size, data);
            break;
        case EVENT_TYPE_CLOCK_STEP:
            // get valu
            l_valu = get_next_token(line, s_valu, 32);
            i_valu = strtol(s_valu, &endptr, 0);
            line += l_valu;
            __EVENT_TYPE_COCK_STEP(i_interface, i_valu);
            break;
        default:
            printf("Unknown event type: %d\n", i_event_type);
            return NULL;
    }
    return event;
}

static void input_from_text(Input *input, const char *pathname) {
    FILE *fp = fopen(pathname, "r");
    if (fp == NULL) {
        printf("[-] %s failed to open. Exit.\n", pathname);
        exit(1);
    }

    char *line = NULL;
    size_t len, n = 0;
    Event *event;
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
        event = parse_line(line, len);
        append_event(input, event);
    }

    fclose(fp);
    free(line);
}

static void input_from_binary(Input *input, const char *pathname) {
    uint8_t *poc = (uint8_t *)calloc(DEFAULT_INPUT_MAXSIZE, 1);
    size_t ret = load_from_seed(pathname, poc, DEFAULT_INPUT_MAXSIZE);
    input->limit= ret;
    input->buf = poc;
    // deserialize
    size_t DeserializationSize = deserialize(input);
    assert(ret == DeserializationSize);
}

static void fprintf_data(Event *event, FILE *fp) {
    char *enc;
    uint32_t size = event->size;
    enc = calloc(2 * size + 1, 1);
    for (int i = 0; i < size; i++) {
        sprintf(&enc[i * 2], "%02x", event->data[i]);
    }
    fprintf(fp, ", %s", enc);
    free(enc);
}

static void __output_to_text(Input *input, FILE *fp) {
    Input *grouped_input;
    Event *event = get_first_event(input);
    for (int i = 0; event != NULL; i++) {
        switch (event->type) {
            case EVENT_TYPE_MMIO_READ:
            case EVENT_TYPE_PIO_READ:
                fprintf(fp, "    %03d, %s", event->interface, EventTypeNames[event->type]);
                fprintf(fp, ", 0x%lx, 0x%x", event->addr, event->size);
                fprintf(fp, "\n");
                break;
            case EVENT_TYPE_MMIO_WRITE:
            case EVENT_TYPE_PIO_WRITE:
                fprintf(fp, "    %03d, %s", event->interface, EventTypeNames[event->type]);
                fprintf(fp, ", 0x%lx, 0x%x", event->addr, event->size);
                fprintf(fp, ", 0x%lx", event->valu);
                fprintf(fp, "\n");
                break;
            case EVENT_TYPE_MEM_READ:
                fprintf(fp, "    %03d, %s", event->interface, EventTypeNames[event->type]);
                fprintf(fp, ", 0x%lx, 0x%x", event->addr, event->size);
                fprintf(fp, "\n");
                break;
            case EVENT_TYPE_MEM_WRITE:
                fprintf(fp, "    %03d, %s", event->interface, EventTypeNames[event->type]);
                fprintf(fp, ", 0x%lx, 0x%x", event->addr, event->size);
                fprintf_data(event, fp);
                fprintf(fp, "\n");
                break;
            case EVENT_TYPE_SOCKET_WRITE:
                fprintf(fp, "    %03d, %s", event->interface, EventTypeNames[event->type]);
                fprintf(fp, ", 0x%x", event->size);
                fprintf_data(event, fp);
                fprintf(fp, "\n");
                break;
            case EVENT_TYPE_CLOCK_STEP:
                fprintf(fp, "    %03d, %s", event->interface, EventTypeNames[event->type]);
                fprintf(fp, ", 0x%lx", event->valu);
                fprintf(fp, "\n");
                break;
            case EVENT_TYPE_GROUP_EVENT_LM:
            case EVENT_TYPE_GROUP_EVENT_RS:
                grouped_input = (Input *)event->data;
                __output_to_text(grouped_input, fp);
                break;
        }
        event = get_next_event(event);
    }
}

static void output_to_text(Input *input, const char *pathname) {
    FILE *fp = fopen(pathname, "w");
    if (fp == NULL) {
        printf("[-] %s failed to open. Exit.\n", pathname);
        exit(1);
    }

    __output_to_text(input, fp);

    fclose(fp);
}

static void output_to_binary(Input *input, const char *pathname) {
    uint8_t *poc = (uint8_t *)calloc(DEFAULT_INPUT_MAXSIZE, 1);
    // serialize
    size_t SerializationSize = serialize(input, poc, DEFAULT_INPUT_MAXSIZE);
    size_t ret = dump_to_file(poc, SerializationSize, pathname);
    assert(SerializationSize == ret);
    free(poc);
}

int main(int argc, char **argv) {
    //
    // This program deserialize and serialize events between text and binary
    // Usage:
    //   ./poc-gen -i text -o binary -O path/to/output path/to/input
    //   ./poc-gen -o text -i binary -O path/to/output path/to/input
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
    //    interface, EVENT_TYPE_MMIO_WRITE, addr, size, valu
    //    interface, EVENT_TYPE_MMIO_READ, addr, size
    //    interface, EVENT_TYPE_CLOCK_STEP, valu
    //    interface, EVENT_TYPE_MEM_WRITE, addr, size, valu
    //    interface, EVENT_TYPE_MEM_READ, addr, valu

    // 0 for text, 1 for binary
    char input_format = 0, output_format = 0;
    char output_pathname[256] = {'\0'};
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
            case 'O':
                optind++;
                memcpy(output_pathname, argv[optind], strlen(argv[optind]));
                break;
            default:
                printf("[-] Usage: %s -i text|binary -o binary|text path/to/input\n", argv[0]);
                exit(1);
        }
    }

    if (argv[7] == NULL) {
        printf("[-] Path to input is missing\n");
        exit(1);
    }

    char input_pathname[256] = {'\0'};
    memcpy(input_pathname, argv[7], strlen(argv[7]));

    videzzo_set_merge();
    DEFAULT_INPUT_MAXSIZE = get_default_input_maxsize();

    Input *input = init_input(NULL, DEFAULT_INPUT_MAXSIZE);

    if (input_format == 0) {
        input_from_text(input, input_pathname);
    } else {
        input_from_binary(input, input_pathname);
    }

    if (output_format == 0) {
        output_to_text(input, output_pathname);
    } else {
        output_to_binary(input, output_pathname);
    }

    free_input(input);

    return 0;
}
