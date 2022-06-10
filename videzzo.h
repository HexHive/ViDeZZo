/*
 * Type-Aware Virtual-Device Fuzzing
 *
 * Copyright Qiang Liu <cyruscyliu@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 */

#ifndef VIDEZZO_H
#define VIDEZZO_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <sys/queue.h>
#include <fcntl.h>
#include <gmodule.h>

//
// Event
//
#define N_EVENT_TYPES           11
typedef enum {                          //I
    EVENT_TYPE_MMIO_READ      = 0,      //*
    EVENT_TYPE_MMIO_WRITE,              //*
    EVENT_TYPE_PIO_READ,                //*
    EVENT_TYPE_PIO_WRITE,               //*
#define CLOCK_MAX_STEP          1000000
    EVENT_TYPE_CLOCK_STEP,              //*
#define SOCKET_WRITE_MIN_SIZE   0x001
#define SOCKET_WRITE_MAX_SIZE   0x100
    EVENT_TYPE_SOCKET_WRITE   = 5,      //*
    EVENT_TYPE_GROUP_EVENT    = 6,      //-
    EVENT_TYPE_MEM_READ       = 7,      //*
    EVENT_TYPE_MEM_WRITE,               //*
    EVENT_TYPE_MEM_ALLOC      = 9,      //*
    EVENT_TYPE_MEM_FREE,                //*
} EventType;

static const char *EventTypeNames[N_EVENT_TYPES] = {
    "EVENT_TYPE_MMIO_READ",             //00
    "EVENT_TYPE_MMIO_WRITE",            //01
    "EVENT_TYPE_PIO_READ",              //02
    "EVENT_TYPE_PIO_WRITE",             //03
    "EVENT_TYPE_CLOCK_STEP",            //04
    "EVENT_TYPE_SOCKET_WRITE",          //05
    "EVNET_TYPE_GROUP_EVENT",           //06
    "EVENT_TYPE_MEM_READ",              //07
    "EVENT_TYPE_MEM_WRITE",             //08
    "EVENT_TYPE_MEM_ALLOC",             //09
    "EVENT_TYPE_MEM_FREE",              //10
};

typedef struct Event {
    uint8_t type;                       /* event type */ /* uint8_t for alignment */
    uint8_t interface;                  /* event interface id or 0xff for a group event */
    uint64_t addr;                      /* possible event args */
    uint32_t size;                      /* possible event args */
    union {
        uint64_t valu;                  /* possible event args */
        uint8_t *data;                  /* possible event args */
    };
    uint32_t offset;                    /* event offset in the input */
    uint32_t event_size;                /* event size */
    struct Event *next;                 /* event linker */
} Event;

typedef struct EventOps {
    void (*change_addr)(Event *event, uint64_t new_addr);
    uint32_t (*change_size)(Event *event, uint32_t new_size); // return real size
    void (*change_valu)(Event *event, uint64_t new_valu);
    void (*change_data)(Event *event, uint8_t *new_data);
    uint64_t (*dispatch)(Event *event);
    void (*print_event)(Event *event);
    Event *(*construct)(uint8_t type, uint8_t interface,
            uint64_t addr, uint32_t size, uint64_t valu, uint8_t *data);
    void (*release)(Event *event);
    uint32_t (*serialize)(Event *event, uint8_t *Data, size_t Offset, size_t MaxSize);
    void (*deep_copy)(Event *orig, Event *copy);
} EventOps;

// Weak VM specific
uint64_t dispatch_mmio_read(Event *event) __attribute__((weak));
uint64_t dispatch_mmio_write(Event *event) __attribute__((weak));
uint64_t dispatch_pio_read(Event *event) __attribute__((weak));
uint64_t dispatch_pio_write(Event *event) __attribute__((weak));
uint64_t dispatch_mem_read(Event *event) __attribute__((weak));
uint64_t dispatch_mem_write(Event *event) __attribute__((weak));
uint64_t dispatch_clock_step(Event *event) __attribute__((weak));
uint64_t dispatch_socket_write(Event *event) __attribute__((weak));
uint64_t dispatch_mem_alloc(Event *event) __attribute__((weak));
uint64_t dispatch_mem_free(Event *event) __attribute__((weak));
uint64_t AroundInvalidAddress(uint64_t physaddr) __attribute__((weak));
void flush_events(void *opaque) __attribute__((weak));

enum Sizes {ViDeZZo_Empty, ViDeZZo_Byte=1, ViDeZZo_Word=2, ViDeZZo_Long=4, ViDeZZo_Quad=8};
extern EventOps event_ops[N_EVENT_TYPES];
void videzzo_dispatch_event(Event *event);

//
// Input
//
typedef struct {
    size_t limit;                       /* input size   */
    void *buf;                          /* input data   */
    int index;                          /* input cursor */
#define DEFAULT_INPUT_MAXSIZE           4096
#define VIDEZZO_INPUT_MAXSIZE           4096
    size_t size;                        /* real input size */
    Event *events;                      /* corresponding events */
    int n_events;                       /* number of events
                                           (all grouped events is one event) */
    int n_groups;                       /* number of groups*/
} Input;

Input *init_input(const uint8_t *Data, size_t Size);
void free_input(Input *input);
size_t get_input_size(Input *input);
uint32_t deserialize(Input *input);
uint32_t serialize(Input *input, uint8_t *Data, uint32_t MaxSize);
Event *get_event(Input *input, uint32_t index);
Event *get_next_event(Event *event);
void remove_event(Input *input, uint32_t idx);
void insert_event(Input *input, Event *event, uint32_t idx);
void append_event(Input *input, Event *event);
size_t reset_data(uint8_t *Data, size_t MaxSize);

//
// Interface
//
// predefined interfaces one-to-one mapped from
// the transparent events, these interfaces are
// also transparent to the fuzzer
// predefined interfaces are fixed by ViDeZZo
#define INTERFACE_MEM_READ      0
#define INTERFACE_MEM_WRITE     1
#define INTERFACE_CLOCK_STEP    2
#define INTERFACE_GROUP_EVENT   3
#define INTERFACE_SOCKET_WRITE  4
#define INTERFACE_MEM_ALLOC     5
#define INTERFACE_MEM_FREE      6
// dynamic interfaces are shared with VM
#define INTERFACE_DYNAMIC       7
#define INTERFACE_END           256

typedef struct {
    uint64_t addr;
    uint32_t size;
} InterfaceMemBlock;

typedef struct {
    EventType type;
    InterfaceMemBlock emb;
    char name[32];
    uint8_t min_access_size;
    uint8_t max_access_size;
    bool dynamic;
} InterfaceDescription;

// InterfaceDescription Id_Description[INTERFACE_END];
// uint32_t n_interfaces;
void add_interface(EventType type, uint64_t addr, uint32_t size,
        const char *name, uint8_t min_access_size, uint8_t max_access_size, bool dynamic);
int get_number_of_interfaces(void);
void print_interfaces(void);
//
// mutators
//
#define N_MUTATORS 16
int select_mutators(int rand);
extern size_t (*CustomMutators[N_MUTATORS])(Input *input);
extern const char *CustomMutatorNames[N_MUTATORS];

//
// Feedback from VM
// Given a generic feedback from VM, we want to leverage this feedback to
// manipulate the current input; sometimes, the whole corpus, which is not
// difficult, but not impossible.
//
typedef struct GenericFeedbackContext {
    uint8_t *Data;
    uint32_t MaxSize;
    Input *current_input;
    int current_event;
    void *object;
} GenericFeedbackContext;

void gfctx_set_current_input(Input *input);
Input *gfctx_get_current_input(void);
void gfctx_set_current_event(int idx);
int gfctx_get_current_event(void);
void gfctx_set_object(void *object);
void *gfctx_get_object(void);
void gfctx_set_data(uint8_t *Data);
uint8_t *gfctx_get_data(void);
void gfctx_set_size(uint32_t MaxSize);
uint32_t gfctx_get_size(void);
typedef void (*__flush)(void *object);
void gfctx_set_flush(__flush);
__flush gfctx_get_flush(void);

// a local handler of a feedback should take the current input and
// the index of the event just issued as parameters and udpate the current input
typedef void (* FeedbackHandler)(uint64_t physaddr);

void GroupMutatorMiss(uint8_t id, uint64_t physaddr);
extern FeedbackHandler group_mutator_miss_handlers[0xff];

//
// Open APIs
//
void __videzzo_execute_one_input(Input *input);
size_t videzzo_execute_one_input(uint8_t *Data, size_t Size, void *object, __flush flush);
size_t ViDeZZoCustomMutator(uint8_t *Data, size_t Size, size_t MaxSize, unsigned int Seed);

//
// libFuzzer
//
size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);
size_t LLVMFuzzerCustomMutator(
        uint8_t *Data, size_t Size, size_t MaxSize, unsigned int Seed);
int LLVMFuzzerInitialize(int *argc, char ***argv, char ***envp);
int LLVMFuzzerTestOneInput(unsigned char *Data, size_t Size);

//
// Reproduce
//
void videzzo_set_merge(void);
void videzzo_clear_merge(void);

//
// Fuzz Targets
//
typedef struct ViDeZZoFuzzTargetConfig {
    // Group 1: basic information
    const char *arch, *name, *args, *file;
    // Group 2: virtual device specific
    const char *mrnames;
    bool byte_address;                      /* Support byte address or not */
    // Group 3: multiple input controls
    bool socket;                            /* Support socket or not */
    bool display;                           /* Support display or not */
} ViDeZZoFuzzTargetConfig;

typedef struct ViDeZZoFuzzTarget {
    const char *name;                       /* target identifier (passed to --fuzz-target=) */
    const char *description;                /* help text */

    // Returns the arguments that are passed to qemu/softmmu init().
    // Freed by the caller.
    GString *(*get_init_cmdline)(struct ViDeZZoFuzzTarget *);

    // Will run once, after a VM is initialized.
    // Can be NULL.
    void(*pre_vm_init)(void);

    // Will run once, after a VM has been initialized, prior to the fuzz-loop.
    void(*pre_fuzz)(void *opaque);

    // This is repeatedly executed during the fuzzing loop.
    // Its should handle setup, input execution and cleanup.
    // Cannot be NULL.
    void(*fuzz)(void *opaque, unsigned char *, size_t);
    void *opaque;                           /* ViDeZZoFuzzTargetConfig */
} ViDeZZoFuzzTarget;

// all fuzz targets go here
typedef struct ViDeZZoFuzzTargetState {
    ViDeZZoFuzzTarget *target;
    LIST_ENTRY(ViDeZZoFuzzTargetState) target_list;
} ViDeZZoFuzzTargetState;

void videzzo_usage(void);
int parse_fuzz_target_name(int *argc, char ***argv, char *target_name);
typedef LIST_HEAD(, ViDeZZoFuzzTargetState) ViDeZZoFuzzTargetList;
void videzzo_add_fuzz_target(ViDeZZoFuzzTarget *target);
ViDeZZoFuzzTarget *videzzo_get_fuzz_target(char* name);

//
// Sockets
//
void init_sockets(int sockfds[]);

//
// VNC
//
int init_vnc(void);
int init_vnc_client(void *s, int vnc_port);
int remove_offset_from_vnc_port(int vnc_port);

#endif /* VIDEZZO_H */
