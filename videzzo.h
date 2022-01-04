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

//
// Event
//
#define N_EVENT_TYPES 9
typedef enum {                          //I
    EVENT_TYPE_MMIO_READ      = 0,      //*
    EVENT_TYPE_MMIO_WRITE,              //*
    EVENT_TYPE_PIO_READ,                //*
    EVENT_TYPE_PIO_WRITE,               //*
#define CLOCK_MAX_STEP 1000000
    EVENT_TYPE_CLOCK_STEP,              //*
#define SOCKET_WRITE_MIN_SIZE 0x001
#define SOCKET_WRITE_MAX_SIZE 0x100
    EVENT_TYPE_SOCKET_WRITE   = 5,      //*
    EVENT_TYPE_GROUP_EVENT    = 6,      //-
    EVENT_TYPE_MEM_READ       = 7,      //*
    EVENT_TYPE_MEM_WRITE,               //*
} EventType;

static const char *EventTypeNames[N_EVENT_TYPES] = {
    "EVENT_TYPE_MMIO_READ",             //0
    "EVENT_TYPE_MMIO_WRITE",            //1
    "EVENT_TYPE_PIO_READ",              //2
    "EVENT_TYPE_PIO_WRITE",             //3
    "EVENT_TYPE_CLOCK_STEP",            //4
    "EVENT_TYPE_SOCKET_WRITE",          //5
    "EVNET_TYPE_GROUP_EVENT",           //6
    "EVENT_TYPE_MEM_READ",              //7
    "EVENT_TYPE_MEM_WRITE",             //8
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

// TODO make struct EventOps a field in struct Event
typedef struct EventOps {
    void (*change_addr)(Event *event, uint64_t new_addr);
    uint32_t (*change_size)(Event *event, uint32_t new_size); // return real size
    void (*change_valu)(Event *event, uint64_t new_valu);
    void (*change_data)(Event *event, uint8_t *new_data);
    void (*dispatch)(Event *event, void *object);
    void (*print_event)(Event *event);
    Event *(*construct)(uint8_t type, uint8_t interface,
            uint64_t addr, uint32_t size, uint64_t valu, uint8_t *data);
    void (*release)(Event *event);
    uint32_t (*serialize)(Event *event, uint8_t *Data, size_t Offset, size_t MaxSize);
    void (*deep_copy)(Event *orig, Event *copy);
} EventOps;

// VM specific
void dispatch_mmio_read(Event *event, void *object);
void dispatch_mmio_write(Event *event, void *object);
void dispatch_pio_read(Event *event, void *object);
void dispatch_pio_write(Event *event, void *object);
void dispatch_mem_read(Event *event, void *object);
void dispatch_mem_write(Event *event, void *object);
void dispatch_clock_step(Event *event, void *object);
void dispatch_socket_write(Event *event, void *object);

enum Sizes {ViDeZZo_Empty, ViDeZZo_Byte=1, ViDeZZo_Word=2, ViDeZZo_Long=4, ViDeZZo_Quad=8};
extern EventOps event_ops[N_EVENT_TYPES];
void videzzo_dispatch_event(Event *event, void *object);

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
uint32_t deserialize(Input *input);
uint32_t serialize(Input *input, uint8_t *Data, uint32_t MaxSize);
Event *get_next_event(Event *event);
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
// dynamic interfaces are shared with VM
#define INTERFACE_DYNAMIC       5
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

extern InterfaceDescription Id_Description[INTERFACE_END];
extern uint32_t n_interfaces;
void add_interface(EventType type, uint64_t addr, uint32_t size,
        char *name, uint8_t min_access_size, uint8_t max_access_size, bool dynamic);
void print_interfaces(void);
//
// mutators
//
#define N_MUTATORS 17
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

extern GenericFeedbackContext gfctx;
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
// a local handler of a feedback should take the current input and
// the index of the event just issued as parameters and return a new input
// Input *(* FeedbackHandler)(Input *current_input, uint32_t current_event);
typedef Input *(* FeedbackHandler)(Input *current_input, uint32_t current_event);

uint32_t videzzo_randint(void);

void GroupMutatorMiss(uint8_t id);
extern FeedbackHandler group_mutator_handlers[0xff];

//
// Open APIs
//
void __videzzo_execute_one_input(Input *input, void *object);
void videzzo_execute_one_input(uint8_t *Data, size_t Size, void *object);
size_t ViDeZZoCustomMutator(uint8_t *Data, size_t Size, size_t MaxSize, unsigned int Seed);

//
// libFuzzer
//
size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);
size_t LLVMFuzzerCustomMutator(
        uint8_t *Data, size_t Size, size_t MaxSize, unsigned int Seed);

#endif /* VIDEZZO_H */
