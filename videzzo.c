/*
 * Dependency-Aware Virtual-Device Fuzzing
 *
 * Copyright Qiang Liu <cyruscyliu@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 */

#include "videzzo.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <rfb/rfbclient.h>
#include <semaphore.h>

//
// Default size for an input
//
int get_default_input_maxsize() {
    if (getenv("DEFAULT_INPUT_MAXSIZE"))
        return atoi(getenv("DEFAULT_INPUT_MAXSIZE"));
    else
        return 0x1000;
}

static int DEFAULT_INPUT_MAXSIZE = 0x1000;

//
// Merge
//
int merge = 0;

void videzzo_set_merge() {
    merge = 1;
}

void videzzo_clear_merge() {
    merge = 0;
}

//
// GroupMutator Feedback
//
// We want to disable the trigger-action protocol and other advanced features.
//
bool DisableInputProcessing = false;

void disable_group_mutator(void) {
    DisableInputProcessing = true;
}

void enable_group_mutator(void) {
    DisableInputProcessing = false;
}

static sem_t mutex;
static int in_one_iteration = 0;
static int loop_counter = 0;
static int status = 0; // 0 -> 1/2 -> 2/1 -> bingo

typedef struct Record {
    int id;
    int status;  // 0 -> 1/2 -> 2/1 -> bingo
    int last_status;
    int current_event_s;
    int current_event_e;
} Record;

static Record records[32] = {{ 0 }};

// TODO: change the API convetion and API name
void GroupMutatorOrder(int id, int status) {
    // TODO: this is not thread-safe (vbox)
    if (DisableInputProcessing)
        return;

    if (getenv("VIDEZZO_DISABLE_GROUP_MUTATOR_RS") ||
            getenv("VIDEZZO_DISABLE_INTER_MESSAGE_MUTATORS"))
        return;

#ifdef VIDEZZO_DEBUG
    fprintf(stderr, "- GroupMutatorOrder: %d\n", status);
#endif
    Record *r = &records[id];

    if (r->status == 0 && status == 1) {
        r->status = 1;
        r->last_status = status;
        // start to record
        r->current_event_s = gfctx_get_current_event(0);
    } else if (r->status == 1 && in_one_iteration) {
        if (status == 2 && r->last_status == 1)
            r->status = 2;
        // end the record
        r->current_event_e = gfctx_get_current_event(0);
    }

    if (r->status == 2 && r->current_event_s < r->current_event_e) {
        // we want to group any events between (_s, _e]
        Input *input = gfctx_get_current_input(0);

        // we dislike a group event to trigger this Order
        Event *trigger_event = get_event(input, gfctx_get_current_event(0));
        if (trigger_event->type == EVENT_TYPE_GROUP_EVENT_RS)
            return;

        // create new context
        Input *new_input = init_input(NULL, DEFAULT_INPUT_MAXSIZE);
        Event *event, *event_copy;
        for (int i = r->current_event_s + 1; i <= r->current_event_e; ++i) {
            event = get_event(input, i);
            // if any EVENT_TYPE_GROUP_EVENT_RS, we drop this
            if (event->type == EVENT_TYPE_GROUP_EVENT_RS)
                return;
            // we don't want a EVENT_TYPE_GROUP_EVENT_LM
            if (event->type == EVENT_TYPE_GROUP_EVENT_LM) {
                // for this, we want its last event
                Input *grouped_input = (Input *)event->data;
                event = get_event(grouped_input, grouped_input->n_events - 1);
            }
            event_copy = (Event *)calloc(sizeof(Event), 1);
            event_ops[event->type].deep_copy(event, event_copy);
            append_event(new_input, event_copy);
            // should we delete the event?
            event_ops[event->type].print_event(event);
        }
        // we are going to construct a group event
        Event *group_event = event_ops[EVENT_TYPE_GROUP_EVENT_RS].construct(
            EVENT_TYPE_GROUP_EVENT_RS, INTERFACE_GROUP_EVENT_RS, 0,
            new_input->size, 0, (uint8_t *)new_input);
        // bingo, we've got all events into new_input
        // let's find a place to inject the group event
        // currently, we don't want to make it a next event
        // let's insert it after current_event_s
        insert_event(input, group_event, r->current_event_s + 1);
        memset(r, 0, sizeof(Record));
    }
#ifdef VIDEZZO_DEBUG
    fprintf(stderr, "- GroupMutatorOrder Done\n");
#endif
}

// TODO: change the API convention and API name
void GroupMutatorMiss(uint8_t id, uint64_t physaddr) {
    if (DisableInputProcessing)
        return;

    // let's first handle intra-message annotation
    if (getenv("VIDEZZO_DISABLE_INTRA_MESSAGE_ANNOTATION"))
        return;

    sem_wait(&mutex);
    Input *old_input;
    int old_current_event;
    Event *trigger_event;
    if (!getenv("VIDEZZO_DISABLE_GROUP_MUTATOR_LM") &&
            !getenv("VIDEZZO_DISABLE_INTER_MESSAGE_MUTATORS")) {
        // we dislike a group event to trigger this Miss
        old_input = gfctx_get_current_input(0);
        old_current_event = gfctx_get_current_event(0);
        trigger_event = NULL;
        if (old_input != NULL) {
            trigger_event = get_event(old_input, old_current_event);
            if (trigger_event->type == EVENT_TYPE_GROUP_EVENT_LM && loop_counter == 0) {
                sem_post(&mutex);
                return;
            }
        }
    }

    // create new context
    // so all injected events will go into here
    Input *input = init_input(NULL, DEFAULT_INPUT_MAXSIZE);
    int current_event = 0;

    gfctx_set_current_input(input, 1);
    gfctx_set_current_event(current_event, 1);

    // in this handler, the current input will be updated
    // Don't delete any events from the current event to the end
    group_mutator_miss_handlers[id](physaddr);

    // let's group messages
    if (getenv("VIDEZZO_DISABLE_GROUP_MUTATOR_LM") ||
            getenv("VIDEZZO_DISABLE_INTER_MESSAGE_MUTATORS") || old_input == NULL) {
        free_input(input);
        goto recover;
    }

#ifdef VIDEZZO_DEBUG
    fprintf(stderr, "- GroupMutatorMiss: %d\n", loop_counter);
#endif

    // nice, all events go into our new input
    // we construct the group event
    if (trigger_event->type == EVENT_TYPE_GROUP_EVENT_LM) {
        // apprantly, we are in a loop
        Input *group_event_input = (Input* )trigger_event->data;
        Event *injected_event = get_first_event(input), *tmp_event;
        // copy event from the injected input to the group event input
        while (injected_event != NULL) {
            Event *tmp_event = (Event *)calloc(sizeof(Event), 1);
            event_ops[injected_event->type].deep_copy(injected_event, tmp_event);
            insert_event(group_event_input, tmp_event, group_event_input->n_events - 1);
            injected_event = get_next_event(injected_event);
        }
        free_input(input);
    } else {
        // apprantly, this is the first time to have a GroupMutatorMiss
        Event *trigger_event_copy = (Event *)calloc(sizeof(Event), 1);
        event_ops[trigger_event->type].deep_copy(trigger_event, trigger_event_copy);
        append_event(input, trigger_event_copy);
        // we are going to construct a group event
        Event *group_event = event_ops[EVENT_TYPE_GROUP_EVENT_LM].construct(
            EVENT_TYPE_GROUP_EVENT_LM, INTERFACE_GROUP_EVENT_LM, 0, input->size, 0, (uint8_t *)input);
        // we inject this group event into the old input, and then
        // we will delete the old_current_event in __videzzo_execute_one_input
        insert_event(old_input, group_event, old_current_event);
        old_input->n_groups++;
    }
    loop_counter += 1;

#ifdef VIDEZZO_DEBUG
    fprintf(stderr, "- GroupMutatorMiss Done\n");
#endif

recover:
    gfctx_set_current_input(old_input, 0);
    gfctx_set_current_event(old_current_event, 0);
    sem_post(&mutex);
}

//
// used in vm|fuzzer-specific mutator callback
//
size_t ViDeZZoCustomMutator(uint8_t *Data, size_t Size,
        size_t MaxSize, unsigned int Seed) {
#ifdef VIDEZZO_DEBUG
    fprintf(stderr, "- ViDeZZoCustomMutator, %zu\n", Size);
#endif
    // Copy data to our input manager
    Input *input = init_input(Data, Size);
    if (!input) {
        return reset_data(Data, MaxSize);
    }
    // Deserialize Data to Events
    // If the input is too short to contain longer event, stop early.
    // Note that we don't discard any intact event.
    Size = deserialize(input);
    if (Size == 0) {
        free_input(input);
        return reset_data(Data, MaxSize);
    }
    // set up the RNG
    srand(Seed);
    // Mutate all events until an non-zero size
    // weighted: select_weighted_mutators
    size_t aaaaaaa = select_mutators(rand());
#ifdef VIDEZZO_DEBUG
    fprintf(stderr, "- %s\n", CustomMutatorNames[aaaaaaa]);
#endif
    size_t NewSize = CustomMutators[aaaaaaa](input);
    if (NewSize) {
        size_t SerializationSize = serialize(input, Data, MaxSize);
        free_input(input);
#ifdef VIDEZZO_DEBUG
        if (NewSize > MaxSize)
            fprintf(stderr, "- NewSize (overflow), %zu\n", NewSize);
        else
            fprintf(stderr, "- NewSize, %zu\n", NewSize);
#endif
        return SerializationSize;
    }
    free_input(input);
    return reset_data(Data, MaxSize); // Fallback, should not happen frequently.
}

static void __videzzo_execute_one_input(Input *input) {
    Event *event = get_first_event(input);
#ifdef VIDEZZO_DEBUG
    fprintf(stderr, "- dispatching events\n");
#endif
    int i;
    for (i = 0; event != NULL; i++) {
        // set up feedback context
        gfctx_set_current_event(i, 0);
        videzzo_dispatch_event(event);
#ifdef VIDEZZO_DEBUG
        event_ops[event->type].print_event(event);
#endif
        event = get_next_event(event);
        if (loop_counter) {
            remove_event(input, i + 1);
        }
        loop_counter = 0;
    }
    gfctx_set_current_event(0, 0);
#ifdef VIDEZZO_DEBUG
    fprintf(stderr, "- dispatching events done\n");
#endif
}

extern void __free_memory_blocks();

int videzzo_execute_one_input(uint8_t *Data, size_t Size, void *object, __flush flush) {
    in_one_iteration = 1;
    status = 0;
    DEFAULT_INPUT_MAXSIZE = get_default_input_maxsize();

    // read Data to Input
    Input *input = init_input(Data, Size);
    if (!input)
        return 0;
    // deserialize Data to Events
    input->size = deserialize(input);
    // set up feedback context
    gfctx_set_current_input(input, 0);
    gfctx_set_object(object, 0);
    gfctx_set_flush(flush);
    if (getenv("VIDEZZO_FORK")) {
        if (fork() == 0) {
            __videzzo_execute_one_input(input);
            _Exit(0);
        } else {
            wait(0);
        }
    } else {
        __videzzo_execute_one_input(input);
    }
    size_t SerializationSize = serialize(input, Data, DEFAULT_INPUT_MAXSIZE);
    gfctx_set_current_input(NULL, 0);
    gfctx_set_object(NULL, 0);
    gfctx_set_flush(NULL);
    free_input(input);
    //
    // We want to free all allocated blocks here to have a reliable reproducer.
    //
    sem_wait(&mutex);
    __free_memory_blocks();
    sem_post(&mutex);

    in_one_iteration = 0;
    return SerializationSize;
}

//
// shared interfaces
//
InterfaceDescription Id_Description[INTERFACE_END] = {
    [INTERFACE_MEM_READ] = {
        .type = EVENT_TYPE_MEM_READ,
        .emb = {.addr = 0xFFFFFFFF, .size = 0xFFFFFFFF},
        .name = "memread", .dynamic = false,
        .min_access_size = 0xFF, .max_access_size = 0xFF,
    }, [INTERFACE_MEM_WRITE] = {
        .type = EVENT_TYPE_MEM_WRITE,
        .emb = {.addr = 0xFFFFFFFF, .size = 0xFFFFFFFF},
        .name = "memwrite", .dynamic = false,
        .min_access_size = 0xFF, .max_access_size = 0xFF,
    }, [INTERFACE_CLOCK_STEP] = {
        .type = EVENT_TYPE_CLOCK_STEP,
        .emb = {.addr = 0xFFFFFFFF, .size = 0xFFFFFFFF},
        .name = "clock_step", .dynamic = true,
        .min_access_size = 0xFF, .max_access_size = 0xFF,
    }, [INTERFACE_SOCKET_WRITE] = {
        .type = EVENT_TYPE_SOCKET_WRITE,
        .emb = {.addr = 0xFFFFFFFF, .size = 0xFFFFFFFF},
        .name = "socket_write", .dynamic = false, // disable socket write
        .min_access_size = 0xFF, .max_access_size = 0xFF,
    }, [INTERFACE_GROUP_EVENT_LM] = {
        .type = EVENT_TYPE_GROUP_EVENT_LM,
        .emb = {.addr = 0xFFFFFFFF, .size = 0xFFFFFFFF},
        .name = "group_event_lm", .dynamic = false,
        .min_access_size = 0xFF, .max_access_size = 0xFF,
    }, [INTERFACE_GROUP_EVENT_RS] = {
        .type = EVENT_TYPE_GROUP_EVENT_RS,
        .emb = {.addr = 0xFFFFFFFF, .size = 0xFFFFFFFF},
        .name = "group_event_re", .dynamic = false,
    }, [INTERFACE_MEM_ALLOC] = {
        .type = EVENT_TYPE_MEM_ALLOC,
        .emb = {.addr = 0xFFFFFFFF, .size = 0xFFFFFFFF},
        .name = "memalloc", .dynamic = false,
        .min_access_size = 0xFF, .max_access_size = 0xFF,
    }, [INTERFACE_MEM_FREE] = {
        .type = EVENT_TYPE_MEM_FREE,
        .emb = {.addr = 0xFFFFFFFF, .size = 0xFFFFFFFF},
        .name = "memfree", .dynamic = false,
        .min_access_size = 0xFF, .max_access_size = 0xFF,
    }
};

static int n_interfaces = INTERFACE_DYNAMIC;

int get_number_of_interfaces(void) {
    return n_interfaces;
}

void add_interface(EventType type, uint64_t addr, uint32_t size,
        const char *name, uint8_t min_access_size, uint8_t max_access_size, bool dynamic) {
    if (min_access_size == 0 && max_access_size == 0) {
        fprintf(stderr, "\n- %s has zero size!!! Won\'t add this\n", name);
        return;
    }
    Id_Description[n_interfaces].type = type;
    Id_Description[n_interfaces].emb.addr = addr;
    Id_Description[n_interfaces].emb.size = size;
    Id_Description[n_interfaces].min_access_size = min_access_size;
    Id_Description[n_interfaces].max_access_size = max_access_size;
    memcpy(Id_Description[n_interfaces].name, name, strlen(name) <= 32 ? strlen(name) : 32);
    Id_Description[n_interfaces].dynamic = dynamic;
    n_interfaces++;
}

bool interface_exists(EventType type, uint64_t addr, uint32_t size) {
    for (int i = 0; i < n_interfaces; i++) {
        if (Id_Description[i].type == type && \
                Id_Description[i].emb.addr == addr && \
                Id_Description[i].emb.size == size)
            return true;
    }
    return false;
}

static uint64_t around_event_addr(uint8_t id, uint64_t raw_addr) {
    if (merge)
        return raw_addr; // do nothing
    if (id < INTERFACE_DYNAMIC)
        return raw_addr; // do nothing
    InterfaceDescription ed = Id_Description[id];
    uint64_t to_avoid_overflow = ed.emb.addr + ((raw_addr - ed.emb.addr) % ed.emb.size);
    if (getenv("VIDEZZO_BYTE_ALIGNED_ADDRESS")) {
        return to_avoid_overflow & 0xFFFFFFFFFFFFFFFF;
    } else {
        return to_avoid_overflow & 0xFFFFFFFFFFFFFFFC;
    }
}

static inline int clz64(uint64_t val) {
    return val ? __builtin_clzll(val) : 64;
}

static inline uint64_t pow2floor(uint64_t value) {
    if (!value) {
        /* Avoid undefined shift by 64 */
        return 0;
    }
    return 0x8000000000000000ull >> clz64(value);
}

static uint32_t around_event_size(uint8_t id, uint32_t raw_size) {
    if (merge)
        return raw_size; // do nothing
    if (id != INTERFACE_SOCKET_WRITE && id < INTERFACE_DYNAMIC)
        return raw_size % 0x80000; // 8M to avoid oom
    if (id == INTERFACE_SOCKET_WRITE)
        return (raw_size - SOCKET_WRITE_MIN_SIZE) %
            (SOCKET_WRITE_MAX_SIZE - SOCKET_WRITE_MIN_SIZE) + SOCKET_WRITE_MIN_SIZE;
    InterfaceDescription ed = Id_Description[id];
    ed = Id_Description[id];
    uint8_t diff = ed.max_access_size - ed.min_access_size + 1;
    return pow2floor(((raw_size - ed.min_access_size) % diff) + ed.min_access_size);
}

void print_interfaces(void) {
    for (int i = 0; i < n_interfaces; i++) {
        InterfaceDescription ed = Id_Description[i];
        if (!ed.dynamic)
            continue;
        fprintf(stderr, "  * %s, %s, 0x%lx +0x%x, %d,%d\n",
                ed.name, EventTypeNames[ed.type],
                ed.emb.addr, ed.emb.size,
                ed.min_access_size, ed.max_access_size);
    }
}

// when generating a new event, we have to check possible interfaces
static uint8_t get_possible_interface(int rand) {
    InterfaceDescription *id;

    uint8_t *valid_interfaces = (uint8_t *)calloc(n_interfaces, 1);

    // sample non-sequential data
    uint32_t real_idx = 0;
    uint32_t real_sum = n_interfaces;
    for (int i = 0 ; i < n_interfaces; ++i, ++real_idx) {
        id = &Id_Description[i];
        if (!id->dynamic) {
            real_idx--;
            real_sum--;
            continue;
        }
        valid_interfaces[real_idx] = i;
    }
    uint32_t target_idx = valid_interfaces[rand % real_sum];
    free(valid_interfaces);
    return target_idx;
}

//
// Event Callbacks
//
static void change_addr_generic(Event *event, uint64_t new_addr) {
    event->addr = around_event_addr(event->interface, new_addr);
}

static void change_size_generic(Event *event, uint32_t new_size) {
    event->size = around_event_size(event->interface, new_size);
}

static void change_valu_generic(Event *event, uint64_t new_valu) {
    event->valu = new_valu;
}

static void change_data_socket_write(Event *event, uint8_t *new_data) {
    // copy old data
    memcpy(event->data, new_data, event->size); // remember to free new_data
}

static void print_event_prologue(Event *event) {
    fprintf(stderr, "  * %03d, %s", event->interface, EventTypeNames[event->type]);
}

static void print_event_io_addr_size(Event *event) {
    fprintf(stderr, ", 0x%lx, 0x%x", event->addr, event->size);
}

static void print_event_io_valu(Event *event) {
    fprintf(stderr, ", 0x%lx", event->valu);
}

static void print_event_data(Event *event) {
    char *enc;
    uint32_t size = event->size;
    enc = calloc(2 * size + 1, 1);
    for (int i = 0; i < size; i++) {
        sprintf(&enc[i * 2], "%02x", event->data[i]);
    }
    if (2 * size + 1 > 80) {
        enc[80] = '\0';
        fprintf(stderr, ", %s...", enc);
    } else
        fprintf(stderr, ", %s", enc);
    free(enc);
}

static void print_end() {
    fprintf(stderr, "\n");
}

static void print_event_mmio_read(Event *event) {
    print_event_prologue(event);
    print_event_io_addr_size(event);
    print_end();
}

static void print_event_pio_read(Event *event) {
    print_event_prologue(event);
    print_event_io_addr_size(event);
    print_end();
}

static void print_event_mem_read(Event *event) {
    print_event_prologue(event);
    print_event_io_addr_size(event);
    print_end();
}

static void print_event_mem_write(Event *event) {
    print_event_prologue(event);
    print_event_io_addr_size(event);
    print_event_data(event);
    print_end();
}

static void print_event_mem_alloc(Event *event) {
    print_event_prologue(event);
    fprintf(stderr, ", 0x%lx", event->valu);
    print_end();
}

static void print_event_mem_free(Event *event) {
    print_event_prologue(event);
    fprintf(stderr, ", 0x%lx", event->valu);
    print_end();
}

static void print_event_socket_write(Event *event) {
    print_event_prologue(event);
    fprintf(stderr, ", 0x%x", event->size);
    print_event_data(event);
    print_end();
}

static void print_event_group_event(Event *event) {
    print_event_prologue(event);
    fprintf(stderr, ", 0x%x", event->size);
    fprintf(stderr, ", 0x%x events", ((Input *)event->data)->n_events);
    print_end();
}

static void print_event_pio_write(Event *event) {
    print_event_prologue(event);
    print_event_io_addr_size(event);
    print_event_io_valu(event);
    print_end();
}

static void print_event_mmio_write(Event *event) {
    print_event_prologue(event);
    print_event_io_addr_size(event);
    print_event_io_valu(event);
    print_end();
}

static void print_event_clock_step(Event *event) {
    print_event_prologue(event);
    print_event_io_valu(event);
    print_end();
}

static uint8_t *__get_buffer(size_t size) {
    uint8_t *buffer = (uint8_t *)calloc(size, 1);
    for (int i = 0; i < size; i++) {
        buffer[i] = rand() % 0xff;
    }
    return buffer;
}

static Event *__alloc_an_event(uint8_t type, uint8_t interface ) {
    Event *event = (Event *)calloc(sizeof(Event), 1);
    event->type = type;
    event->interface = interface;
    return event;
}

static Event *construct_io_read(uint8_t type, uint8_t interface,
        uint64_t addr, uint32_t size, uint64_t valu, uint8_t *data) {
    Event *event = __alloc_an_event(type, interface);
    event->addr = around_event_addr(interface, addr);
    event->size = around_event_size(interface, size);
    event->event_size = 14;
    return event;
}

static Event *construct_io_write(uint8_t type, uint8_t interface,
        uint64_t addr, uint32_t size, uint64_t valu, uint8_t *data) {
    Event *event = __alloc_an_event(type, interface);
    event->addr = around_event_addr(interface, addr);
    event->size = around_event_size(interface, size);
    event->valu = valu;
    event->event_size = 22;
    return event;
}

static Event *construct_mem_read_write(uint8_t type, uint8_t interface,
        uint64_t addr, uint32_t size, uint64_t valu, uint8_t *data) {
    Event *event = __alloc_an_event(type, interface);
    event->addr = around_event_addr(interface, addr);
    event->size = around_event_size(interface, size);
    if (data == NULL)
        data = __get_buffer(event->size);
    // assume we are in charge of free this data for performance
    event->data = data;
    event->event_size = event->size + 14;
    return event;
}

static Event *construct_mem_alloc_or_free(uint8_t type, uint8_t interface,
        uint64_t addr, uint32_t size, uint64_t valu, uint8_t *data) {
    Event *event = __alloc_an_event(type, interface);
    event->valu = valu;
    event->event_size = 10;
    return event;
}

static Event *construct_socket_write(uint8_t type, uint8_t interface,
        uint64_t addr, uint32_t size, uint64_t valu, uint8_t *data) {
    Event *event = __alloc_an_event(type, interface);
    event->size = around_event_size(interface, size);
    if (data == NULL)
        data = __get_buffer(event->size);
    // assume we are in charge of free this data for performance
    event->data = data;
    event->event_size = event->size + 6;
    return event;
}

static Event *construct_clock_step(uint8_t type, uint8_t interface,
        uint64_t addr, uint32_t size, uint64_t valu, uint8_t *data) {
    Event *event = __alloc_an_event(type, interface);
    event->valu = valu % CLOCK_MAX_STEP;
    event->event_size = 10;
    return event;
}

static Event *construct_group_event(uint8_t type, uint8_t interface,
        uint64_t addr, uint32_t size, uint64_t valu, uint8_t *data) {
    Event *event = __alloc_an_event(type, interface);
    event->size = size; // it's usually 0 at the beginning
    assert(data != NULL);
    // assume we are in charge of free this data for performance
    /*(Input *)*/event->data = /*(Input *)*/data;
    event->event_size = event->size + 6;
    return event;
}

static uint32_t serialize_io_read(Event *event, uint8_t *Data, size_t Offset, size_t MaxSize) {
    if (Offset + 14 >= MaxSize)
        return 0;
    Data[Offset] = event->type;
    Data[Offset + 1] = event->interface;
    memcpy(Data + Offset + 2, (uint8_t *)&(event->addr), 8);
    memcpy(Data + Offset + 10, (uint8_t *)&(event->size), 4);
#ifdef VIDEZZO_DEBUG
    event_ops[event->type].print_event(event);
#endif
    return 14;
}

static uint32_t serialize_io_write(Event *event, uint8_t *Data, size_t Offset, size_t MaxSize) {
    if (Offset + 22 >= MaxSize)
        return 0;
    Data[Offset] = event->type;
    Data[Offset + 1] = event->interface;
    memcpy(Data + Offset + 2, (uint8_t *)&(event->addr), 8);
    memcpy(Data + Offset + 10, (uint8_t *)&(event->size), 4);
    memcpy(Data + Offset + 14, (uint8_t *)&(event->valu), 8);
#ifdef VIDEZZO_DEBUG
    event_ops[event->type].print_event(event);
#endif
    return 22;
}

static uint32_t serialize_mem_read_or_write(Event *event, uint8_t *Data, size_t Offset, size_t MaxSize) {
    uint32_t size = event->size;
    if (Offset + 14 + size >= MaxSize)
        return 0;
    Data[Offset] = event->type;
    Data[Offset + 1] = event->interface;
    memcpy(Data + Offset + 2, (uint8_t *)&(event->addr), 8);
    memcpy(Data + Offset + 10, (uint8_t *)&(event->size), 4);
    if (event->type == EVENT_TYPE_MEM_READ)
        memset(Data + Offset + 14, 0, size);
    else
        memcpy(Data + Offset + 14, (uint8_t *)(event->data), size);
#ifdef VIDEZZO_DEBUG
    event_ops[event->type].print_event(event);
#endif
    return 14 + event->size;
}

static uint32_t serialize_mem_alloc_or_free(Event *event, uint8_t *Data, size_t Offset, size_t MaxSize) {
    if (Offset + 8 >= MaxSize)
        return 0;
    Data[Offset] = event->type;
    Data[Offset + 1] = event->interface;
    memcpy(Data + Offset + 2, (uint8_t *)&(event->valu), 8);
#ifdef VIDEZZO_DEBUG
    event_ops[event->type].print_event(event);
#endif
    return 10;
}

static uint32_t serialize_socket_write(Event *event, uint8_t *Data, size_t Offset, size_t MaxSize) {
    uint32_t size = event->size;
    if (Offset + 6 + size >= MaxSize)
            return 0;
    Data[Offset] = event->type;
    Data[Offset + 1] = event->interface;
    memcpy(Data + Offset + 2, (uint8_t *)&size, 4);
    memcpy(Data + Offset + 6, (uint8_t *)event->data, size);
#ifdef VIDEZZO_DEBUG
    event_ops[event->type].print_event(event);
#endif
    return 6 + size;
}

static uint32_t serialize_clock_step(Event *event, uint8_t *Data, size_t Offset, size_t MaxSize) {
    if (Offset + 10 >= MaxSize)
        return 0;
    Data[Offset] = event->type;
    Data[Offset + 1] = event->interface;
    memcpy(Data + Offset + 2, (uint8_t *)&event->valu, 8);
#ifdef VIDEZZO_DEBUG
    event_ops[event->type].print_event(event);
#endif
    return 10;
}

// For consecutive writes, we don't guarentee that two consecutive writes are
// address-consecutive. This make the following the solution breaks its
// assumption. Here, we sacrifice some performance to guarentee this assumption.
static int handle_non_address_consecutive_writes(Input *input) {
    Event *e;
    int n_delete = 0;
    uint8_t *delete = (uint8_t *)calloc(input->n_events, 1);

    Event *head = NULL, *next = NULL;

    e = get_first_event(input);

    for (int i = 0; e != NULL; i++) {
        if (delete[i] || e->type != EVENT_TYPE_MEM_WRITE) {
            e = get_next_event(e);
            continue;
        }
        // for each write, we search
        head = e;
        next = get_next_event(head);
        for (int j = i + 1; next != NULL; j++) {
            if (head && delete[j] == 0 && next->addr == head->addr + head->size) {
                uint32_t new_size = head->size + next->size;
                uint8_t *new_data = (uint8_t *)calloc(new_size, 1);
                memcpy(new_data, head->data, head->size);
                memcpy(new_data + head->size, next->data, next->size);
                free(head->data);
                head->data = new_data;
                head->size += next->size;
                head->event_size += next->size;
                input->size += next->size;

                // let's mark this
                delete[j] = 0xde;
                n_delete += 1;
                break;
            }
            next = get_next_event(next);
        }
        e = get_next_event(e);
    }

    for (int i = input->n_events - 1; i >= 0; i--) {
        if (delete[i] == 0xde)
            remove_event(input, i);
    }
    free(delete);

    return n_delete;
}

// For consecutive writes, we will concat them into one message, and this will
// reduce the number of messages by 80%. However, this handler should be fast.
//
// The following is the nearest neighbor solution.
static int handle_consecutive_writes(Input *input) {
    Event *e;

    bool reset = false;
    int consecutive_writes = 0; // 0 -> write -> 1 -> non-write|non-consecutive -> 0
    Event *head = NULL, *next = NULL;
    uint32_t additional_size = 0;
    uint8_t *additional_data = (uint8_t *)calloc(1024, 1);

    int n_delete = 0;
    uint8_t *delete = (uint8_t *)calloc(input->n_events, 1);

    e = get_first_event(input);

    for (int i = 0; e != NULL; i++) {
        if (e->type != EVENT_TYPE_MEM_WRITE) {
            reset = true;
        } else {
            consecutive_writes += 1;
            if (consecutive_writes == 1) {
                head = e;
            } else {
                next = e;
                if (head && next->addr != head->addr + head->size + additional_size) {
                    reset = true;
                } else {
                    // copy
                    memcpy(additional_data + additional_size, next->data, next->size);
                    additional_size += next->size;
                    // let's mark this
                    delete[i] = 0xde;
                    n_delete += 1;
                }
            }
        }

        if (reset) {
            // update
            if (head && additional_size > 0) {
                uint32_t new_size = head->size + additional_size;
                uint8_t *new_data = (uint8_t *)calloc(new_size, 1);
                memcpy(new_data, head->data, head->size);
                memcpy(new_data + head->size, additional_data, additional_size);
                free(head->data);
                head->data = new_data;
                head->size += additional_size;
                head->event_size += additional_size;
                input->size += additional_size;
            }
            // reset
            reset = false;
            consecutive_writes = 0;
            head = NULL;
            next = NULL;
            additional_size = 0;
            memset(additional_data, 0, 1024);
        }
        e = get_next_event(e);
    }

    for (int i = input->n_events - 1; i >= 0; i--) {
        if (delete[i] == 0xde)
            remove_event(input, i);
    }
    free(delete);
    free(additional_data);
    return n_delete;
}

// Remove useless messages as follows
static int handle_useless_messages(Input *input) {
    Event *e;
    int n_delete = 0;
    uint8_t *delete = (uint8_t *)calloc(input->n_events, 1);

    e = get_first_event(input);
    for (int i = 0; e != NULL; i++) {
        if (e->type == EVENT_TYPE_MEM_ALLOC ||
                e->type == EVENT_TYPE_MEM_READ ||
                e->type == EVENT_TYPE_MEM_FREE) {
            delete[i] = 0xde; // let's mark this
            n_delete += 1;
        }
        e = get_next_event(e);
    }
    for (int i = input->n_events - 1; i >= 0; i--) {
        if (delete[i] == 0xde)
            remove_event(input, i);
    }
    free(delete);
    return n_delete;
}

static uint32_t serialize_group_event(Event *event, uint8_t *Data, size_t Offset, size_t MaxSize) {
    static int log_counter = 0;

    Input *input = (Input *)event->data;
    int n_events = input->n_events;

    // since this degrads the performance by 20%, I disable it
    // handle_useless_messages(input);
    // since this degrads the performance by 50%, I disable it
    // while (handle_non_address_consecutive_writes(input)) {};
    // this is covered by handle_non_address_consecutive_writes
    // while (handle_consecutive_writes(input)) {};
    size_t size = input->size;
    // let's update event
    event->size = input->size;
    event->event_size = 6 + event->size;
    // note that parent input is not updated, but this is fine
    // we are going to end this iteration ...

    if (Offset + 6 + size >= MaxSize) {
        // this is only a reminder, we don't want it to degrade the performance
        log_counter++;
        if (log_counter < 100) {
            fprintf(stderr, "  * serialize_group_event: reduce %d/%d messages, remain %lu bytes",
                    n_events - input->n_events, n_events, input->size);
            fprintf(stderr, ", but space is not enough\n");
        }
        Event *last_event = get_event(input, input->n_events - 1);
        // serialize_xxx will print event, so we don't print it here
        return event_ops[last_event->type].serialize(last_event, Data, Offset, MaxSize);
    }

    Data[Offset] = event->type;
    Data[Offset + 1] = event->interface;
    memcpy(Data + Offset + 2, (uint8_t *)&size, 4);
    serialize(input, Data + Offset + 6, MaxSize - Offset - 6);
#ifdef VIDEZZO_DEBUG
    event_ops[event->type].print_event(event);
#endif
    return 6 + size;
}

static void release_nothing(Event *event) {
    return;
}

static void release_data(Event *event) {
    free(event->data);
}

static void release_group_event(Event *event) {
    Input *input = (Input *)event->data;

    free_input(input);
}

static void deep_copy_no_data(Event *orig, Event *copy) {
    memcpy(copy, orig, sizeof(Event));
}

static void deep_copy_with_data(Event *orig, Event *copy) {
    memcpy(copy, orig, sizeof(Event));
    copy->data = (uint8_t *)calloc(copy->size, 1);
    memcpy(copy->data, orig->data, copy->size);
}

static void deep_copy_with_grouped_input(Event *orig, Event *copy) {
    // copy Event
    memcpy(copy, orig, sizeof(Event));

    // copy Input.Event
    Input *origed_input = (Input *)orig->data;
    Input *copied_input = init_input(NULL, origed_input->size);

    Event *origed_event = get_first_event(origed_input);
    for (int i = 0; origed_event != NULL; i++) {
        Event *copied_event = (Event *)calloc(sizeof(Event), 1);
        event_ops[origed_event->type].deep_copy(origed_event, copied_event);
        append_event(copied_input, copied_event);
        origed_event = get_next_event(origed_event);
    }
    copy->data = (uint8_t *)copied_input;
}

static uint64_t dispatch_group_event(Event *event) {
    Input *input = (Input *)event->data;
    Event *e;
    int i;
#ifdef VIDEZZO_DEBUG
    fprintf(stderr, "- dispatching events\n");
#endif
    for (e = get_first_event(input), i = 0;
            e != NULL; i++) {
#ifdef VIDEZZO_DEBUG
        event_ops[e->type].print_event(e);
#endif
        videzzo_dispatch_event(e);
        e = get_next_event(e);
    }
#ifdef VIDEZZO_DEBUG
    fprintf(stderr, "- dispatching events done\n");
#endif
    return 0;
}

EventOps event_ops[] = {
    [EVENT_TYPE_MMIO_READ] = {
        .change_addr = change_addr_generic, .change_size = change_size_generic,
        .change_valu = NULL,                .change_data = NULL,
        .dispatch    = dispatch_mmio_read,  .print_event = print_event_mmio_read,
        .serialize   = serialize_io_read,
        .construct   = construct_io_read,   .release     = release_nothing,
        .deep_copy   = deep_copy_no_data,
    }, [EVENT_TYPE_MMIO_WRITE] = {
        .change_addr = change_addr_generic, .change_size = change_size_generic,
        .change_valu = change_valu_generic, .change_data = NULL,
        .dispatch    = dispatch_mmio_write, .print_event = print_event_mmio_write,
        .serialize   = serialize_io_write,
        .construct   = construct_io_write,  .release     = release_nothing,
        .deep_copy   = deep_copy_no_data,
    }, [EVENT_TYPE_PIO_READ] = {
        .change_addr = change_addr_generic, .change_size = change_size_generic,
        .change_valu = NULL,                .change_data = NULL,
        .dispatch    = dispatch_pio_read,   .print_event = print_event_pio_read,
        .serialize   = serialize_io_read,
        .construct   = construct_io_read,   .release     = release_nothing,
        .deep_copy   = deep_copy_no_data,
    }, [EVENT_TYPE_PIO_WRITE] = {
        .change_addr = change_addr_generic, .change_size = change_size_generic,
        .change_valu = change_valu_generic, .change_data = NULL,
        .dispatch    = dispatch_pio_write,  .print_event = print_event_pio_write,
        .serialize   = serialize_io_write,
        .construct   = construct_io_write,  .release     = release_nothing,
        .deep_copy   = deep_copy_no_data,
    }, [EVENT_TYPE_CLOCK_STEP] = {
        .change_addr = NULL,                .change_size = NULL,
        .change_valu = change_valu_generic, .change_data = NULL,
        .dispatch    = dispatch_clock_step, .print_event = print_event_clock_step,
        .serialize   = serialize_clock_step,
        .construct   = construct_clock_step,.release     = release_nothing,
        .deep_copy   = deep_copy_no_data,
    }, [EVENT_TYPE_SOCKET_WRITE] = {
        .change_addr = NULL,                .change_size = NULL,
        .change_valu = NULL,                .change_data = change_data_socket_write,
        .dispatch    =dispatch_socket_write,.print_event = print_event_socket_write,
        .serialize   = serialize_socket_write,
        .construct   = construct_socket_write,
                                            .release     = release_data,
        .deep_copy   = deep_copy_with_data,
    }, [EVENT_TYPE_GROUP_EVENT_LM] = {
        .change_addr = NULL,                .change_size = NULL,
        .change_valu = NULL,                .change_data = NULL,
        .dispatch    = dispatch_group_event,.print_event = print_event_group_event,
        .serialize   = serialize_group_event,
        .construct   = construct_group_event,
                                            .release     = release_group_event,
        .deep_copy   = deep_copy_with_grouped_input,
    }, [EVENT_TYPE_GROUP_EVENT_RS] = {
        .change_addr = NULL,                .change_size = NULL,
        .change_valu = NULL,                .change_data = NULL,
        .dispatch    = dispatch_group_event,.print_event = print_event_group_event,
        .serialize   = serialize_group_event,
        .construct   = construct_group_event,
                                            .release     = release_group_event,
        .deep_copy   = deep_copy_with_grouped_input,
    }, [EVENT_TYPE_MEM_READ] = {
        .change_addr = NULL,                .change_size = NULL,
        .change_valu = NULL,                .change_data = NULL,
        .dispatch    = dispatch_mem_read,   .print_event = print_event_mem_read,
        .serialize   = serialize_mem_read_or_write,
        .construct   = construct_mem_read_write,
                                            .release     = release_data,
        .deep_copy   = deep_copy_with_data,
    }, [EVENT_TYPE_MEM_WRITE] = {
        .change_addr = NULL,                .change_size = NULL,
        .change_valu = NULL,                .change_data = NULL,
        .dispatch    = dispatch_mem_write,  .print_event = print_event_mem_write,
        .serialize   = serialize_mem_read_or_write,
        .construct   = construct_mem_read_write,
                                            .release     = release_data,
        .deep_copy   = deep_copy_with_data,
    }, [EVENT_TYPE_MEM_ALLOC] = {
        .change_addr = NULL,                .change_size = NULL,
        .change_valu = NULL,                .change_data = NULL,
        .dispatch    = dispatch_mem_alloc,  .print_event = print_event_mem_alloc,
        .serialize   = serialize_mem_alloc_or_free,
        .construct   = construct_mem_alloc_or_free,
                                            .release     = release_nothing,
        .deep_copy   = deep_copy_no_data,
    }, [EVENT_TYPE_MEM_FREE] = {
        .change_addr = NULL,                .change_size = NULL,
        .change_valu = NULL,                .change_data = NULL,
        .dispatch    = dispatch_mem_free,   .print_event = print_event_mem_free,
        .serialize   = serialize_mem_alloc_or_free,
        .construct   = construct_mem_alloc_or_free,
                                            .release     = release_nothing,
        .deep_copy   = deep_copy_no_data,
    },
};

void videzzo_dispatch_event(Event *event) {
    event_ops[event->type].dispatch(event);
    __flush flush = gfctx_get_flush();
    if (flush != NULL)
        flush(gfctx_get_object(0));
}

//
// Input Helpers
//
size_t get_input_size(Input *input) {
    return input->size;
}

Event *get_next_event(Event *event) {
    return TAILQ_NEXT(event, links);
}

Event *get_first_event(Input *input) {
    return TAILQ_FIRST(input->head);
}

Event *get_prev_event(Event *event) {
    return TAILQ_PREV(event, EventHead, links);
}

Event *get_event(Input *input, uint32_t index) {
    Event *event;
    if (index > input->n_events / 2) {
        // search from the end
        event = TAILQ_LAST(input->head, EventHead);
        for (int i = input->n_events - 1; i != index; i--) {
            event = get_prev_event(event);
        }
    } else {
        // search from the beginning
        event = get_first_event(input);
        for (int i = 0; i != index; i++) {
            event = get_next_event(event);
        }
    }
    return event;
}

void append_event(Input *input, Event *event) {
    TAILQ_INSERT_TAIL(input->head, event, links);
    input->n_events++;

    // update offset
    event->offset = input->size; // should be in advance
    // update input size
    input->size += event->event_size;
}

void insert_event(Input *input, Event *event, uint32_t idx) {
    if (input->n_events == 0) {
        append_event(input, event);
        return;
    }
    idx = idx % input->n_events; // don't overflow
    Event *after = get_event(input, idx);
    TAILQ_INSERT_BEFORE(after, event, links);
    input->n_events++;

    // update offset
    event->offset = get_next_event(event)->offset; // won't overflow
    for (Event *following_event = get_next_event(event);
            following_event != NULL;
            following_event = get_next_event(following_event)) {
        following_event->offset += event->event_size;
    }
    // update input size
    input->size += event->event_size;
}

static Event *__delink_event(Input *input, uint32_t idx) {
    Event *target = get_event(input, idx);
    Event *before = get_prev_event(target);
    Event *after = get_next_event(target);
    TAILQ_REMOVE(input->head, target, links);
    input->n_events--;

    // update offset
    for (Event *following_event = after;
            following_event != NULL;
            following_event = get_next_event(following_event)) {
        following_event->offset -= target->event_size;
    }
    // update input size
    input->size -= target->event_size;
    return target;
}

void remove_event(Input *input, uint32_t idx) {
    // unlink
    Event *target = __delink_event(input, idx);
    // release
    event_ops[target->type].release(target);
    free(target);
}

static void remove_events(Input *input, uint32_t start, uint32_t to) { // [a, b]
    for (int i = 0; i < to - start + 1; i++) {
        remove_event(input, start); // in-place removal
    }
}

static void swap_event(Input *input, uint32_t idx_a, uint32_t idx_b) {
    if (idx_a == idx_b)
        return;
    uint32_t left, right;
    if (idx_a > idx_b) {
        left = idx_b;
        right = idx_a;
    } else {
        left = idx_a;
        right = idx_b;
    }
    // a, b, c, d -delete-> b, d -insert-> c, b, a, d
    // 0     2              0, 1           0,    2
    // a, b, c, d -delete-> a, c -insert-> a, d, c, b
    //    1     3                             1,    2
    // step 1, delete them
    Event *event_right = __delink_event(input, right);
    Event *event_left = __delink_event(input, left);
    // stemp 2, insert them
    insert_event(input, event_right, left);
    insert_event(input, event_left, right);
}

static void swap_events(Input *input,
        uint32_t left_start, uint32_t left_end, // [left_start, left_end]
        uint32_t right_start, uint32_t right_end) { // [right_start, right_end]
    int i, j;
    Event * event;
    uint32_t left = left_end - left_start + 1;
    uint32_t right = right_end - right_start + 1;
    if (right >= left) {
        for (i = 0; i < left; i++) {
            swap_event(input, left_start + i, right_start + i);
        }
        for (j = 0; j < right - left; j++) {
            event = __delink_event(input, right_start + i + j);
            insert_event(input, event, right_start);
        }
    } else { // right < left
        for (i = 0; i < right; i++) {
            swap_event(input, left_start + i, right_start + i);
        }
        for (j = 0; j < left - right; j++) {
            event = __delink_event(input, left_start + i + j);
            append_event(input, event);
        }
    }
}

static void copy_event_to(Input *input, uint32_t from, uint32_t to) {
    // copy
    Event *orig = get_event(input, from);
    Event *copy= (Event *)calloc(sizeof(Event), 1);
    event_ops[copy->type].deep_copy(orig, copy);
    if (to >= input->n_events)
        // append
        append_event(input, copy);
    else {
        // delete target and insert
        remove_event(input, to);
        insert_event(input, copy, to);
    }
}


Input *init_input(const uint8_t *Data, size_t Size) {
    if (Size < 10)
        return NULL;
    Input *input = (Input *)calloc(sizeof(Input), 1);
    if (Data != NULL) { /* this is only for deserialization */
        input->limit = Size;
        input->buf = (void *)calloc(Size, 1);
        memcpy(input->buf, Data, Size);
    }
    input->index = 0;
    input->size = 0;
    input->head = (EventHead *)calloc(sizeof(EventHead), 1);
    TAILQ_INIT(input->head);
    input->n_events = 0;
    input->n_groups = 0;
    return input;
}

static void free_events(Input *input) {
    Event *event;
    while (!TAILQ_EMPTY(input->head)) {
        event = get_first_event(input);
        TAILQ_REMOVE(input->head, event, links);
        event_ops[event->type].release(event);
        free(event);
    }
}

void free_input(Input *input) {
    free(input->buf);
    free_events(input);
    free(input->head);
    free(input);
}

//
// Input IO
//
static bool input_check_index(Input* input, int request) {
    if (input->index + request > input->limit) {
        return false;
    }
    return true;
}

static void input_next(Input* input, void* buf, size_t size) {
    // littile-endian
    memcpy(buf, input->buf + input->index, size);
    input->index += size;
}


#define CONSUME_INPUT_NEXT(sz) \
    static uint##sz##_t input_next_##sz(Input* input) { \
    uint##sz##_t ch = 0; \
    input_next(input, &ch, sizeof(ch)); \
    return ch; \
}

CONSUME_INPUT_NEXT(8);
CONSUME_INPUT_NEXT(16);
CONSUME_INPUT_NEXT(32);
CONSUME_INPUT_NEXT(64);
CONSUME_INPUT_NEXT(ptr);

//
// Deserialize an input
//
// 1. It will happen two times. First, it will be invoked when the fuzzer is
// mutating the input; Second, it will be invoked when the fuzzer is executing
// the input. Because EventType: Interface is 1: N, we have to bind each event
// to a specific interface. The reason why we seperate events and interfaces is
// what is claimed in the MorPhuzz paper, it is better to only mutate offset
// rather than real address.
// 2. Event-Interface Binding should happen when the fuzzer is creating a new
// event (besides reset_data) rather than serializing and deserializing an
// input because which interface to bind is also a valid information.
uint32_t deserialize(Input *input) {
    // some saved data
    uint8_t interface, type, type1;
    uint64_t addr, val;
    uint32_t size;
    Event *event = NULL;
    uint8_t *Data;

#ifdef VIDEZZO_DEBUG
    fprintf(stderr, "- deserialize\n");
#endif
    while (input_check_index(input, 2)) {
        type1 = input_next_8(input);
        if (merge) {
            // if merge, we do not have a dynamic interface list, therefore
            // we cannot around event interface!
            interface = input_next_8(input);
            type = type1;
        } else {
            interface = __disimm_around_event_interface(input_next_8(input));
            type = Id_Description[interface].type;
        }
        switch (type) {
            case EVENT_TYPE_MMIO_READ:
            case EVENT_TYPE_PIO_READ:
                //   1B   1B   8B   4B
                // +TYPE+ ID +ADDR+SIZE+
                if (!input_check_index(input, 8 + 4)) {
                    input->index -= 2;
                    return get_input_size(input);
                }
                event = event_ops[type].construct(
                    type, interface, input_next_64(input), input_next_32(input), 0, NULL);
#ifdef VIDEZZO_DEBUG
                event_ops[event->type].print_event(event);
#endif
                append_event(input, event);
                break;
            case EVENT_TYPE_PIO_WRITE:
            case EVENT_TYPE_MMIO_WRITE:
                //   1B   1B   8B   4B   8B
                // +TYPE+ ID +ADDR+SIZE+VALU+
                if (!input_check_index(input, 8 + 4 + 8)) {
                    input->index -= 2;
                    return get_input_size(input);
                }
                event = event_ops[type].construct(
                    type, interface, input_next_64(input), input_next_32(input), input_next_64(input), NULL);
#ifdef VIDEZZO_DEBUG
                event_ops[event->type].print_event(event);
#endif
                append_event(input, event);
                break;
            case EVENT_TYPE_MEM_READ:
            case EVENT_TYPE_MEM_WRITE:
                //   1B   1B   8B   4B   XB
                // +TYPE+ ID +ADDR+SIZE+DATA+
                if (!input_check_index(input, 8 + 4)) {
                    input->index -= 2;
                    return get_input_size(input);
                }
                addr = input_next_64(input);
                size = input_next_32(input);
                if (!input_check_index(input, size)) {
                    input->index -= 14;
                    return get_input_size(input);
                }
                Data = (uint8_t *)calloc(size, 1);
                input_next(input, Data, size);
                event = event_ops[type].construct(type, interface, addr, size, 0, Data);
#ifdef VIDEZZO_DEBUG
                event_ops[event->type].print_event(event);
#endif
                append_event(input, event);
                break;
            case EVENT_TYPE_SOCKET_WRITE:
                //   1B   1B   4B   XB
                // +TYPE+ ID +SIZE+DATA+
                if (!input_check_index(input, 4)) {
                    input->index -= 2;
                    return get_input_size(input);
                }
                size = input_next_32(input);
                if (!input_check_index(input, size)) {
                    input->index -= 6;
                    return get_input_size(input);
                }
                Data = (uint8_t *)calloc(size, 1);
                input_next(input, Data, size);
                event = event_ops[type].construct(type, interface, 0, size, 0, Data);
#ifdef VIDEZZO_DEBUG
                event_ops[event->type].print_event(event);
#endif
                append_event(input, event);
                break;
            case EVENT_TYPE_CLOCK_STEP:
                //   1B   1B   8B
                // +TYPE+ ID +VALU+
                if (!input_check_index(input, 8)) {
                    input->index -= 2;
                    return get_input_size(input);
                }
                event = event_ops[type].construct(type, interface, 0, 0, input_next_64(input), NULL);
#ifdef VIDEZZO_DEBUG
                event_ops[event->type].print_event(event);
#endif
                append_event(input, event);
                break;
            case EVENT_TYPE_GROUP_EVENT_LM:
            case EVENT_TYPE_GROUP_EVENT_RS:
                //  1B   1B   4B
                //+TYPE+ ID +SIZE+
                if (!input_check_index(input, 4)) {
                    input->index -= 2;
                    return get_input_size(input);
                }
                // basically, we want to unflatten sub events
                size = input_next_32(input);
                if (!input_check_index(input, size)) {
                    input->index -= 6;
                    return get_input_size(input);
                }
                uint8_t *sub_events = (uint8_t *)calloc(size, 1);
                input_next(input, sub_events, size); // get their data
                Input *grouped_input = init_input(sub_events, size); // make it an input
                deserialize(grouped_input); // nice!
                free(sub_events);
                event = event_ops[type].construct(type, interface, 0, size, 0, (uint8_t *)grouped_input);
#ifdef VIDEZZO_DEBUG
                event_ops[event->type].print_event(event);
#endif
                append_event(input, event);
                break;
            default:
                fprintf(stderr, "Unsupport Event Type (deserialize)\n");
        }
    }
#ifdef VIDEZZO_DEBUG
    fprintf(stderr, "- deserialize done (%zu)\n", get_input_size(input));
#endif
    return get_input_size(input);
}

//
// Serialize an input
//
uint32_t serialize(Input *input, uint8_t *Data, uint32_t MaxSize) {
    size_t Offset = 0;

    Event *event = get_first_event(input);
#ifdef VIDEZZO_DEBUG
    fprintf(stderr, "- serialize\n");
#endif
    for (int i = 0; event != NULL; i++) {
        Offset += event_ops[event->type].serialize(event, Data, Offset, MaxSize);
        event = get_next_event(event);
    }
#ifdef VIDEZZO_DEBUG
    fprintf(stderr, "- serialize done (%zu)\n", Offset);
#endif
    return Offset;
}

//
// Mutator helpers
//
static void __Mutate_ChangeAddr(Event *event, uint64_t new_addr) {
    if (event_ops[event->type].change_addr) { // check
        event_ops[event->type].change_addr(event, new_addr); // update
    }
}

static void __Mutate_ChangeSize(Event *event, uint32_t new_size) {
    if (event_ops[event->type].change_size) { // check
        event_ops[event->type].change_size(event, new_size); // update
    }
}

static void __Mutate_ChangeValu(Event *event, uint64_t new_value) {
    if (event_ops[event->type].change_valu) { // check
        event_ops[event->type].change_valu(event, new_value); // update
    }
}

static void __Mutate_ChangeData(Event *event, uint8_t *new_data) {
    if (event_ops[event->type].change_data) { // check
        event_ops[event->type].change_data(event, new_data); // update
    }
}

static void __Mutate_InsertEvent(Input *input, uint32_t idx, uint32_t N) {
    // contruct a new event
    uint8_t interface = get_possible_interface(rand());
    uint8_t type = Id_Description[interface].type;
    for (int i = 0; i < N; i++) {
        Event *event = event_ops[type].construct(
                type, interface, rand(), rand(), rand(),
                NULL/*will allocate a buffer if needed*/);
        // insert this event at idx
        insert_event(input, event, idx);
    }
}

//
// Mutators
//
// Discard fragment [e1, e2][e3, e4, e5] -> [e1, e2]
// Size--
static size_t Mutate_EraseFragment(Input *input) { // discard
    if (input->n_events == 1) return 0; // to avoid nonsense
    size_t Idx = (rand() % input->n_events) / 2 + 1; // split it to two parts
    remove_events(input, Idx, input->n_events - 1);
    return get_input_size(input);
}

// Insert fragment [e1, e2] -> [e1, e2][e3, e4, e5]
// Size++
#define N_EVENT_FOR_A_FRAGMENT 8
static size_t Mutate_InsertFragment(Input *input) { // insert
    if (input->n_events == 1) return 0; // to avoid nonsense
    size_t N = rand() % N_EVENT_FOR_A_FRAGMENT;
    size_t Idx = (rand() % input->n_events) / 2 + 1; // split it to two parts
    for (int i = 0; i < N; i ++) {
        __Mutate_InsertEvent(input, Idx + i, 1);
    }
    return get_input_size(input);
}

// Shuffle fragments [e1, e2][e3, e4, e5] -> [e3, e4, e5][e1, e2].
// Size||
static size_t Mutate_ShuffleFragments(Input *input) { // swap
    if (input->n_events == 1) return 0; // to avoid nonsense
    size_t Idx = (rand() % input->n_events) / 2 + 1; // split it to two parts
    swap_events(input, 0, Idx, Idx + 1, input->n_events - 1);
    return get_input_size(input);
}

// Copy part of one fragment to override another fragment.
// [e1, e2][e3, e4, e5] -> [e1, e2][e3, e1, e2]
// Size++||--
static size_t Mutate_CopyPartOfFragment(Input *input) { // override
    return 0;
    if (input->n_events == 1) return 0; // to avoid nonsense
    size_t Idx = (rand() % input->n_events) / 2 + 1; // split it to two parts
    size_t ToBeg = (rand() % (input->n_events - Idx)) + Idx;
    size_t FromBeg = rand() % Idx;
    size_t N = rand() % (Idx - FromBeg);
    for (int i = 0; i < N; i++) {
        copy_event_to(input, FromBeg + i, ToBeg + i);
    }
    return get_input_size(input);
}

// CrossOver fragments [e1, e2][e3, e4, e5] -> [e1, e3][e3, e2, e4].
// Size||
static size_t Mutate_CrossOverFragments(Input *input) { // crossover
    if (input->n_events <= 2) return 0; // to avoid nonsense
    size_t Idx = (rand() % input->n_events) / 2 + 1; // split it to two parts
    size_t LeftEventIdx = rand() % Idx; // choose one
    size_t RightEventIdx = (rand() % (input->n_events - Idx)) + Idx; // choose another one
    swap_event(input, LeftEventIdx, RightEventIdx);
    return get_input_size(input);
}

static size_t Mutate_AddFragmentFromManualDictionary(Input *input) { // dictionary
    return get_input_size(input);
}

static size_t Mutate_AddFragmentFromPersistentAutoDictionary(Input *input) { // dictionary
    return get_input_size(input);
}

// Discard event [e1, e2, e3] -> [e1, e2]
// Size--
static size_t Mutate_EraseEvent(Input *input) { // discard
    if (input->n_events <= 1) return 0; // to avoid nonsense
    size_t Idx = rand() % input->n_events; // choose one event
    remove_events(input, Idx, Idx); // remove it
    return get_input_size(input);
}

// Insert event [e1, e2, e3] -> [e1, e2, e3, e4]
// Size++
static size_t Mutate_InsertEvent(Input *input) { // insert
    size_t Idx = rand() % input->n_events; // choose one event
    __Mutate_InsertEvent(input, Idx, 1);
    return get_input_size(input);
}

// Insert repeated event [e1, e2, e3] -> [e1, e2, e3, e4, e4, e4]
// Size++
#define N_MIN_EVENTS_TO_INSERT 3
#define N_MAX_EVENTS_TO_INSERT 8
static size_t Mutate_InsertRepeatedEvent(Input *input) { // duplicate
    size_t Idx = rand() % input->n_events; // choose one event
    size_t N = (rand() - N_MIN_EVENTS_TO_INSERT) %
        (N_MAX_EVENTS_TO_INSERT - N_MIN_EVENTS_TO_INSERT) + N_MIN_EVENTS_TO_INSERT; // insert N events
    Event *event = get_event(input, Idx); // get this event
    if (event->type == EVENT_TYPE_GROUP_EVENT_RS || event->type == EVENT_TYPE_GROUP_EVENT_LM)
        return 0;
    Event *copy;
    for (int i = 0; i < N; i++) {
        copy = (Event *)calloc(sizeof(Event), 1);
        event_ops[event->type].deep_copy(event, copy);
        insert_event(input, copy, Idx);
    }
    return get_input_size(input);
}

// Shuffle events [e1, e2, e3] -> [e3, e1, e2]
// Size||
static size_t Mutate_ShuffleEvents(Input *input) { //shuffle
    // Fisher-Yates Shuffle
    // https://www.geeksforgeeks.org/shuffle-a-given-array-using-fisher-yates-shuffle-algorithm/
    for (int i = input->n_events - 1, j = 0; i > 0; i--) { // for each event
        j = rand() % (i + 1); // select one event from 0 to i
        swap_event(input, i, j);
    }
    return get_input_size(input);
}

// Size++
static size_t Mutate_AddEventFromManualDictionary(Input *input) { // dictionary
    return get_input_size(input);
}

// Size++
static size_t Mutate_AddEventFromPersistentAutoDictionary(Input *input) { // dictionary
    return get_input_size(input);
}

// Size||
static size_t Mutate_ChangeAddr(Input *input) { // randomize
    size_t Idx = rand() % input->n_events; // choose one event
    Event *event = get_event(input, Idx); // get this event
    __Mutate_ChangeAddr(event, rand());
    return get_input_size(input);
}

// Size||
static size_t Mutate_ChangeSize(Input *input) { // randomize
    size_t Idx = rand() % input->n_events; // choose one event
    Event *event = get_event(input, Idx); // get this event
    __Mutate_ChangeSize(event, rand());
    return get_input_size(input);
}

// Size||
static size_t Mutate_ChangeValue(Input *input) { // randomize
    size_t Idx = rand() % input->n_events; // choose one event
    Event *event = get_event(input, Idx); // get this event
    __Mutate_ChangeValu(event, rand());
    uint8_t *buffer = __get_buffer(event->size);
    __Mutate_ChangeData(event, buffer);
    free(buffer);
    return get_input_size(input);
}

size_t (*CustomMutators[])(Input *input) = {
    Mutate_EraseFragment,
    Mutate_InsertFragment,
    Mutate_ShuffleFragments,
    Mutate_ShuffleEvents,
    Mutate_EraseEvent,
    Mutate_InsertEvent,
    Mutate_InsertRepeatedEvent,
    Mutate_ChangeAddr,
    Mutate_ChangeSize,
    Mutate_ChangeValue,
    Mutate_CopyPartOfFragment,
    Mutate_CrossOverFragments,
    Mutate_AddFragmentFromManualDictionary,
    Mutate_AddFragmentFromPersistentAutoDictionary,
    Mutate_AddEventFromManualDictionary,
    Mutate_AddEventFromPersistentAutoDictionary,
};

const char *CustomMutatorNames[N_MUTATORS] = {
    "Mutate_EraseFragment", // g
    "Mutate_InsertFragment", // g
    "Mutate_ShuffleFragments", // g
    "Mutate_ShuffleEvents", // g
    "Mutate_EraseEvent", // l
    "Mutate_InsertEvent", // l
    "Mutate_InsertRepeatedEvent", // l
    "Mutate_ChangeAddr", // l
    "Mutate_ChangeSize", // l
    "Mutate_ChangeValue", // l
    "Mutate_CopyPartOfFragment", // g
    "Mutate_CrossOverFragments", // g
    "Mutate_AddFragmentFromManualDictionary", // d
    "Mutate_AddFragmentFromPersistentAutoDictionary", // d
    "Mutate_AddEventFromManualDictionary", // d
    "Mutate_AddEventFromPersistentAutoDictionary", // d
};

//
// Mutator Scheduling
//
int select_mutators(int rand) {
    return rand % 11;
}

int select_weighted_mutators(int rand) {
    int t = 6 * 1 + 7 * 4;
    rand = rand % t;

    if (rand < 6) {
        return rand;
    } else {
        return 6 + (rand - 6) / 4;
    }
}

//
// Generic Feedback Context
//
static GenericFeedbackContext gfctx[2];

void gfctx_set_current_input(Input *input, int gfctx_id) {
    gfctx[gfctx_id].current_input = input;
}

Input *gfctx_get_current_input(int gfctx_id) {
    return gfctx[gfctx_id].current_input;
}

void gfctx_set_current_event(int idx, int gfctx_id) {
    gfctx[gfctx_id].current_event = idx;
}

int gfctx_get_current_event(int gfctx_id) {
    return gfctx[gfctx_id].current_event;
}

void gfctx_set_object(void *object, int gfctx_id) {
    gfctx[gfctx_id].object = object;
}

void *gfctx_get_object(int gfctx_id) {
    return gfctx[gfctx_id].object;
}

void gfctx_set_data(uint8_t *Data, int gfctx_id) {
    gfctx[gfctx_id].Data = Data;
}

uint8_t *gfctx_get_data(int gfctx_id) {
    return gfctx[gfctx_id].Data;
}

void gfctx_set_size(uint32_t MaxSize, int gfctx_id) {
    gfctx[gfctx_id].MaxSize = MaxSize;
}

uint32_t gfctx_get_size(int gfctx_id) {
    return gfctx[gfctx_id].MaxSize;
}

static __flush vmm_flush;

void gfctx_set_flush(__flush flush) {
    vmm_flush = flush;
}

__flush gfctx_get_flush(void) {
    return vmm_flush;
}

//
// Maybe we can make the initial seed empty
//
size_t reset_data(uint8_t *Data, size_t MaxSize) {
    InterfaceDescription *ed;
    Event *event;

    Input *input = init_input(Data, MaxSize);
#ifdef VIDEZZO_DEBUG
    fprintf(stderr, "- reset_data\n");
#endif
    for (int i = 0; i < n_interfaces; ++i) {
        ed = &Id_Description[i];
        if (!ed->dynamic)
            continue;
        event = event_ops[ed->type].construct(ed->type, i, rand(), rand(), rand(), NULL);
        append_event(input, event);
    }
    // save
    size_t Size = serialize(input, Data, MaxSize);
    free_input(input);
    return Size;
}

//
// libFuzzer interfaces
//
size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
        size_t MaxSize, unsigned int Seed) {
    if (getenv("VIDEZZO_DISABLE_INTER_MESSAGE_MUTATORS"))
        return LLVMFuzzerMutate(Data, Size, MaxSize);
    else
        return ViDeZZoCustomMutator(Data, Size, MaxSize, Seed);
}

ViDeZZoFuzzTarget *fuzz_target;
void save_fuzz_target(ViDeZZoFuzzTarget *new_fuzz_target) {
    fuzz_target = new_fuzz_target;
}

ViDeZZoFuzzTarget *restore_fuzz_target(void) {
    return fuzz_target;
}

int LLVMFuzzerTestOneInput(unsigned char *Data, size_t Size) {
    static int pre_fuzz_done;
    if (!pre_fuzz_done && fuzz_target->pre_fuzz) {
        fuzz_target->pre_fuzz();
        pre_fuzz_done = true;
        sem_init(&mutex, 0, 1);
    }
    // as we may append events, LLVMFuzzerTestoneInput should
    // return the size of the new input
    size_t Res = fuzz_target->fuzz(Data, Size);
    return Res;
}

//
// Fuzz Target
//
// all targets go here
ViDeZZoFuzzTargetList *videzzo_fuzz_target_list;

void videzzo_usage(void) {
    ViDeZZoFuzzTargetState *tmp;
    if (!videzzo_fuzz_target_list) {
        fprintf(stderr, "Fuzz target list not initialized\n");
        abort();
    }
    LIST_FOREACH(tmp, videzzo_fuzz_target_list, target_list) {
        printf(" * %s  : %s\n", tmp->target->name, tmp->target->description);
    }
    printf("Alternatively, add -target-FUZZ_TARGET to the executable name\n\n");
}

int parse_fuzz_target_name(int *argc, char ***argv, char **target_name) {
    *target_name = strstr(**argv, "-target-");
    if (*target_name) {      /* The binary name specifies the target */
        *target_name += strlen("-target-");
        return NAME_INBINARY;
    } else if (*argc > 1) { /* The target is specified as an argument */
        *target_name = (*argv)[1];
        if (!strstr(*target_name, "--fuzz-target="))
            return NAME_INVALID;
        *target_name += strlen("--fuzz-target=");
        return NAME_INARGUMENT;
    } else {
        return NAME_INVALID;
    }
}

void videzzo_add_fuzz_target(ViDeZZoFuzzTarget *target) {
    ViDeZZoFuzzTargetState *tmp;
    ViDeZZoFuzzTargetState *target_state;
    if (!videzzo_fuzz_target_list) {
        videzzo_fuzz_target_list = g_new0(ViDeZZoFuzzTargetList, 1);
    }

    LIST_FOREACH(tmp, videzzo_fuzz_target_list, target_list) {
        if (g_strcmp0(tmp->target->name, target->name) == 0) {
            fprintf(stderr, "Error: Fuzz target name %s already in use\n", target->name);
            abort();
        }
    }
    target_state = g_new0(ViDeZZoFuzzTargetState, 1);
    target_state->target = g_new0(ViDeZZoFuzzTarget, 1);
    *(target_state->target) = *target;
    LIST_INSERT_HEAD(videzzo_fuzz_target_list, target_state, target_list);
}

ViDeZZoFuzzTarget *videzzo_get_fuzz_target(char* name) {
    ViDeZZoFuzzTargetState *tmp;
    if (!videzzo_fuzz_target_list) {
        fprintf(stderr, "Fuzz target list not initialized\n");
        abort();
    }

    LIST_FOREACH(tmp, videzzo_fuzz_target_list, target_list) {
        if (g_strcmp0(tmp->target->name, name) == 0) {
            return tmp->target;
        }
    }
    return NULL;
}

//
// Sockets
//
void init_sockets(int sockfds[]) {
    int ret = socketpair(PF_UNIX, SOCK_STREAM, 0, sockfds);
    g_assert_cmpint(ret, !=, -1);
    fcntl(sockfds[0], F_SETFL, O_NONBLOCK);
}

//
// VNC
//
static rfbClient* client;
static void vnc_client_output(rfbClient* client, int x, int y, int w, int h) {}

int remove_offset_from_vnc_port(int vnc_port) {
    return vnc_port - SERVER_PORT_OFFSET;
}

/*
 * FindFreeTcpPort tries to find unused TCP port in the range
 * (SERVER_PORT_OFFSET, SERVER_PORT_OFFSET + 99]. Returns 0 on failure.
 */
static int FindFreeTcpPort1(void) {
  int sock, port;
  struct sockaddr_in addr;

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);

  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    rfbClientErr(": FindFreeTcpPort: socket\n");
    return 0;
  }

  for (port = SERVER_PORT_OFFSET + 99; port > SERVER_PORT_OFFSET; port--) {
    addr.sin_port = htons((unsigned short)port);
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
      close(sock);
      return port;
    }
  }

  close(sock);
  return 0;
}

int init_vnc(void) {
    int vnc_port = FindFreeTcpPort1();
    if (!vnc_port) {
        _Exit(1);
    }
    return vnc_port;
}

int init_vnc_client(void *s, int vnc_port) {
    client = rfbGetClient(8, 3, 4);
    if (fork() == 0) {
        client->GotFrameBufferUpdate = vnc_client_output;
        client->serverPort = vnc_port;
        if(!rfbInitClient(client, NULL, NULL)) {
            _Exit(1);
        }
        while (1) {
            if(WaitForMessage(client, 50) < 0)
                break;
            if(!HandleRFBServerMessage(client))
                break;
        }
        rfbClientCleanup(client);
        _Exit(0);
    } else {
        __flush flush = gfctx_get_flush();
        if (flush != NULL)
            flush(s);
    }
    return 0;
}

static void vnc_client_receive(void) {
    while (1) {
        if(WaitForMessage(client, 50) < 0)
            break;
        if(!HandleRFBServerMessage(client))
            break;
    }
}

static void uninit_vnc_client(void) {
    rfbClientCleanup(client);
}

//
// Disable inter-message mutators
//
uint32_t __disimm_around_event_size(uint32_t size, uint32_t mod) {
    if (getenv("VIDEZZO_DISABLE_INTER_MESSAGE_MUTATORS"))
        return pow2floor((size - 1) % (mod - 1) + 1);
    else
        return size;
}

uint8_t __disimm_around_event_interface(uint8_t interface) {
    if (getenv("VIDEZZO_DISABLE_INTER_MESSAGE_MUTATORS")) {
        return get_possible_interface(interface);
    } else
        return interface;
}
