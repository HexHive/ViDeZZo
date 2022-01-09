/*
 * Type-Aware Virtual-Device Fuzzing
 *
 * Copyright Qiang Liu <cyruscyliu@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 */

#include "videzzo.h"
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>

//
// GroupMutator Feedback
//
bool DisableGroupMutator = 0;

void GroupMutatorMiss(uint8_t id, uint64_t physaddr) {
#ifdef VIDEZZO_DEBUG
    fprintf(stderr, "- GroupMutatorMiss\n");
#endif
    if (DisableGroupMutator)
        return;

    // In this handler, the current input will be changed
    // Don't delete any events from the current event to the end
    group_mutator_miss_handlers[id](physaddr);
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
    // Mutate all events
    // TODO: maybe 100 is tunable
    for (int i = 0; i < 100; i++) {
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
    }
    free_input(input);
    return reset_data(Data, MaxSize); // Fallback, should not happen frequently.
}

void __videzzo_execute_one_input(Input *input, void *object) {
    Event *event = input->events;
#ifdef VIDEZZO_DEBUG
    fprintf(stderr, "- dispatching events\n");
#endif
    int i;
    for (i = 0; event != NULL; i++) {
#ifdef VIDEZZO_DEBUG
        event_ops[event->type].print_event(event);
#endif
        // set up feedback context
        gfctx_set_current_event(i);
        videzzo_dispatch_event(event, object);
        event = get_next_event(event);
    }
    gfctx_set_current_event(0);
#ifdef VIDEZZO_DEBUG
    fprintf(stderr, "- dispatching events done\n");
#endif
}

size_t videzzo_execute_one_input(uint8_t *Data, size_t Size, void *object) {
    // read Data to Input
    Input *input = init_input(Data, Size);
    if (!input)
        return 0;
    // deserialize Data to Events
    input->size = deserialize(input);
    // set up feedback context
    gfctx_set_current_input(input);
    gfctx_set_object(object);
    // if (fork() == 0) {
        __videzzo_execute_one_input(input, object);
    //    _Exit(0);
    // } else {
    //     wait(0);
    // }
    size_t SerializationSize = serialize(input, Data, DEFAULT_INPUT_MAXSIZE);
    gfctx_set_current_input(NULL);
    gfctx_set_object(NULL);
    free_input(input);
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
        .name = "socket_write", .dynamic = true,
        .min_access_size = 0xFF, .max_access_size = 0xFF,
    }, [INTERFACE_GROUP_EVENT] = {
        .type = EVENT_TYPE_GROUP_EVENT,
        .emb = {.addr = 0xFFFFFFFF, .size = 0xFFFFFFFF},
        .name = "group_event", .dynamic = false,
        .min_access_size = 0xFF, .max_access_size = 0xFF,
    }, [INTERFACE_MEM_ALLOC] = {
        .type = EVENT_TYPE_MEM_ALLOC,
        .emb = {.addr = 0xFFFFFFFF, .size = 0xFFFFFFFF},
        .name = "group_event", .dynamic = false,
        .min_access_size = 0xFF, .max_access_size = 0xFF,
    }, [INTERFACE_MEM_FREE] = {
        .type = EVENT_TYPE_MEM_FREE,
        .emb = {.addr = 0xFFFFFFFF, .size = 0xFFFFFFFF},
        .name = "group_event", .dynamic = false,
        .min_access_size = 0xFF, .max_access_size = 0xFF,
    }
};

uint32_t n_interfaces = INTERFACE_DYNAMIC;

void add_interface(EventType type, uint64_t addr, uint32_t size,
        char *name, uint8_t min_access_size, uint8_t max_access_size, bool dynamic) {
    Id_Description[n_interfaces].type = type;
    Id_Description[n_interfaces].emb.addr = addr;
    Id_Description[n_interfaces].emb.size = size;
    Id_Description[n_interfaces].min_access_size = min_access_size;
    Id_Description[n_interfaces].max_access_size = max_access_size;
    memcpy(Id_Description[n_interfaces].name, name, strlen(name) <= 32 ? strlen(name) : 32);
    Id_Description[n_interfaces].dynamic = dynamic;
    n_interfaces++;
}

static uint64_t around_event_addr(uint8_t id, uint64_t raw_addr) {
    if (id < INTERFACE_DYNAMIC)
        return raw_addr; // do nothing
    InterfaceDescription ed = Id_Description[id];
    if (getenv("VIDEZZO_BYTE_ALIGNED_ADDRESS")) {
        return (ed.emb.addr + raw_addr % ed.emb.size) & 0xFFFFFFFFFFFFFFFF;
    } else {
        return (ed.emb.addr + raw_addr % ed.emb.size) & 0xFFFFFFFFFFFFFFFC;
    }
}

static inline int clz64(uint64_t val)
{
    return val ? __builtin_clzll(val) : 64;
}

static inline uint64_t pow2floor(uint64_t value)
{
    if (!value) {
        /* Avoid undefined shift by 64 */
        return 0;
    }
    return 0x8000000000000000ull >> clz64(value);
}

static uint32_t around_event_size(uint8_t id, uint32_t raw_size) {
    if (id != INTERFACE_SOCKET_WRITE && id < INTERFACE_DYNAMIC)
        return raw_size % 0x10000; // 1M to avoid oom
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

static uint32_t change_size_generic(Event *event, uint32_t new_size) {
    event->size = around_event_size(event->interface, new_size);
    return new_size;
}

static void change_valu_generic(Event *event, uint64_t new_valu) {
    event->valu = new_valu;
}

static uint32_t change_size_socket_write(Event *event, uint32_t new_size) {
    // copy old data
    new_size = around_event_size(event->interface, new_size);
    uint8_t *new_data = (uint8_t *)calloc(new_size, 1);
    if (new_size >= event->size) {
        memcpy(new_data, event->data, event->size);
    } else {
        memcpy(new_data, event->data, new_size);
    }
    free(event->data);
    event->data = new_data;
    // update size
    event->event_size += (new_size - event->size);
    event->size = new_size;
    return new_size;
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
        fprintf(stderr, ", 0x%s...", enc);
    } else
        fprintf(stderr, ", 0x%s", enc);
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
    event->size = around_event_size(interface, size);
    assert(data != NULL);
    // assume we are in charge of free this data for performance
    event->data = data;
    event->event_size = event->size + 3;
    return event;
}

static uint32_t serialize_io_read(Event *event, uint8_t *Data, size_t Offset, size_t MaxSize) {
    if (Offset + 14 >= MaxSize)
        return 0;
    Data[Offset] = event->type;
    Data[Offset + 1] = event->interface;
    memcpy(Data + Offset + 2, (uint8_t *)&(event->addr), 8);
    memcpy(Data + Offset + 10, (uint8_t *)&(event->size), 4);
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
        memcpy(Data + Offset + 14, (uint8_t *)&(event->valu), size);
    return 14 + event->size;
}

static uint32_t serialize_mem_alloc_or_free(Event *event, uint8_t *Data, size_t Offset, size_t MaxSize) {
    if (Offset + 8 >= MaxSize)
        return 0;
    Data[Offset] = event->type;
    Data[Offset + 1] = event->interface;
    memcpy(Data + Offset + 2, (uint8_t *)&(event->valu), 8);
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
    return 6 + size;
}

static uint32_t serialize_clock_step(Event *event, uint8_t *Data, size_t Offset, size_t MaxSize) {
    if (Offset + 10 >= MaxSize)
        return 0;
    Data[Offset] = event->type;
    Data[Offset + 1] = event->interface;
    memcpy(Data + Offset + 2, (uint8_t *)&event->valu, 8);
    return 10;
}

static uint32_t serialize_group_event(Event *event, uint8_t *Data, size_t Offset, size_t MaxSize) {
    uint32_t size = event->size;
    if (Offset + 3 + size >= MaxSize)
        return 0;
    Data[Offset] = event->type;
    Data[Offset + 1] = event->interface;
    Input *input = (Input *)event->data;
    return 3 + size;
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
        .change_addr = NULL,                .change_size = change_size_socket_write,
        .change_valu = NULL,                .change_data = change_data_socket_write,
        .dispatch    =dispatch_socket_write,.print_event = print_event_socket_write,
        .serialize   = serialize_socket_write,
        .construct   = construct_socket_write,
                                            .release     = release_data,
        .deep_copy   = deep_copy_with_data,
    }, [EVENT_TYPE_GROUP_EVENT] = { // ?
        .change_addr = NULL,                .change_size = NULL,
        .change_valu = NULL,                .change_data = NULL,
        .dispatch    = NULL,                .print_event = NULL,
        .serialize   = serialize_group_event,
        .construct   = construct_group_event,
                                            .release     = release_group_event,
        .deep_copy   = deep_copy_with_data,
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

void videzzo_dispatch_event(Event *event, void *object) {
    uint64_t addr = event->addr;
    uint32_t size = event->size;
    event_ops[event->type].dispatch(event, object);
}

//
// Input Helpers
//
static size_t get_input_size(Input *input) {
    return input->size;
}

static uint32_t get_event_size(Input *input, uint32_t index) {
    // event->next, event->event_size are used
    Event *event = input->events;
    for (int i = 0; i < index; i++) {
        if (!event->next)
            break;
        event = event->next;
    }
    return event->event_size;
}

static uint32_t get_event_offset(Input *input, uint32_t index) {
    // event->next, event->offset are used
    Event *event = input->events;
    for (int i = 0; i < index; i++) {
        if (!event->next)
            break;
        event = event->next;
    }
    return event->offset;
}

Event *get_event(Input *input, uint32_t index) {
    Event *event = input->events;
    for (int i = 0; i != index; i++)
        event = event->next;
    return event;
}

Event *get_next_event(Event *event) {
    return event->next;
}

static void append_event(Input *input, Event *event) {
    Event *last_event = input->events;
    if (!last_event) {
        input->events = event;
    } else {
        while (last_event->next) {
            last_event = last_event->next;
        }
        last_event->next = event;
    }
    event->next = NULL;
    input->n_events++;
    event->offset = input->size; // should be in advance
    input->size += event->event_size; // DataSize
}

void insert_event(Input *input, Event *event, uint32_t idx) {
    if (input->n_events == 0) {
        append_event(input, event);
        return;
    }
    // single linked list insertion
    idx = idx % input->n_events; // don't overflow
    if (idx == 0) {
        event->next = input->events;
        input->events = event;
    } else {
        Event *head = get_event(input, idx - 1);
        event->next = head->next;
        head->next = event;
    }
    input->n_events++;
    // update offset
    event->offset = event->next->offset; // won't overflow
    for (Event *following_event = event->next;
            following_event != NULL; following_event = following_event->next) {
        following_event->offset += event->event_size;
    }
    // update input size
    input->size += event->event_size;
}

static Event *__delink_event(Input *input, uint32_t idx) {
    // remove
    Event *before, *target, *after;
    if (idx == 0) {
        target = input->events;
        input->events = target->next;
        after = target->next;
    } else {
        before = get_event(input, idx - 1);
        target = before->next;
        after = target->next;
        before->next = after;
    }
    input->n_events--;
    // update offset
    for (Event *following_event = after;
            following_event != NULL; following_event = following_event->next) {
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
    fprintf(stderr, "%d, %d\n", from, to);
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
    if (Size < 13)
        return NULL;
    Input *input = (Input *)calloc(sizeof(Input), 1);
    input->limit = Size;
    input->buf = (void *)calloc(Size, 1);
    memcpy(input->buf, Data, Size);
    input->index = 0;
    input->size = 0;
    input->events = NULL;
    input->n_events = 0;
    input->n_groups = 0;
    return input;
}

static void free_events(Input *input) {
    Event *events = input->events, *tmp;
    while ((tmp = events)) {
        event_ops[tmp->type].release(tmp);
        events = events->next;
        free(tmp);
    }
}

void free_input(Input *input) {
    free(input->buf);
    free_events(input);
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
    uint8_t interface, type;
    uint64_t addr, val;
    uint32_t size;
    Event *event = NULL;
    uint8_t *Data;

#ifdef VIDEZZO_DEBUG
    fprintf(stderr, "- deserialize\n");
#endif
    while (input_check_index(input, 2)) {
        type = input_next_8(input);
        interface = input_next_8(input);
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
            case EVENT_TYPE_GROUP_EVENT:
                //  1B   1B   1B
                //+TYPE+ ID +SIZE+
                if (!input_check_index(input, 1)) {
                    input->index -= 2;
                    return get_input_size(input);
                }
                // basically, we want to unflatten sub events
                uint8_t *sub_events = (uint8_t *)calloc(size, 1);
                input_next(input, sub_events, size); // get their data
                Input *input = init_input(sub_events, size); // make it an input
                deserialize(input); // nice!
                free(sub_events);
                event = event_ops[type].construct(type, interface, 0, input_next_8(input), 0, (uint8_t *)input);
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

    Event *event = input->events;
#ifdef VIDEZZO_DEBUG
    fprintf(stderr, "- serialize\n");
#endif
    for (int i = 0; event != NULL; i++) {
#ifdef VIDEZZO_DEBUG
        event_ops[event->type].print_event(event);
#endif
        Offset += event_ops[event->type].serialize(event, Data, Offset, MaxSize);
        event = event->next;
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

static uint32_t __Mutate_ChangeSize(Event *event, uint32_t new_size) {
    if (event->type == EVENT_TYPE_SOCKET_WRITE) {
        new_size = (new_size - SOCKET_WRITE_MIN_SIZE) %
            (SOCKET_WRITE_MAX_SIZE - SOCKET_WRITE_MIN_SIZE) + SOCKET_WRITE_MIN_SIZE;
    }
    if (event_ops[event->type].change_size) { // check
        return event_ops[event->type].change_size(event, new_size); // update
    }
    return 0;
}

static void __Mutate_ChangeValu(Event *event, uint64_t new_value) {
    if (event_ops[event->type].change_valu) { // check
        event_ops[event->type].change_valu(event, new_value); // update
    }
}

static void __Mutate_ChangeData(Event *event, uint8_t *new_data) {
    if (event_ops[event->type].change_data) {
        event_ops[event->type].change_data(event, new_data);
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
    __Mutate_InsertEvent(input, Idx, N);
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

// Size--||++
static size_t Mutate_ChangeSize(Input *input) { // randomize
    size_t Idx = rand() % input->n_events; // choose one event
    Event *event = get_event(input, Idx); // get this event
    uint32_t old_size = event->size;
    uint32_t new_size = rand();
    new_size = __Mutate_ChangeSize(event, rand());
    if (new_size == 0)
        return 0;
    // update offset
    for (Event *following_event = event->next;
            following_event != NULL; following_event = following_event->next) {
        if (new_size >= old_size)
            following_event->offset += (new_size - old_size);
        else
            following_event->offset -= (old_size - new_size);
    }
    // update input size
    if (new_size >= old_size)
        input->size += (new_size - old_size);
    else
        input->size -= (old_size - new_size);
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
GenericFeedbackContext gfctx;

void gfctx_set_current_input(Input *input) {
    gfctx.current_input = input;
}

Input *gfctx_get_current_input() {
    return gfctx.current_input;
}

void gfctx_set_current_event(int idx) {
    gfctx.current_event = idx;
}

int gfctx_get_current_event() {
    return gfctx.current_event;
}

void gfctx_set_object(void *object) {
    gfctx.object = object;
}

void *gfctx_get_object() {
    return gfctx.object;
}

void gfctx_set_data(uint8_t *Data) {
    gfctx.Data = Data;
}

uint8_t *gfctx_get_data() {
    return gfctx.Data;
}

void gfctx_set_size(uint32_t MaxSize) {
    gfctx.MaxSize = MaxSize;
}

uint32_t gfctx_get_size() {
    return gfctx.MaxSize;
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
    serialize(input, Data, MaxSize);
    size_t Size = get_input_size(input);
    free_input(input);
    return Size;
}
