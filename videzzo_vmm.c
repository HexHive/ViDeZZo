/*
 * Type-Aware Virtual-Device Fuzzing
 *
 * Copyright Qiang Liu <cyruscyliu@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#include "videzzo.h"

//
// VMM for testing
// This small VM has one main memory, one robot virtual device with one PIO
// region and two MMIO regions.
//

//
// Memory
//
enum MemoryRegionType {PIO, MMIO, MEM};

typedef struct MemoryRegion {
    uint8_t type;
    char devname[15];
    uint64_t base;
    uint32_t size;
    uint8_t pad1[4];
    uint64_t (*read)(uint64_t addr, uint32_t size);
    void (*write)(uint64_t addr, uint32_t size, uint64_t valu);
} MemoryRegion;

static uint64_t generic_pio_read(uint64_t addr, uint32_t size) {
    return 0xabababab;
}

static void dma_memory_read(uint64_t addr) { }

static void generic_pio_write(uint64_t addr, uint32_t size, uint64_t valu) {
    if (addr == 0x30) {
        // suppose we are going to read some here
        dma_memory_read(0x10000);
        // some dma memory read in the following
    }
}

static uint64_t generic_mmio_read(uint64_t addr, uint32_t size) {
    return 0x41414141;
}

static void generic_mmio_write(uint64_t addr, uint32_t size, uint64_t valu) {
    if (addr == 0x20) {
        // suppose we are going to read some here
        dma_memory_read(0x10000);
    }
}

static uint64_t generic_mem_read(uint64_t addr, uint32_t size) {
    return rand() % 2 ? 0xffffffff : 0x0;
}

static void generic_mem_write(uint64_t addr, uint32_t size, uint8_t *valu) {
}

MemoryRegion memory[4] = {
    [0] = {
        .type = PIO,
        .devname = "robot",
        .base = 0xff00,
        .size = 0xff,
        .read = generic_pio_read,
        .write= generic_pio_write,
    }, [1] = {
        .type = MMIO,
        .devname = "robot",
        .base = 0xe000b000,
        .size = 0xff,
        .read = generic_mmio_read,
        .write= generic_mmio_write,
    }, [2] = {
        .type = MMIO,
        .devname = "robot",
        .base = 0xe000b100, // byte-aligned
        .size = 0xff,
        .read = generic_mmio_read,
        .write= generic_mmio_write,
    }, [3] = {
        .type = MEM,
        .devname = "memory",
        .base = 0x10000,
        .size = 0xfffff,
    }
};

//
// Simple Trap Emulator
//
static MemoryRegion *find_mr(uint64_t addr) {
    MemoryRegion *mr;
    for (int i = 0; i < 4; i++) {
        mr = &memory[i];
        if (addr >= mr->base && addr < mr->base + mr->size) {
            return mr;
        }
    }
    return NULL;
}

static uint64_t trap_read(uint64_t addr, uint32_t size)  {
    MemoryRegion *mr = find_mr(addr);
    if (mr == NULL) fprintf(stderr, "[-] error: cannot find addr 0x%lx, please check\n", addr);
    return mr->read(addr - mr->base, size);
}

static void trap_write(uint64_t addr, uint32_t size, uint64_t valu)  {
    MemoryRegion *mr = find_mr(addr);
    if (mr == NULL) fprintf(stderr, "[-] error: cannot find addr 0x%lx, please check\n", addr);
    mr->write(addr - mr->base, size, valu);
}


//
// VM Specific Bindings
//
int LLVMFuzzerInitialize(int *argc, char ***argv, char ***envp) {
    //
    // Usage: through libFuzzer
    //

    //
    // Register targets: not necessary
    //

    //
    // Initialize the VM: not necessary
    //

    //
    // Set up interfaces
    //
    MemoryRegion *mr;
    for (int i = 0; i < 4; i++) {
        mr = &memory[i];
        switch (mr->type) {
            case PIO:
                add_interface(EVENT_TYPE_PIO_READ, mr->base, mr->size, mr->devname, 0x1, 0x4, true);
                add_interface(EVENT_TYPE_PIO_WRITE, mr->base, mr->size, mr->devname, 0x1, 0x4, true);
                break;
            case MMIO:
                add_interface(EVENT_TYPE_MMIO_READ, mr->base, mr->size, mr->devname, 0x1, 0x4, true);
                add_interface(EVENT_TYPE_MMIO_WRITE, mr->base, mr->size, mr->devname, 0x1, 0x4, true);
                break;
            default:
                break;
        }
    }
    return 0;
}

//
// Call into videzzo from QEMU
//
int __LLVMFuzzerTestOneInput(uint8_t *Data, size_t Size) {
    videzzo_execute_one_input(Data, Size, NULL, NULL);
    return 0;
}

//
// Call into videzzo from QEMU
//
size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
        size_t MaxSize, unsigned int Seed) {
    return ViDeZZoCustomMutator(Data, Size, MaxSize, Seed);
}

//
// Dispatcher
//
static uint64_t dispatch_generic_read(Event *event) {
    switch (event->size) {
        case ViDeZZo_Byte: return trap_read(event->addr, 1);
        case ViDeZZo_Word: return trap_read(event->addr, 2);
        case ViDeZZo_Long: return trap_read(event->addr, 4);
        case ViDeZZo_Quad: return trap_read(event->addr, 8);
        default: fprintf(stderr, "[-] wrong size of dispatch_generic_read %d\n", event->size); return 0;
    }
}

static uint64_t dispatch_generic_write(Event *event) {
    switch (event->size) {
        case ViDeZZo_Byte: trap_write(event->addr, 1, event->valu); break;
        case ViDeZZo_Word: trap_write(event->addr, 2, event->valu); break;
        case ViDeZZo_Long: trap_write(event->addr, 4, event->valu); break;
        case ViDeZZo_Quad: trap_write(event->addr, 8, event->valu); break;
        default: fprintf(stderr, "[-] wrong size of dispatch_generic_write %d\n", event->size); break;
    }
    return 0;
}

uint64_t dispatch_mmio_read(Event *event) { return dispatch_generic_read(event); }
uint64_t dispatch_pio_read(Event *event) { return dispatch_generic_read(event); }
uint64_t dispatch_mmio_write(Event *event) { dispatch_generic_write(event); return 0; }
uint64_t dispatch_pio_write(Event *event) { dispatch_generic_write(event); return 0; }

uint64_t dispatch_mem_read(Event *event) {
    uint64_t ret = generic_mem_read(event->addr, event->size);
    memcpy(event->data, (uint8_t *)&ret, event->size);
    return 0;
}

uint64_t dispatch_mem_write(Event *event) {
    generic_mem_write(event->addr, event->size, event->data);
    return 0;
}

static int mem_index = 0;

uint64_t AroundInvalidAddress(uint64_t physaddr) { return physaddr; }

uint64_t dispatch_mem_alloc(Event *event) {
    // a small allocator
    mem_index += 1;
    return 0x10000 + 0x2000 * mem_index;
}

uint64_t dispatch_mem_free(Event *event) {
    // a small allocator
    mem_index -= 1;
    return 0;
}

uint64_t dispatch_clock_step(Event *event) { return 0; }
uint64_t dispatch_socket_write(Event *event) { return 0; }
