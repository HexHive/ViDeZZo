#include <stdio.h>
#include <stdint.h>

typedef struct GuestMemoryBlock {
    uint64_t address;
    struct GuestMemoryBlock *next;
} GuestMemoryBlock;

GuestMemoryBlock *guest_memory_blocks = NULL;

static void append_address(uint64_t address) {
    GuestMemoryBlock *gmb = (GuestMemoryBlock *)calloc(sizeof(GuestMemoryBlock), 1);
    gmb->address = address;
    gmb->next = NULL;

    GuestMemoryBlock *tmp = guest_memory_blocks;
    if (tmp == NULL) {
        guest_memory_blocks = gmb;
        return;
    }
    for (; tmp->next != NULL; tmp = tmp->next) { }
    tmp->next = gmb;
}

static void free_memory_blocks() {
    GuestMemoryBlock *tmp = guest_memory_blocks, *last = NULL;

    if (tmp == NULL) return;
    do {
        // MEM
        last = tmp;
        tmp = tmp->next;
        free(last);
    } while (tmp != NULL);
}
