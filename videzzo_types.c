/*
 * Type-Aware Virtual-Device Fuzzing
 *
 * Copyright Qiang Liu <cyruscyliu@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 */

#include "videzzo.h"


uint32_t get_bit(uint32_t data, uint32_t start, uint32_t length) {
    return (data >> start) & (1 << (length + 1) - 1);
}

#define GEN_LINKED_LIST(type, filed_name, head_name, last_name, tail_name) \
    do { \
        type *head_name = get_##type(); \
        type *last_name = head_name, *tail_name = head_name; \
        for (int i = 0; i < (videzzo_randint() % 5 -1); i++) { \
            type *next_##type = get_##type(); \
            last_name->filed_name = next_##type; \
            last_name = next_##type; \
            tail_name = next_##type; \
        } \
    } while(0)

typedef struct {
    uint32_t intr0;
    uint16_t frame;
    uint16_t pad;
    uint32_t done;
} OHCI_HCCA;

typedef struct {
    uint32_t flags;
    uint32_t tail;
    uint32_t head;
    uint32_t next;
} OHCI_ED;

typedef struct {
    uint32_t flags;
    uint32_t cbp;
    uint32_t next;
    uint32_t be;
} OHCI_TD;

typedef struct {
    uint32_t flags;
    uint32_t bp;
    uint32_t next;
    uint32_t be;
    uint16_t offset0;
    uint16_t offset1;
    uint16_t offset2;
    uint16_t offset3;
    uint16_t offset4;
    uint16_t offset5;
    uint16_t offset6;
    uint16_t offset7;
} OHCI_ISO_TD;

static OHCI_HCCA *get_OHCI_HCCA() {
    // generating OHCI_HCCA
    OHCI_HCCA *OHCI_HCCA_vf4c68674f0 = (OHCI_HCCA*)videzzo_calloc(sizeof(OHCI_HCCA), 1);
    OHCI_HCCA_vf4c68674f0->frame = videzzo_randint();
    OHCI_HCCA_vf4c68674f0->pad = videzzo_randint();
    OHCI_HCCA_vf4c68674f0->done = videzzo_randint();
    return OHCI_HCCA_vf4c68674f0;
}

static OHCI_ED *get_OHCI_ED() {
    // generating OHCI_ED
    OHCI_ED *OHCI_ED_vcf2d252ac6 = (OHCI_ED*)videzzo_calloc(sizeof(OHCI_ED), 1);
    OHCI_ED_vcf2d252ac6->flags = ((0 & ((1 << (0x07 + 1)) - 1)) << 0x00)
         | ((videzzo_randint() & ((1 << (0x04 + 1)) - 1)) << 0x07)
         | ((videzzo_randint() & ((1 << (0x02 + 1)) - 1)) << 0x0b)
         | ((videzzo_randint() & ((1 << (0x01 + 1)) - 1)) << 0x0d)
         | ((videzzo_randint() & ((1 << (0x01 + 1)) - 1)) << 0x0e)
         | ((videzzo_randint() & ((1 << (0x01 + 1)) - 1)) << 0x0f)
         | ((videzzo_randint() & ((1 << (0x0b + 1)) - 1)) << 0x10)
         | ((videzzo_randint() & ((1 << (0x05 + 1)) - 1)) << 0x1b);
    return OHCI_ED_vcf2d252ac6;
}

static OHCI_TD *get_OHCI_TD() {
    // generating OHCI_TD
    OHCI_TD *OHCI_TD_v98bd6c706b = (OHCI_TD*)videzzo_calloc(sizeof(OHCI_TD), 1);
    OHCI_TD_v98bd6c706b->flags = ((videzzo_randint() & ((1 << (0x10 + 1)) - 1)) << 0x00)
         | ((videzzo_randint() & ((1 << (0x01 + 1)) - 1)) << 0x10)
         | ((videzzo_randint() & ((1 << (0x02 + 1)) - 1)) << 0x11)
         | ((videzzo_randint() & ((1 << (0x03 + 1)) - 1)) << 0x13)
         | ((videzzo_randint() & ((1 << (0x01 + 1)) - 1)) << 0x16)
         | ((videzzo_randint() & ((1 << (0x01 + 1)) - 1)) << 0x17)
         | ((videzzo_randint() & ((1 << (0x02 + 1)) - 1)) << 0x18)
         | ((videzzo_randint() & ((1 << (0x04 + 1)) - 1)) << 0x1a);
    OHCI_TD_v98bd6c706b->cbp = videzzo_randint();
    OHCI_TD_v98bd6c706b->be = videzzo_randint();
    return OHCI_TD_v98bd6c706b;
}

static OHCI_ISO_TD *get_OHCI_ISO_TD() {
    // generating OHCI_ISO_TD
    OHCI_ISO_TD *OHCI_ISO_TD_v1b6a155a01 = (OHCI_ISO_TD*)videzzo_calloc(sizeof(OHCI_ISO_TD), 1);
    OHCI_ISO_TD_v1b6a155a01->flags = ((videzzo_randint() & ((1 << (0x10 + 1)) - 1)) << 0x00)
         | ((videzzo_randint() & ((1 << (0x01 + 1)) - 1)) << 0x10)
         | ((videzzo_randint() & ((1 << (0x02 + 1)) - 1)) << 0x11)
         | ((videzzo_randint() & ((1 << (0x03 + 1)) - 1)) << 0x13)
         | ((videzzo_randint() & ((1 << (0x01 + 1)) - 1)) << 0x16)
         | ((videzzo_randint() & ((1 << (0x01 + 1)) - 1)) << 0x17)
         | ((videzzo_randint() & ((1 << (0x02 + 1)) - 1)) << 0x18)
         | ((videzzo_randint() & ((1 << (0x04 + 1)) - 1)) << 0x1a);
    OHCI_ISO_TD_v1b6a155a01->bp = videzzo_randint();
    OHCI_ISO_TD_v1b6a155a01->be = videzzo_randint();
    OHCI_ISO_TD_v1b6a155a01->offset0 = videzzo_randint();
    OHCI_ISO_TD_v1b6a155a01->offset1 = videzzo_randint();
    OHCI_ISO_TD_v1b6a155a01->offset2 = videzzo_randint();
    OHCI_ISO_TD_v1b6a155a01->offset3 = videzzo_randint();
    OHCI_ISO_TD_v1b6a155a01->offset4 = videzzo_randint();
    OHCI_ISO_TD_v1b6a155a01->offset5 = videzzo_randint();
    OHCI_ISO_TD_v1b6a155a01->offset6 = videzzo_randint();
    OHCI_ISO_TD_v1b6a155a01->offset7 = videzzo_randint();
    return OHCI_ISO_TD_v1b6a155a01;
}

void videzzo_group_miss_0() {
    OHCI_HCCA *OHCI_HCCA_vdc416d6ffe = get_OHCI_HCCA();
    // gen point_to for OHCI_HCCA_vdc416d6ffe->intr0
    OHCI_ED *OHCI_ED_v8f899166ea = get_OHCI_ED();
    // gen point_to for OHCI_ED_v8f899166ea->head
    switch (get_bit(OHCI_ED_v8f899166ea->flags, 15, 1)) {
        case 0: {
            // gen linked list for OHCI_TD->next
            GEN_LINKED_LIST(OHCI_TD, next, OHCI_TD_ve3be941ad0, last_struct_name_ve58587b9bb, tail_struct_name_v9a660cacb3)
            OHCI_ED_v8f899166ea->head = OHCI_TD_ve3be941ad0;
            OHCI_ED_v8f899166ea->tail = tail_struct_name_v9a660cacb3;
            break; }
        case 1: {
            // gen linked list for OHCI_ISO_TD->next
            GEN_LINKED_LIST(OHCI_ISO_TD, next, OHCI_ISO_TD_v2578229349, last_struct_name_va84a98496a, tail_struct_name_va714803bc3)
            OHCI_ED_v8f899166ea->head = OHCI_ISO_TD_v2578229349;
            OHCI_ED_v8f899166ea->tail = tail_struct_name_va714803bc3;
            break; }
    }
    // gen point_to for OHCI_ED_v8f899166ea->next
    // gen linked list for OHCI_ED->next
    GEN_LINKED_LIST(OHCI_ED, next, OHCI_ED_v6a28264b44, last_struct_name_v873774a2b6, tail_struct_name_v4c5ab35cf3)
    OHCI_ED_v8f899166ea->next = OHCI_ED_v6a28264b44;
    OHCI_HCCA_vdc416d6ffe->intr0 = OHCI_ED_v8f899166ea;
}
