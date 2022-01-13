import sys
import importlib
import argparse
from videzzo_types_lib import Model, FIELD_RANDOM, FIELD_POINTER, FIELD_FLAG, FIELD_CONSTANT

def __gen_code(models, hypervisor_dir):
    code ="""/*
 * Type-Aware Virtual-Device Fuzzing
 *
 * Copyright Qiang Liu <cyruscyliu@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 */

#include "videzzo.h"

static uint64_t get_bit(uint64_t data, uint32_t start, uint32_t length) {{
    return (data >> start) & ((1 << (length + 1)) - 1);
}}

// very interesting and useful function
static void fill(uint8_t *dst, size_t dst_size, uint64_t filler, size_t filler_size) {{
    uint8_t *filler_p = (uint8_t *)&filler;
    for (int i = 0; i < dst_size; i++)
        dst[i] = filler_p[i % filler_size];
}}

static void refill(uint64_t *dst, size_t dst_size, uint8_t* filler_p, size_t filler_size) {{
    memcpy((uint8_t *)dst, filler_p, dst_size);
}}

static uint64_t EVENT_MEMALLOC(size_t size) {{
    Event *event = event_ops[EVENT_TYPE_MEM_ALLOC].construct(EVENT_TYPE_MEM_ALLOC,
         INTERFACE_MEM_ALLOC, 0, 0, size, NULL);
#ifdef VIDEZZO_DEBUG
    event_ops[event->type].print_event(event);
#endif
    uint64_t phyaddr = event_ops[EVENT_TYPE_MEM_ALLOC].dispatch(event);
    event_ops[event->type].release(event);
    free(event);
    return phyaddr;
}}

static void EVENT_MEMFREE(uint64_t physaddr) {{
    Event *event = event_ops[EVENT_TYPE_MEM_FREE].construct(EVENT_TYPE_MEM_FREE,
         INTERFACE_MEM_FREE, 0, 0, physaddr, NULL);
#ifdef VIDEZZO_DEBUG
    event_ops[event->type].print_event(event);
#endif
    event_ops[EVENT_TYPE_MEM_FREE].dispatch(event);
    event_ops[event->type].release(event);
    free(event);
}}

static void __EVENT_MEMREAD(uint64_t physaddr, size_t size, uint8_t *data) {{
    Event *event = event_ops[EVENT_TYPE_MEM_READ].construct(EVENT_TYPE_MEM_READ,
        INTERFACE_MEM_READ, physaddr, size, 0, data);
#ifdef VIDEZZO_DEBUG
    event_ops[event->type].print_event(event);
#endif
    event_ops[EVENT_TYPE_MEM_READ].dispatch(event);

    int current_event = gfctx_get_current_event();
    insert_event(gfctx_get_current_input(), event, current_event);
    current_event++;
    gfctx_set_current_event(current_event);
}}

static void __EVENT_MEMWRITE(uint64_t physaddr, size_t size, uint8_t *data) {{
    Event *event = event_ops[EVENT_TYPE_MEM_WRITE].construct(EVENT_TYPE_MEM_WRITE,
        INTERFACE_MEM_WRITE, physaddr, size, 0, data);
#ifdef VIDEZZO_DEBUG
    event_ops[event->type].print_event(event);
#endif
    event_ops[EVENT_TYPE_MEM_WRITE].dispatch(event);

    int current_event = gfctx_get_current_event();
    insert_event(gfctx_get_current_input(), event, current_event);
    current_event++;
    gfctx_set_current_event(current_event);
}}

typedef struct GuestMemoryBlock {{
    uint64_t address;
    struct GuestMemoryBlock *next;
}} GuestMemoryBlock;

GuestMemoryBlock *guest_memory_blocks = NULL;

static void append_address(uint64_t address) {{
    GuestMemoryBlock *gmb = (GuestMemoryBlock *)calloc(sizeof(GuestMemoryBlock), 1);
    gmb->address = address;
    gmb->next = NULL;

    GuestMemoryBlock *tmp = guest_memory_blocks;
    if (tmp == NULL) {{
        guest_memory_blocks = gmb;
        return;
    }}
    for (; tmp->next != NULL; tmp = tmp->next) {{  }}
    tmp->next = gmb;
}}

static void free_memory_blocks() {{
    GuestMemoryBlock *tmp = guest_memory_blocks, *last = NULL;

    if (tmp == NULL) return;
    do {{
        EVENT_MEMFREE(tmp->address);
        last = tmp;
        tmp = tmp->next;
        free(last);
        last = NULL;
    }} while (tmp != NULL);
    guest_memory_blocks = NULL;
}}

{}
"""

    headers = []
    for model_name, model in models.items():
        print('Handling {} ...'.format(model_name), end='')
        filepath = '{}/{}.h'.format(hypervisor_dir, model_name)
        with open(filepath, 'w') as f:
            f.write(model.get_code())
        headers.append(filepath)
        print('\tin {}'.format(filepath))

    with open('videzzo_types.c', 'w') as f:
        f.write(code.format('\n'.join(['#include "{}"'.format(header) for header in headers])))
        f.write('\n')
        f.write('FeedbackHandler group_mutator_miss_handlers[0xff] = {\n')
        for model in models.values():
            f.write('    [{0}] = videzzo_group_mutator_miss_handler_{0},\n'.format(model.index))
        f.write('};')

def gen_types(hypervisor, summary=True):
    """
    file orgranization
        1. generate a header for each callback
        2. videzzo_types.c includes these headers
        3. define some commonly used code in videzzo_types.c
    """
    hypervisor_dir = 'videzzo_{}'.format(hypervisor)
    module_name = '{}.videzzo_types_gen'.format(hypervisor_dir)
    module = importlib.import_module(module_name)

    models = {}
    for k, v in module.__dict__.items():
        if isinstance(v, Model):
            models[k] = v
    if summary:
        for model in models.values():
            model.get_stats()
        return
    __gen_code(models, hypervisor_dir)

def gen_vmm(summary=False):
    vmm_01 = Model('vmm', 1)
    t = {}
    for i in range(0, 1):
        t['intr{}#0x4'.format(i)] = FIELD_POINTER
    t.update({'frame#0x2': FIELD_RANDOM, 'pad#0x2': FIELD_RANDOM, 'done#0x4': FIELD_RANDOM})
    vmm_01.add_struct('VMM_HCCA', t)
    vmm_01.add_struct('VMM_ED', {
        'flags#0x4': FIELD_FLAG, 'tail#0x4': FIELD_POINTER , 'head#0x4': FIELD_POINTER, 'next#0x4': FIELD_POINTER})
    vmm_01.add_flag('VMM_ED.flags', {0: '7@0x0', 7: 4, 11: 2, 13: 1, 14: 1, 15: 1, 16: 11, 27: 5})
    for i in range(0, 1):
        vmm_01.add_context_flag_to_point_to(None, 'VMM_HCCA.intr{}'.format(i), ['VMM_ED'])
    vmm_01.add_context_flag_to_single_linked_list(None, 'VMM_ED.next', ['VMM_ED'], ['next'])
    vmm_01.add_context_flag_to_single_linked_list(
        ['VMM_ED.flags.15'], 'VMM_ED.head', ['VMM_TD', 'VMM_ISO_TD'], ['next', 'next'], tail='VMM_ED.tail')
    vmm_01.add_struct('VMM_TD', {
        'flags#0x4': FIELD_FLAG, 'cbp#0x4': FIELD_RANDOM, 'next#0x4': FIELD_POINTER, 'be#0x4': FIELD_RANDOM})
    vmm_01.add_flag('VMM_TD.flags', {0: 16, 18: 1, 19: 2, 21: 3, 24: 1, 25: 1, 26: 2, 28: 4})
    vmm_01.add_context_flag_to_single_linked_list(None, 'VMM_TD.next', ['VMM_TD'], ['next'])
    vmm_01.add_struct('VMM_ISO_TD', {
        'flags#0x4': FIELD_FLAG, 'bp#0x4': FIELD_RANDOM, 'next#0x4': FIELD_POINTER, 'be#0x4': FIELD_RANDOM,
        'offset0#0x2': FIELD_RANDOM, 'offset1#0x2': FIELD_RANDOM, 'offset2#0x2': FIELD_RANDOM, 'offset3#0x2': FIELD_RANDOM,
        'offset4#0x2': FIELD_RANDOM, 'offset5#0x2': FIELD_RANDOM, 'offset6#0x2': FIELD_RANDOM, 'offset7#0x2': FIELD_RANDOM})
    vmm_01.add_flag('VMM_ISO_TD.flags', {0: 16, 18: 1, 19: 2, 21: 3, 24: 1, 25: 1, 26: 2, 28: 4})
    vmm_01.add_context_flag_to_single_linked_list(None, 'VMM_ISO_TD.next', ['VMM_ISO_TD'], ['next'])
    vmm_01.add_head(['VMM_HCCA'], ['ohci_frame_boundary', 'ohci_read_hcca'])
    vmm_02 = Model('vmm', 2)
    vmm_02.add_struct('TEMP_BUF', {'temp#0x1000': FIELD_RANDOM})
    vmm_02.add_head(['TEMP_BUF'], ['vmm_transfer_audio', 'pci_dma_read'])

    models = {'videzzo_vmm-01': vmm_01, 'videzzo_vmm-02': vmm_02}
    if summary:
        for model in models.values():
            model.get_stats()
        return
    __gen_code(models, '.')

def main(argv):
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-s', '--summary', action='store_true', default=False, help='Print summary rather than build')
    parser.add_argument('vmm', help='Hypervisors', choices=['vmm', 'qemu', 'byhve', 'virtualbox'])
    args = parser.parse_args()

    if args.summary:
        print('name, id, #-of-structs, #-of-flag-fields, #-of-pointer-fields, #-of-fields')
    if args.vmm == 'vmm':
        gen_vmm(summary=args.summary)
    else:
        gen_types(args.vmm, summary=args.summary)

    if not args.summary:
        print('Please check videzzo_types.c in the root directory of the current project.')

if __name__ == '__main__':
    main(sys.argv)
