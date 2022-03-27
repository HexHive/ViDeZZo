import sys
import yaml
import argparse
import importlib
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

#define RAND() (rand() & 0x7fff) /* ensure only 15-bit */
uint32_t urand32() {{
    return (uint32_t)(((uint32_t)RAND() << 30) ^ ((uint32_t)RAND() << 15) ^ (uint32_t)RAND());
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
    instrumentation_points = []
    for k, v in module.__dict__.items():
        if isinstance(v, Model):
            models[k] = v
            instrumentation_points.extend(v.get_instrumentation_points())
    yaml.safe_dump(instrumentation_points, open('./{0}/videzzo_{1}_types.yaml'.format(hypervisor_dir, hypervisor), 'w'))
    if summary:
        for model in models.values():
            model.get_stats()
        return
    __gen_code(models, hypervisor_dir)

def gen_vmm(summary=False):
    vmm_00 = Model('vmm', 0)
    vmm_00.add_struct('VMM_BD', {'addr0#0x4': FIELD_POINTER | FIELD_FLAG, 'addr1#0x4': FIELD_POINTER, 'ctl_len#0x4': FIELD_FLAG})
    vmm_00.add_flag('VMM_BD.addr0', {1: 1})
    vmm_00.add_flag('VMM_BD.ctl_len', {0: 16, 16: 14, 30: 1, 31: 1})
    vmm_00.add_struct('VMM_BUF0', {'buf#0x1000': FIELD_RANDOM, 'constant#0x4': FIELD_CONSTANT})
    vmm_00.add_constant('VMM_BUF0.constant', [0xdeadbeef])
    vmm_00.add_struct('VMM_BUF1', {'buf#0x1000': FIELD_RANDOM})
    vmm_00.add_struct('VMM_BUF2', {'next#0x4': FIELD_POINTER})
    vmm_00.add_point_to('VMM_BUF2.next', ['VMM_BUF2'])
    vmm_00.add_point_to('VMM_BD.addr0', ['VMM_BUF0', 'VMM_BUF1'], flags=['VMM_BD.ctl_len.31'], alignment=2)
    vmm_00.add_point_to_single_linked_list('VMM_BD.addr1', None, ['VMM_BUF2'], ['next'], alignment=2)
    vmm_00.add_head(['VMM_BD'])
    vmm_00.add_instrumentation_point('videzzo_vmm.c', ['generic_pio_write', 'dma_memory_read', 0, 0])
    vmm_00.add_instrumentation_point('videzzo_vmm.c', ['generic_mmio_write', 'dma_memory_read', 0, 0])

    instrumentation_points = vmm_00.get_instrumentation_points()
    yaml.safe_dump(instrumentation_points, open('./videzzo_vmm_types.yaml', 'w'))

    models = {'videzzo_vmm-00': vmm_00}
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
