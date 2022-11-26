import sys
import yaml
import argparse
import importlib
from videzzo_types_lib import Model, FIELD_RANDOM, FIELD_POINTER, FIELD_FLAG, FIELD_CONSTANT

def __gen_code(models, hypervisor_dir):
    code ="""/*
 * Dependency-Aware Virtual-Device Fuzzing
 *
 * Copyright Qiang Liu <cyruscyliu@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 */

#include "videzzo.h"

static uint64_t get_bit(uint64_t data, uint32_t start, uint32_t length) {{
    return (data >> start) & ((1 << (length)) - 1);
}}

// very interesting and useful function
static void fill(uint8_t *dst, size_t dst_size, uint64_t filler, size_t filler_size) {{
    uint8_t *filler_p = (uint8_t *)&filler;

    if (dst_size <= 2 * filler_size) {{
        for (int i = 0; i < dst_size; i++)
            dst[i] = filler_p[i % filler_size];
    }} else {{
        // we can do the copy in batches (>=2)
        int segments = dst_size / filler_size;
        int first = 0;
        int segment_size = (segments / 2) * filler_size;
        fill(dst + first, segment_size, filler, filler_size);
        memcpy(dst + segment_size, dst + first, segment_size);
        int third = 2 * segment_size;
        int third_size = dst_size - third;
        fill(dst + third, third_size, filler, filler_size);
    }}
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

    int current_event = gfctx_get_current_event(1);
    append_event(gfctx_get_current_input(1), event);
    current_event++;
    gfctx_set_current_event(current_event, 1);
}}

static void __EVENT_MEMWRITE(uint64_t physaddr, size_t size, uint8_t *data) {{
    Event *event = event_ops[EVENT_TYPE_MEM_WRITE].construct(EVENT_TYPE_MEM_WRITE,
        INTERFACE_MEM_WRITE, physaddr, size, 0, data);
#ifdef VIDEZZO_DEBUG
    event_ops[event->type].print_event(event);
#endif
    event_ops[EVENT_TYPE_MEM_WRITE].dispatch(event);

    int current_event = gfctx_get_current_event(1);
    append_event(gfctx_get_current_input(1), event);
    current_event++;
    gfctx_set_current_event(current_event, 1);
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
    if (guest_memory_blocks == NULL) {{
        guest_memory_blocks = gmb;
    }} else {{
        gmb->next = guest_memory_blocks;
        guest_memory_blocks = gmb;
    }}
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

void __free_memory_blocks() {{
    GuestMemoryBlock *tmp = guest_memory_blocks, *last = NULL;
    Event *event;

    if (tmp == NULL) return;
    do {{
        // construct
        event = event_ops[EVENT_TYPE_MEM_FREE].construct(EVENT_TYPE_MEM_FREE,
            INTERFACE_MEM_FREE, 0, 0, tmp->address, NULL);
        // dispatch
        event_ops[EVENT_TYPE_MEM_FREE].dispatch(event);
        // free
        event_ops[EVENT_TYPE_MEM_FREE].release(event);
        free(event);

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
        if model.get_head() is None:
            continue
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
            if model.get_head() is None:
                continue
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
    if summary:
        print(' & '.join(['Device', 'Struct', '# of Flags', '# of Pointers', "# of Fields"]))
        for model in models.values():
            for name, struct_type, n_flags, n_pointers, n_fields in model.get_stats():
                print(' & '.join([
                    name.upper().replace('_', '\_'),
                    struct_type.replace('_', '\_'), str(n_flags), '', str(n_pointers), '', str(n_fields), '\\\\']))
        return
    yaml.safe_dump(instrumentation_points, open('./{0}/videzzo_{1}_types.yaml'.format(hypervisor_dir, hypervisor), 'w'))
    __gen_code(models, hypervisor_dir)

def main(argv):
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-s', '--summary', action='store_true', default=False, help='Print summary rather than build')
    parser.add_argument('vmm', help='Hypervisors', choices=['qemu', 'vbox'])
    args = parser.parse_args()

    gen_types(args.vmm, summary=args.summary)

    if not args.summary:
        print('Please check videzzo_types.c in the root directory of the current project.')

if __name__ == '__main__':
    main(sys.argv)
