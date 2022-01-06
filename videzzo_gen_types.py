import sys
import importlib
from videzzo_types_lib import Model

def gen_types(hypervisor):
    """
    file orgranization
        1. generate a header for each callback
        2. videzzo_types.c includes these headers
        3. generate some commonly used code in videzzo_types.c
    """
    code ="""/*
 * Type-Aware Virtual-Device Fuzzing
 *
 * Copyright Qiang Liu <cyruscyliu@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 */

#include "videzzo.h"
{}

void group_mutator_handler_prologue(
        Input *current_input, uint32_t *current_event) {{
    // basically, we have to duplicate the current event
    // in order to reissue it when GroupMutatorMiss returns
    Event *orig = get_event(current_input, *current_event);
    Event *copy= (Event *)calloc(sizeof(Event), 1);
    event_ops[copy->type].deep_copy(orig, copy);
    insert_event(current_input, copy, *current_event++ + 1);
}}

FeedbackHandler group_mutator_handlers[0xff];
"""
    hypervisor_dir = 'videzzo_{}'.format(hypervisor)
    module_name = '{}.videzzo_gen_types'.format(hypervisor_dir)
    module = importlib.import_module(module_name)

    headers = []
    for k, v in module.__dict__.items():
        if isinstance(v, Model):
            print('Handling {} ...'.format(k), end='')
            filepath = '{}/{}.h'.format(hypervisor_dir, k)
            with open(filepath, 'w') as f:
                f.write(v.get_code())
            headers.append(filepath)
            print('\tin {}'.format(filepath))

    with open('videzzo_types.c', 'w') as f:
        f.write(code.format('\n'.join(['#include "{}"'.format(header) for header in headers])))

def usage(argv):
    print('usage: python3 {} [{{qemu, virtualbox, bhyve}}|-h]'.format(argv[0]))
    exit(1)

def main(argv):
    if len(argv) == 1:
        # default vmm: do nothing
        code ="""/*
 * Type-Aware Virtual-Device Fuzzing
 *
 * Copyright Qiang Liu <cyruscyliu@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 */

#include "videzzo.h"

FeedbackHandler group_mutator_handlers[0xff];
"""
        with open('videzzo_types.c', 'w') as f:
            f.write(code)
    elif len(argv) == 2:
        if argv[1] == '-h':
            usage(argv)
        hypervisor = argv[1]
        gen_types(hypervisor)
    else:
        usage(argv)
    print('Please check videzzo_types.c in the root directory of the current project.')

if __name__ == '__main__':
    main(sys.argv)
