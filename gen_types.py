import os
import random
import json

FIELD_RANDOM  = 0
FIELD_POINTER = 1
FIELD_FLAG    = 2
FIELD_CONSTANT= 3

class Model(object):
    def __init__(self, name):
        self.name = name
        self.structs = {}
        self.head_struct_types = None
        self.instrumentation = None

        # some internal controls
        self.last_uuid = None
        self.code = []
        self.indent = 0
        self.callocations = []

    def get_uuid(self):
        self.last_uuid = '{:010x}'.format(random.randint(0, 0xFFFFFFFFFFFFFFFF))[:10]
        return 'v' + self.last_uuid

    def get_last_uuid(self):
        return 'v' + self.last_uuid
###########################################################################################

    def add_struct(self, struct_type, metadata):
        """
        struct_type: struct_type
        metadata: {'field_name#size': filed_type}

        ViDeZZo struct format:
            self.structs[struct_type] = {
                field_name: {'field_size': field_size, 'field_type': field_type}
            }
        """
        if struct_type not in self.structs:
            self.structs[struct_type] = {}
        for k, field_type in metadata.items():
            field_name, field_size = k.split('#')
            field_size = str(int(field_size, 16))
            self.structs[struct_type][field_name] = {'field_size': field_size, 'field_type': field_type}

    def get_struct(self, struct_type):
        return self.structs[struct_type]

    def check_field(self, struct_type, field_name):
        if struct_type not in self.structs:
            raise KeyError('{} is not a valid struct'.format(struct_type))
        if field_name not in self.structs[struct_type]:
            raise KeyError('{} is not a valid field'.format(field_name))

    def add_head(self, head_struct_types, instrumentation):
        self.head_struct_types = head_struct_types
        self.instrumentation = instrumentation

    def add_flag(self, key, value):
        """
        key: struct_type.field_name
        value: {'length[@initvalue]'}

        ViDeZZo flag format:
            self.structs[struct_type][field_name]['flags'] = {
                'start': {'length': length, 'value': initvalue}
            }
        """
        struct_type, field_name = key.split('.')
        self.check_field(struct_type, field_name)
        flags = {}
        for k, v in value.items():
            start = str(k)
            if isinstance(v, str):
                length, initvalue = v.split('@')
                initvalue = int(initvalue, 16)
                length = int(length)
            else:
                initvalue = None
                length = v
            flags[start] = {'length': length, 'initvalue': initvalue}
        self.structs[struct_type][field_name]['flags'] = flags

    def get_flag_length(self, struct_type, field_name, bit):
        return self.structs[struct_type][field_name]['flags'][bit]['length']

    def add_context_tail_pointer(self, pointer):
        """
        key: struct_type.field_name

        ViDeZZo point_to format:
            self.structs[struct][field_name]['point_to'] = {'tail': True}
        """
        struct_type, field_name = pointer.split('.')
        self.check_field(struct_type, field_name)
        self.structs[struct_type][field_name]['point_to'] = {'tail': True}

    def add_context_flag_to_point_to(self, flags, pointer, types):
        """
        flags: [struct_type.field_name.bitwise] n
        pointer: struct_type.field_name 1
        types: [type0] 2^n

        ViDeZZo point_to format:
            self.structs[struct_type][field_name]['point_to'] = {
                'flags': [{'struct_type': struct_type, 'field_name': field_name, 'bit': bit, 'length': length}] or None,
                'types': {'0': point_to_struct_type}
            }
        """
        struct_type, field_name = pointer.split('.')
        self.check_field(struct_type, field_name)
        if flags is None:
            assert len(types) == 1
            self.structs[struct_type][field_name]['point_to'] = {'flags': None, 'types': {'0': types[0]}}
        else:
            metadata = {'flags': [], 'types': {}}
            for flag in flags:
                flag_struct_type, flag_field_name, flag_bit = flag.split('.')
                self.check_field(flag_struct_type, flag_field_name)
                metadata['flags'].append({
                    'struct_type': flag_struct_type, 'field_name': flag_field_name,
                    'bit': flag_bit, 'length': self.get_flag_length(flag_struct_type, flag_field_name, flag_bit)})
            for idx, point_to_struct_type in enumerate(types):
                metadata['types'][str(idx)] = point_to_struct_type
            self.structs[struct_type][field_name]['point_to'] = metadata
        return struct_type, field_name

    def add_context_flag_to_single_linked_list(self, flags, pointer, types, links, tail=None):
        """
        flags: [struct_type.field_name.bitwise] n
        pointer: struct_type.field_name 1
        types: [type0] 2^n
        tail: struct_type.field_name 1
        links: [link] 2^n

        ViDeZZo point_to format:
            self.structs[struct][field_name]['point_to'] = {
                'flags': [{'struct_type': struct_type, 'field_name': field_name, 'bit': bit, 'length': length}] or None,
                'types': {'0': point_to_struct_type},
                'tail': {'struct_type': struct_type, 'filed_name': field_name},
                'links': {'0': link},
                'linked_list': False
            }
        """
        struct_type, field_name = self.add_context_flag_to_point_to(flags, pointer, types)
        self.structs[struct_type][field_name]['point_to']['linked_list'] = True
        if tail is not None:
            tail_struct_type, tail_field_name = tail.split('.')
            self.check_field(tail_struct_type, tail_field_name)
            self.structs[struct_type][field_name]['point_to']['tail'] = {
                'struct_type': tail_struct_type, 'field_name': tail_field_name}
            self.structs[tail_struct_type][tail_field_name]['point_to'] = {'tail': True}
        if links is not None:
            metadata = self.structs[struct_type][field_name]['point_to']
            metadata['links'] = {}
            for idx, _ in metadata['types'].items():
                self.structs[struct_type][field_name]['point_to']['links'][idx] = links[int(idx)]
###########################################################################################

    def gen_flag(self, struct_name, field_name, metadata):
        flags = []
        length_in_total = 0
        for start, length_and_initvalue in metadata.items():
            length = length_and_initvalue['length']
            initvalue = length_and_initvalue['initvalue']
            if initvalue is None:
                initvalue = 'videzzo_randint()'
            flags.append(('(({0} & ((1 << (0x{1:02x} + 1)) - 1)) << 0x{2:02x})'.format(initvalue, length, length_in_total)))
            length_in_total += int(length)
        sep = '\n    {} | '.format(' ' * self.indent * 4)
        self.append_code('{}->{} = {};'.format(struct_name, field_name, sep.join(flags)))

    def gen_random(self, struct_name, field_name, metadata):
        self.append_code('{}->{} = {};'.format(struct_name, field_name, 'videzzo_randint()'))

    def gen_linked_list(self, struct, field_name):
        self.append_code('// gen linked list for {}->{}'.format(struct, field_name))
        head_struct_name = '{}_{}'.format(struct, self.get_uuid())
        last_struct_name = 'last_struct_name_{}'.format(self.get_uuid())
        tail_struct_name = 'tail_struct_name_{}'.format(self.get_uuid())
        self.append_code('GEN_LINKED_LIST({}, {}, {}, {}, {})'.format(
            struct, field_name, head_struct_name, last_struct_name, tail_struct_name))
        return head_struct_name, tail_struct_name

    def gen_point_to(self, struct_name, field_name, metadata):
        if 'tail' in metadata and metadata['tail'] is True:
            return

        self.append_code('// gen point_to for {}->{}'.format(struct_name, field_name))
        flags = metadata['flags']
        types = metadata['types']

        def gen_conditional_point_to(__gen_func):
            cond = ' | '.join(['get_bit({}->{}, {}, {})'.format(
                struct_name, flag['field_name'], flag['bit'], flag['length']) for flag in flags])
            self.append_code('switch ({}) {{'.format(cond))
            self.indent += 1
            for case, struct_type in types.items():
                self.append_code('case {}: {{'.format(case))
                self.indent += 1
                __gen_func(struct_type, links[case])
                self.append_code('break; }')
                self.indent -= 1
            self.indent -= 1
            self.append_code('}')

        def gen_linked_list(__struct_type, __field_name):
            head_struct_name, tail_struct_name = self.gen_linked_list(__struct_type, __field_name)
            self.append_code('{}->{} = {};'.format(struct_name, field_name, head_struct_name))
            if 'tail' in metadata and isinstance(metadata['tail'], dict):
                self.append_code('{}->{} = {};'.format(struct_name, metadata['tail']['field_name'], tail_struct_name))

        def gen_point_to(__struct_type, reserved):
            sub_struct_name = self.gen_struct_point_to(__struct_type)
            self.append_code('{}->{} = {};'.format(struct_name, field_name, sub_struct_name))

        if 'linked_list' in metadata and metadata['linked_list'] is True:
            links = metadata['links']
            if flags is None:
                gen_linked_list(types['0'], links['0'])
            else:
                gen_conditional_point_to(gen_linked_list)
        else:
            if flags is None:
                gen_point_to(types['0'], None)
            else:
                gen_conditional_point_to(gen_point_to)

    def gen_struct_point_to(self, struct_type):
        """
        {struct_name}->{non_pointer_field_name} = {corresponding_value};
        """
        struct_name = '{}_{}'.format(struct_type, self.get_uuid())
        self.append_code('{} *{} = get_{}();'.format(struct_type, struct_name, struct_type))
        self.callocations.append(struct_name)
        for field_name, metadata in self.get_struct(struct_type).items():
            field_type = metadata['field_type']
            if field_type == FIELD_POINTER:
                self.gen_point_to(struct_name, field_name, metadata['point_to'])
        return struct_name

    def free_struct(self):
        pass
###########################################################################################

    def gen_license(self):
        license = """/*
 * Type-Aware Virtual-Device Fuzzing
 *
 * Copyright Qiang Liu <cyruscyliu@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 */
"""
        self.append_code(license)

    def gen_headers(self):
        self.append_code('#include "videzzo.h"\n')

    def gen_helpers(self):
        helpers = """
uint32_t get_bit(uint32_t data, uint32_t start, uint32_t length) {
    return (data >> start) & (1 << (length + 1) - 1);
}

#define GEN_LINKED_LIST(type, filed_name, head_name, last_name, tail_name) \\
    do { \\
        type *head_name = get_##type(); \\
        type *last_name = head_name, *tail_name = head_name; \\
        for (int i = 0; i < (videzzo_randint() % 5 -1); i++) { \\
            type *next_##type = get_##type(); \\
            last_name->filed_name = next_##type; \\
            last_name = next_##type; \\
            tail_name = next_##type; \\
        } \\
    } while(0)
"""
        self.append_code(helpers)

    def gen_struct_definition(self):
        for struct_type, fields in self.structs.items():
            self.append_code('typedef struct {')
            for field, metadata in fields.items():
                field_size = metadata['field_size']
                if field_size == '1':
                    self.append_code('    uint8_t {};'.format(field))
                elif field_size == '2':
                    self.append_code('    uint16_t {};'.format(field))
                elif field_size == '4':
                    self.append_code('    uint32_t {};'.format(field))
                elif field_size == '8':
                    self.append_code('    uint64_t {};'.format(field))
                else:
                    raise ValueError('unsupported size: '.format(size))
            self.append_code('}} {};\n'.format(struct_type))

    def gen_struct(self, struct_type):
        """
        {struct} * get_{struct}();
        """
        self.append_code('// generating {}'.format(struct_type))
        struct_name = '{}_{}'.format(struct_type, self.get_uuid())
        self.append_code('{1} *{0} = ({1}*)videzzo_calloc(sizeof({1}), 1);'.format(struct_name, struct_type))
        for field_name, metadata in self.get_struct(struct_type).items():
            field_type = metadata['field_type']
            if field_type == FIELD_FLAG:
                self.gen_flag(struct_name, field_name, metadata['flags'])
            elif field_type == FIELD_RANDOM:
                self.gen_random(struct_name, field_name, metadata)
            elif field_type == FIELD_CONSTANT:
                self.gen_constant(struct_name, field_name, metdata)
            elif field_type == FIELD_POINTER:
                pass
            else:
                raise ValueError('unsupported FIELD_TYPE: {}'.format(field_type))
        return struct_name

    def gen_struct_initialization_without_pointers(self):
        for struct_type, fields in self.structs.items():
            self.append_code('static {} *get_{}() {{'.format(struct_type, struct_type))
            self.indent += 1
            struct_name = self.gen_struct(struct_type)
            self.append_code('return {};'.format(struct_name))
            self.indent -= 1
            self.append_code('}\n')
###########################################################################################

    def append_code(self, code):
        self.code.append(' ' * self.indent * 4 + code)

    def get_code(self):
        self.gen_license()
        self.gen_headers();
        self.gen_helpers();
        self.gen_struct_definition()
        self.gen_struct_initialization_without_pointers()

        uuid = self.get_uuid()
        for index, head_struct_type in enumerate(self.head_struct_types):
            self.append_code('void videzzo_group_miss_{}() {{'.format(index))
            self.indent += 1
            struct_name = self.gen_struct_point_to(head_struct_type)
            ### add more code here ###
            # self.free_structs()
            self.indent -= 1
            self.append_code('}')
        return '\n'.join(self.code)

ohci_01 = Model('ohci-01')
t = {}
for i in range(0, 1):
    t['intr{}#0x4'.format(i)] = FIELD_POINTER
t.update({'frame#0x2': FIELD_RANDOM, 'pad#0x2': FIELD_RANDOM, 'done#0x4': FIELD_RANDOM})
ohci_01.add_struct('OHCI_HCCA', t)
ohci_01.add_struct('OHCI_ED', {
    'flags#0x4': FIELD_FLAG, 'tail#0x4': FIELD_POINTER , 'head#0x4': FIELD_POINTER, 'next#0x4': FIELD_POINTER})
ohci_01.add_flag('OHCI_ED.flags', {0: '7@0x0', 7: 4, 11: 2, 13: 1, 14: 1, 15: 1, 16: 11, 27: 5})
for i in range(0, 1):
    ohci_01.add_context_flag_to_point_to(None, 'OHCI_HCCA.intr{}'.format(i), ['OHCI_ED'])
ohci_01.add_context_flag_to_single_linked_list(None, 'OHCI_ED.next', ['OHCI_ED'], ['next'])
ohci_01.add_context_flag_to_single_linked_list(
    ['OHCI_ED.flags.15'], 'OHCI_ED.head', ['OHCI_TD', 'OHCI_ISO_TD'], ['next', 'next'], tail='OHCI_ED.tail')
ohci_01.add_struct('OHCI_TD', {
    'flags#0x4': FIELD_FLAG, 'cbp#0x4': FIELD_RANDOM, 'next#0x4': FIELD_POINTER, 'be#0x4': FIELD_RANDOM})
ohci_01.add_flag('OHCI_TD.flags', {0: 16, 18: 1, 19: 2, 21: 3, 24: 1, 25: 1, 26: 2, 28: 4})
ohci_01.add_context_flag_to_single_linked_list(None, 'OHCI_TD.next', ['OHCI_TD'], ['next'])
ohci_01.add_struct('OHCI_ISO_TD', {
    'flags#0x4': FIELD_FLAG, 'bp#0x4': FIELD_RANDOM, 'next#0x4': FIELD_POINTER, 'be#0x4': FIELD_RANDOM,
    'offset0#0x2': FIELD_RANDOM, 'offset1#0x2': FIELD_RANDOM, 'offset2#0x2': FIELD_RANDOM, 'offset3#0x2': FIELD_RANDOM,
    'offset4#0x2': FIELD_RANDOM, 'offset5#0x2': FIELD_RANDOM, 'offset6#0x2': FIELD_RANDOM, 'offset7#0x2': FIELD_RANDOM})
ohci_01.add_flag('OHCI_ISO_TD.flags', {0: 16, 18: 1, 19: 2, 21: 3, 24: 1, 25: 1, 26: 2, 28: 4})
ohci_01.add_context_flag_to_single_linked_list(None, 'OHCI_ISO_TD.next', ['OHCI_ISO_TD'], ['next'])
ohci_01.add_head(['OHCI_HCCA'], ['ohci_frame_boundary', 'ohci_read_hcca'])
print(ohci_01.get_code())
