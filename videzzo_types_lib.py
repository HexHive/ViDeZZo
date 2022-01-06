import random

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

    def recover_struct_type_from_name(self, struct_name):
        return '_'.join(struct_name.split('_')[:-1])

    def construct_struct_name_from_type(self, struct_type):
        return '{}_{}'.format(struct_type, self.get_uuid())
###########################################################################################

    def add_struct(self, struct_type, metadata):
        """
        struct_type: struct_type
        metadata: {'field_name#size': field_type}

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
                'tail': {'struct_type': struct_type, 'field_name': field_name},
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

    def __gen_event_memwrite(self, struct_name, field_name, value, value_size):
        struct_type = self.recover_struct_type_from_name(struct_name)
        field_size = self.structs[struct_type][field_name]['field_size']
        self.append_code('EVENT_MEMWRITE({} + offsetof({}, {}), {}, {}, {}, {});'.format(
            struct_name, struct_type, field_name, field_size, value, value_size, self.get_uuid()))

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
        # MAGIC
        # self.append_code('{}->{} = {};'.format(struct_name, field_name, sep.join(flags)))
        self.__gen_event_memwrite(struct_name, field_name, sep.join(flags), 4)

    def gen_random(self, struct_name, field_name, metadata):
        # MAGIC
        # self.append_code('{}->{} = {};'.format(struct_name, field_name, 'videzzo_randint()'))
        self.__gen_event_memwrite(struct_name, field_name, 'videzzo_randint()', 4)

    def gen_linked_list(self, struct_type, field_name):
        self.append_code('// gen linked list for {}->{}'.format(struct_type, field_name))
        head_struct_name = self.construct_struct_name_from_type(struct_type)
        last_struct_name = 'last_struct_name_{}'.format(self.get_uuid())
        tail_struct_name = 'tail_struct_name_{}'.format(self.get_uuid())
        self.append_code('GEN_LINKED_LIST({}, {}, {}, {}, {}, {})'.format(
            struct_type, field_name, head_struct_name, last_struct_name, tail_struct_name, self.get_uuid()))
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
            # MAGIC
            # self.append_code('{}->{} = {};'.format(struct_name, field_name, head_struct_name))
            self.__gen_event_memwrite(struct_name, field_name, head_struct_name, 4);
            if 'tail' in metadata and isinstance(metadata['tail'], dict):
                # MAGIC
                # self.append_code('{}->{} = {};'.format(struct_name, metadata['tail']['field_name'], tail_struct_name))
                self.__gen_event_memwrite(struct_name, metadata['tail']['field_name'], tail_struct_name, 4);

        def gen_point_to(__struct_type, reserved):
            sub_struct_name = self.gen_struct_point_to(__struct_type)
            # MAGIC
            # self.append_code('{}->{} = {};'.format(struct_name, field_name, sub_struct_name))
            self.__gen_event_memwrite(struct_name, field_name, sub_struct_name, 4);

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
        struct_name = self.construct_struct_name_from_type(struct_type)
        self.append_code('uint32_t {} = get_{}(current_input, &current_event);'.format(struct_name, struct_type))
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
        self.append_code('#include <stddef.h>"')
        self.append_code('#include "videzzo.h"\n')

    def gen_helpers(self):
        helpers = """uint32_t get_bit(uint32_t data, uint32_t start, uint32_t length) {
    return (data >> start) & (1 << (length + 1) - 1);
}

// very interesting and useful function
static void fill(uint8_t *dst, size_t dst_size, uint64_t filler, size_t filler_size) {
    uint8_t *filler_p = (uint8_t *)&filler;
    for (int i = 0; i < dst_size; i++)
        dst[i] = filler_p[i % filler_size];
}

#define EVENT_MEMALLOC(size, n) \\
    videzzo_calloc(size, n)

#define EVENT_MEMWRITE(physaddr, size, data, data_size, uuid) \\
    uint8_t *tmp_buf_##uuid = (uint8_t *)calloc(size, 1); \\
    fill(tmp_buf_##uuid, size, data, data_size); \\
    Event *event_##uuid = event_ops[EVENT_TYPE_MEM_WRITE].construct(EVENT_TYPE_MEM_WRITE, \\
        INTERFACE_MEM_WRITE, physaddr, size, 0, tmp_buf_##uuid); \\
    insert_event(current_input, event_##uuid, *current_event++ + 1); \\
    free(tmp_buf_##uuid);

#define GEN_LINKED_LIST(type, field_name, head_name, last_name, tail_name, uuid) \\
    do { \\
        uint64_t head_name = get_##type(current_input, &current_event); \\
        uint64_t last_name = head_name, tail_name = head_name; \\
        for (int i = 0; i < (videzzo_randint() % 5 -1); i++) { \\
            type *next_##type = get_##type(current_input, &current_event); \\
            EVENT_MEMWRITE(last_name + offsetof(type, field_name), 4, next_##type, 4, uuid) \\
            last_name = next_##type; \\
            tail_name = next_##type; \\
        } \\
    } while(0)
"""
        self.append_code(helpers)

    def gen_struct_definition(self):
        for struct_type, fields in self.structs.items():
            self.append_code('typedef struct {')
            for field_name, metadata in fields.items():
                field_size = metadata['field_size']
                if field_size == '1':
                    self.append_code('    uint8_t {};'.format(field_name))
                elif field_size == '2':
                    self.append_code('    uint16_t {};'.format(field_name))
                elif field_size == '4':
                    self.append_code('    uint32_t {};'.format(field_name))
                elif field_size == '8':
                    self.append_code('    uint64_t {};'.format(field_name))
                else:
                    self.append_code('    uint8_t {}[{}];'.format(field_name, field_size))
            self.append_code('}} {};\n'.format(struct_type))

    def gen_struct(self, struct_type):
        """
        uint32_t get_{struct}();
        """
        self.append_code('// generating {}'.format(struct_type))
        struct_name = self.construct_struct_name_from_type(struct_type)
        # MAGIC
        # self.append_code('{1} *{0} = ({1}*)videzzo_calloc(sizeof({1}), 1);'.format(struct_name, struct_type))
        self.append_code('uint64_t {0} = (uint64_t)EVENT_MEMALLOC(sizeof({1}), 1);'.format(struct_name, struct_type))
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
            self.append_code('static uint64_t get_{}(Input *current_input, uint32_t *current_event) {{'.format(struct_type))
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

        for index, head_struct_type in enumerate(self.head_struct_types):
            self.append_code('void videzzo_group_miss_{}(Input *current_input, uint32_t current_event) {{'.format(index))
            self.indent += 1
            self.append_code('group_mutator_handler_prologue(current_input, &current_event);\n')
            struct_name = self.gen_struct_point_to(head_struct_type)
            # self.free_structs()
            self.indent -= 1
            self.append_code('}')

        return '\n'.join(self.code)
