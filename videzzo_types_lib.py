import random

FIELD_RANDOM  = 1
FIELD_POINTER = 2
FIELD_FLAG    = 4 # TODO: pointer | flag
FIELD_CONSTANT= 8

def dict_append(a, b):
    for k, v in b.items():
        if k in a:
            print('Error: {} is in {}'.format(k, a))
            exit(0)
        else:
            a[k] = v

class Model(object):
    def __init__(self, name, index):
        self.name = name
        self.index = index
        self.structs = {}

        # instrumentation information
        self.head_struct_types = None
        self.instrumentation_points = []
        self.n_instrumentation_points = 0

        # some internal controls
        self.last_uuid = None
        self.code = []
        self.indent = 0

    def initialize(self, index, replacement):
        self.index = index
        structs = {}
        for struct_type, struct_metadata in self.structs.items():
            for field_name, metadata in struct_metadata.items():
                field_type = metadata['field_type']
                if field_type & FIELD_POINTER:
                    for k, v in metadata['point_to']['types'].items():
                        metadata['point_to']['types'][k] = v.replace('###', replacement)
            structs[struct_type.replace('###', replacement)] = struct_metadata
        self.structs = structs

    def get_uuid(self):
        self.last_uuid = '{:010x}'.format(random.randint(0, 0xFFFFFFFFFFFFFFFF))[:10]
        return 'v' + self.last_uuid

    def get_last_uuid(self):
        return 'v' + self.last_uuid

    def get_stats(self):
        for struct_type, struct_metadata in self.structs.items():
            n_fields, n_flag_fields, n_pointer_fields = 0, 0, 0
            for field_name, metadata in struct_metadata.items():
                n_fields += 1
                field_type = metadata['field_type']
                if field_type & FIELD_FLAG:
                    n_flag_fields += 1
                if field_type & FIELD_POINTER:
                    n_pointer_fields += 1
            yield self.name, struct_type, n_flag_fields, n_pointer_fields, n_fields

###########################################################################################
### Construct
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
            field_size = int(field_size, 16)
            self.structs[struct_type][field_name] = {
                'field_size': field_size, 'field_type': field_type}

    def get_struct(self, struct_type):
        return self.structs[struct_type]

    def recover_struct_type_from_name(self, struct_name):
        return '_'.join(struct_name.split('_')[:-1])

    def construct_struct_name_from_type(self, struct_type):
        return '{}_{}'.format(struct_type, self.get_uuid())

    def check_field(self, struct_type, field_name):
        if struct_type not in self.structs:
            raise KeyError('{} is not a valid struct'.format(struct_type))
        if field_name not in self.structs[struct_type]:
            raise KeyError('{} is not a valid field'.format(field_name))

    def get_field_size(self, struct_type, field_name):
        return self.structs[struct_type][field_name]['field_size']

    def add_head(self, head_struct_types):
        """
        head_struct_types: [struct_type0, struct_type1, ..., struct_typen]
        """
        self.head_struct_types = head_struct_types

    def get_head(self):
        return self.head_struct_types

    def add_instrumentation_point(self, filename, callstack):
        """
        filename: basename.c
        callstack: [function1, function2, function_index, argument_index]
        """
        self.instrumentation_points.append({
            'filename': filename, 'callstack': callstack, 'id': self.index})
        self.n_instrumentation_points = len(self.instrumentation_points)

    def get_instrumentation_points(self):
        return self.instrumentation_points

    """
    ViDeZZo constant format:
        self.structs[struct_type][field_name] = {
            'field_name': {'field_size': field_size, 'field_type': field_type, 'field_value': field_value}
        }
    """
    def add_constant(self, key, value):
        """
        key: struct_type.field_name
        value: field_value (list)
        """
        struct_type, field_name = key.split('.')
        self.check_field(struct_type, field_name)
        field_value = value
        self.structs[struct_type][field_name]['field_value'] = field_value

    """
    ViDeZZo flag format:
        self.structs[struct_type][field_name]['flags'] = {
            'start': {'length': length, 'value': initvalue}
        }
    """
    def add_flag(self, key, value):
        """
        key: struct_type.field_name
        value: {'length[@initvalue]'}
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

    """
    ViDeZZo point_to format:
        self.structs[struct][field_name]['point_to'] = {
            'types': {'0': point_to_struct_type},
            'flags': [{'struct_type': struct_type, 'field_name': field_name,
                     'bit': bit, 'length': length}] or None,
            'alignment': 0,
            'array': False or True,
            'linked_list': 'single' or 'double' or None,
            'tail': {'struct_type': struct_type, 'field_name': field_name},
                    if linked_list is not None
            'links': {'0': field_name},
        }
    """
    def add_point_to(self, pointer, types, flags=None, alignment=0, array=False, immediate=False):
        """
        pointer: struct_type.field_name
        types: [struct_type0, struct_type1, ..., struct_typen]
        flags: [struct_type.field_name.bitwise] (if len(types)==1 then flags is None)
        """
        struct_type, field_name = pointer.split('.')
        self.check_field(struct_type, field_name)
        if len(types) == 1:
            self.structs[struct_type][field_name]['point_to'] = {
                'flags': None, 'types': {'0': types[0]},
                'alignment': alignment, 'array': array, 'immediate': immediate}
            return struct_type, field_name
        else:
            assert flags is not None
            metadata = {
                'flags': [], 'types': {},
                'alignment': alignment, 'array': array, 'immediate': immediate}
            for flag in flags:
                flag_struct_type, flag_field_name, flag_bit = flag.split('.')
                self.check_field(flag_struct_type, flag_field_name)
                metadata['flags'].append({
                    'struct_type': flag_struct_type,
                    'field_name': flag_field_name,
                    'bit': flag_bit,
                    'length': self.get_flag_length(flag_struct_type, flag_field_name, flag_bit)})
            for idx, point_to_struct_type in enumerate(types):
                metadata['types'][str(idx)] = point_to_struct_type
            self.structs[struct_type][field_name]['point_to'] = metadata
            return struct_type, field_name

    def add_point_to_single_linked_list(
            self, head, tail, types, links, flags=None, alignment=0, array=False):
        """
        head: struct_type.field_name
        tail: struct_type.field_name
        types: [struct_type0, struct_type1, ..., struct_typen]
        links: [link0, link1, ..., linkn]
        flags: [struct_type.field_name.bitwise] (if len(types)==1 then flags is None)
        """
        # let's handle the head pointer first
        struct_type, field_name = self.add_point_to(
            head, types, flags=flags, alignment=alignment, array=array)
        # let's handle the tail pointer then
        self.structs[struct_type][field_name]['point_to']['linked_list'] = 'single'
        if tail is not None:
            tail_struct_type, tail_field_name = tail.split('.')
            self.check_field(tail_struct_type, tail_field_name)
            self.structs[struct_type][field_name]['point_to']['tail'] = {
                'struct_type': tail_struct_type, 'field_name': tail_field_name}
            self.structs[tail_struct_type][tail_field_name]['point_to'] = {'tail': True}

        metadata = self.structs[struct_type][field_name]['point_to']
        metadata['links'] = {}
        for idx, _ in metadata['types'].items():
            self.structs[struct_type][field_name]['point_to']['links'][idx] = links[int(idx)]

###########################################################################################
### Generate
###########################################################################################
    def __gen_event_memwrite(self, struct_name, field_name, value, value_size):
        struct_type = self.recover_struct_type_from_name(struct_name)
        field_size = self.get_field_size(struct_type, field_name)
        if value_size < field_size and field_size == 8:
            value_size = field_size
        self.append_code('EVENT_MEMWRITE({} + offsetof({}, {}), {}, {}, {}, {});'.format(
            struct_name, struct_type, field_name, hex(field_size), value, hex(value_size), self.get_uuid()))

    def __gen_flag_value(self, metadata):
        flags = []
        length_in_total = 0
        for start, length_and_initvalue in metadata.items():
            if int(start) != length_in_total:
                length_in_total = int(start)
            length = length_and_initvalue['length']
            initvalue = length_and_initvalue['initvalue']
            if initvalue is None:
                initvalue = 'urand32()'
            # flags.append(('(({0} & ((1 << 0x{1:02x}) - 1)) << 0x{2:02x})'.format(initvalue, length, length_in_total)))
            flags.append(('(({0} % (1u << 0x{1:02x})) << 0x{2:02x})'.format(initvalue, length, length_in_total)))
            length_in_total += int(length)
        sep = '\n    {} | '.format(' ' * self.indent * 4)
        return sep.join(flags)

    def gen_flag(self, struct_name, field_name, metadata):
        # MAGIC
        # self.append_code('{}->{} = {};'.format(struct_name, field_name, sep.join(flags)))
        self.__gen_event_memwrite(struct_name, field_name, self.__gen_flag_value(metadata), 4)

    def gen_random(self, struct_name, field_name, metadata):
        # MAGIC
        # self.append_code('{}->{} = {};'.format(struct_name, field_name, 'urand32()'))
        self.__gen_event_memwrite(struct_name, field_name, 'urand32()', 4)

    def gen_immediate_point_to(self, struct_name, field_name, metadata):
        struct_type = self.recover_struct_type_from_name(struct_name)

        flags = metadata['flags']
        if flags:
            flag_value = self.__gen_flag_value(flags)
        else:
            flag_value = '0x0'
        self.__gen_point_to(struct_name, field_name, metadata['point_to'], flag_value)

    def gen_constant_declaration(self):
        """
        Declare these constants.
        """
        for struct_type, fields in self.structs.items():
            for field_name, metadata in fields.items():
                field_size = metadata['field_size']
                field_type = metadata['field_type']
                if (field_type & FIELD_CONSTANT) == 0:
                    continue
                assert field_size in [1, 2, 4, 8]
                field_value = metadata['field_value']
                assert isinstance(field_value, list)
                self.append_code('uint{}_t {}_{}_constant[{}] = {{'.format(
                    int(field_size) * 8, struct_type, field_name, len(field_value)))
                self.indent += 1
                for constant in field_value:
                    self.append_code('{},'.format(hex(constant)))
                self.indent -= 1
                self.append_code('}};\n'.format(struct_type))

    def gen_constant(self, struct_name, field_name, metadata):
        field_value = metadata['field_value']
        struct_type = self.recover_struct_type_from_name(struct_name)

        flag_value = '0x0'
        if 'flags' in metadata:
            flags = metadata['flags']
            if flags:
                flag_value = self.__gen_flag_value(flags)

        # MAGIC
        # self.append_code('{}->{} = {};'.format(struct_name, field_name, 'urand32()'))
        self.__gen_event_memwrite(
            struct_name, field_name, '{}_{}_constant[urand32() % {}] | ({})'.format(
                struct_type, field_name, len(field_value), flag_value), 4)

    def __gen_point_to(self, struct_name, field_name, metadata, flag_value):
        """
        Handle each pointer.
        """
        if 'tail' in metadata and metadata['tail'] is True:
            return

        self.append_code('// gen point_to for {}->{}'.format(struct_name, field_name))
        flags = metadata['flags']
        types = metadata['types']
        links = metadata['links'] if 'links' in metadata else None

        def __gen_single_linked_list(__struct_type, __field_name):
            self.append_code('// gen linked list for {}->{}'.format(__struct_type, __field_name))
            head_struct_name = self.construct_struct_name_from_type(__struct_type)
            last_struct_name = 'last_struct_name_{}'.format(self.get_uuid())
            tail_struct_name = 'tail_struct_name_{}'.format(self.get_uuid())
            self.append_code('GEN_LINKED_LIST({}, {}, {}, {}, {}, {}, {});'.format(
                __struct_type, __field_name, head_struct_name, last_struct_name, tail_struct_name, self.get_uuid(), flag_value))
            return head_struct_name, tail_struct_name

        def gen_single_linked_list(__struct_type, __field_name):
            head_struct_name, tail_struct_name = __gen_single_linked_list(__struct_type, __field_name)
            # MAGIC
            # self.append_code('{}->{} = {};'.format(struct_name, field_name, head_struct_name))
            self.append_code('{} |= {};'.format(head_struct_name, flag_value))
            self.__gen_event_memwrite(struct_name, field_name, head_struct_name, 4);
            if 'tail' in metadata and isinstance(metadata['tail'], dict):
                # MAGIC
                # self.append_code('{}->{} = {};'.format(struct_name, metadata['tail']['field_name'], tail_struct_name))
                self.append_code('{} |= {};'.format(tail_struct_name, flag_value))
                self.__gen_event_memwrite(struct_name, metadata['tail']['field_name'], tail_struct_name, 4);

        def gen_single_object(__struct_type):
            sub_struct_name = self.gen_struct_point_to(__struct_type)
            # MAGIC
            # self.append_code('{}->{} = {};'.format(struct_name, field_name, sub_struct_name))
            self.append_code('{} |= {};'.format(sub_struct_name, flag_value))
            self.__gen_event_memwrite(struct_name, field_name, sub_struct_name, 4);

        def is_single_linked_list(__metadata):
            return 'linked_list' in __metadata and __metadata['linked_list'] == 'single'

        # we support pointing to a single object, or a single linked list
        if flags is None:
            if is_single_linked_list(metadata):
                assert links is not None
                gen_single_linked_list(types['0'], links['0'])
            else:
                gen_single_object(types['0'])
        else:
            #  gen_conditional_point_to(gen_single_linked_list, links)
            #  gen_conditional_point_to(gen_single_object, None)
            # MAGIC
            # cond = ' | '.join(['get_bit({}->{}, {}, {})'.format(
            #     struct_name, flag['field_name'], flag['bit'], flag['length']) for flag in flags])
            struct_type = self.recover_struct_type_from_name(struct_name)
            field_size = self.get_field_size(struct_type, field_name)
            conds = []
            for flag in flags:
                tmp_buf_name = 'tmp_buf_{}'.format(self.get_uuid())
                self.append_code('uint64_t {} = 0;'.format(tmp_buf_name))
                self.append_code('EVENT_MEMREAD({} + offsetof({}, {}), {}, &{}, {}, {});'.format(
                    struct_name, struct_type, flag['field_name'], hex(field_size), tmp_buf_name, hex(4), self.get_uuid()))
                conds.append('get_bit({}, {}, {})'.format(tmp_buf_name, flag['bit'], flag['length']))
            cond = ' | '.join(conds)
            self.append_code('switch ({}) {{'.format(cond))
            self.indent += 1
            for case, struct_type in types.items():
                self.append_code('case {}: {{'.format(case))
                self.indent += 1
                if struct_type is None:
                    self.append_code('break; }')
                    continue
                if is_single_linked_list(metadata):
                    assert links is not None
                    gen_single_linked_list(struct_type, links[case])
                else:
                    gen_single_object(struct_type)
                self.append_code('break; }')
                self.indent -= 1
            self.indent -= 1
            self.append_code('}')

    def gen_struct_point_to(self, struct_type, head=False):
        """
        Initilize a struct's pointers and return the struct name.
        """
        struct_name = self.construct_struct_name_from_type(struct_type)
        if head:
            self.append_code('uint32_t {} = get_{}(physaddr);'.format(struct_name, struct_type))
        else:
            self.append_code('uint32_t {} = get_{}(INVALID_ADDRESS);'.format(struct_name, struct_type))
            self.append_code('append_address({});'.format(struct_name))
        for field_name, metadata in self.get_struct(struct_type).items():
            field_type = metadata['field_type']
            if field_type & FIELD_POINTER:
                if field_type & FIELD_FLAG:
                    flag_value = self.__gen_flag_value(metadata['flags'])
                else:
                    flag_value = '0x0'
                self.__gen_point_to(struct_name, field_name, metadata['point_to'], flag_value=flag_value)
        return struct_name

    def gen_struct_declaration(self):
        """
        Declare these structs.
        """
        for struct_type, fields in self.structs.items():
            self.append_code('typedef struct {')
            for field_name, metadata in fields.items():
                field_size = metadata['field_size']
                if field_size == 1:
                    self.append_code('    uint8_t {};'.format(field_name))
                elif field_size == 2:
                    self.append_code('    uint16_t {};'.format(field_name))
                elif field_size == 4:
                    self.append_code('    uint32_t {};'.format(field_name))
                elif field_size == 8:
                    self.append_code('    uint64_t {};'.format(field_name))
                else:
                    self.append_code('    uint8_t {}[{}];'.format(field_name, field_size))
            self.append_code('}} {};\n'.format(struct_type))

    def __gen_struct_without_pointers(self, struct_type):
        """
        Handle each non-pointer field.
        """
        self.append_code('// generating {}'.format(struct_type))
        struct_name = self.construct_struct_name_from_type(struct_type)
        # MAGIC
        # self.append_code('{1} *{0} = ({1}*)videzzo_calloc(sizeof({1}), 1);'.format(struct_name, struct_type))
        self.append_code('uint64_t {0};'.format(struct_name))
        self.append_code('if (physaddr == INVALID_ADDRESS) {{ {0} = (uint64_t)EVENT_MEMALLOC(sizeof({1})); }} else {{ {0} = physaddr; }}'.format(struct_name, struct_type))
        for field_name, metadata in self.get_struct(struct_type).items():
            field_type = metadata['field_type']
            if (field_type & FIELD_FLAG) and \
                    (not field_type & FIELD_POINTER) and (not field_type & FIELD_CONSTANT):
                assert 'flags' in metadata, 'flag {}.{} is not set up'.format(struct_type, field_name)
                self.gen_flag(struct_name, field_name, metadata['flags'])
            elif field_type & FIELD_RANDOM:
                self.gen_random(struct_name, field_name, metadata)
            elif field_type & FIELD_CONSTANT:
                self.gen_constant(struct_name, field_name, metadata)
            elif (field_type & FIELD_POINTER):
                if 'immediate' in metadata['point_to'] and metadata['point_to']['immediate']:
                    # we want both point_to and flags so we pass metadata
                    self.gen_immediate_point_to(struct_name, field_name, metadata)
            else:
                raise ValueError('unsupported FIELD_TYPE: {}'.format(field_type))
        return struct_name

    def gen_struct_initialization_without_pointers(self):
        """
        Create a function to define a struct and its non-pointer fields.
        """
        for struct_type, fields in self.structs.items():
            self.append_code('static uint64_t get_{}(uint64_t physaddr) {{'.format(struct_type))
            self.indent += 1
            struct_name = self.__gen_struct_without_pointers(struct_type)
            self.append_code('return {};'.format(struct_name))
            self.indent -= 1
            self.append_code('}\n')

    def gen_free_structs(self):
        """
        Create a function to free allocated memory.
        """
        self.append_code('// free_memory_blocks();')

    def gen_license(self):
        """
        Generate license.
        """
        license = """/*
 * Dependency-Aware Virtual-Device Fuzzing
 *
 * Copyright Qiang Liu <cyruscyliu@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 */
"""
        self.append_code(license)

    def gen_headers(self):
        """
        Generate headers required.
        """
        self.append_code('#include <stdint.h>')
        self.append_code('#include <stddef.h>\n')

    def gen_helpers(self):
        """
        Generate common functions as helpers.
        """
        helpers = """#define INVALID_ADDRESS 0xFFFFFFFFFFFFFFFF
#define EVENT_MEMREAD(physaddr, size, data, data_size, uuid) \\
    uint8_t *tmp_buf_##uuid = (uint8_t *)calloc(size, 1); \\
    __EVENT_MEMREAD(physaddr, size, tmp_buf_##uuid); \\
    refill(data, data_size, tmp_buf_##uuid, size); \\
    // free(tmp_buf_##uuid);

#define EVENT_MEMWRITE(physaddr, size, data, data_size, uuid) \\
    uint8_t *tmp_buf_##uuid = (uint8_t *)calloc(size, 1); \\
    fill(tmp_buf_##uuid, size, data, data_size); \\
    __EVENT_MEMWRITE(physaddr, size, tmp_buf_##uuid); \\
    // free(tmp_buf_##uuid);

#define GEN_LINKED_LIST(type, field_name, head_name, last_name, tail_name, uuid, flag_value) \\
    uint64_t head_name = get_##type(INVALID_ADDRESS); \\
    append_address(head_name); \\
    uint64_t last_name = head_name, tail_name = head_name; \\
    for (int i = 0; i < (urand32() % 5 -1); i++) { \\
        uint64_t next_##type = get_##type(INVALID_ADDRESS); \\
        append_address(next_##type); \\
        next_##type |= flag_value; \\
        EVENT_MEMWRITE(last_name + offsetof(type, field_name), 4, next_##type, 4, uuid) \\
        last_name = next_##type; \\
        tail_name = next_##type; \\
    }
"""
        self.append_code(helpers)

    def append_code(self, code):
        self.code.append(' ' * self.indent * 4 + code)

    def get_code(self):
        self.gen_license()
        self.gen_headers();
        self.gen_helpers();
        self.gen_struct_declaration()
        self.gen_constant_declaration()
        self.gen_struct_initialization_without_pointers()

        self.append_code('void videzzo_group_mutator_miss_handler_{}(uint64_t physaddr) {{'.format(self.index))
        self.indent += 1
        self.append_code('switch (urand32() % {}) {{'.format(len(self.head_struct_types)))
        self.indent += 1
        for idx, head_struct_type in enumerate(self.head_struct_types):
            self.append_code('case {} : {{'.format(idx))
            self.indent += 1
            struct_name = self.gen_struct_point_to(head_struct_type, head=True)
            self.append_code('break; }')
            self.indent -= 1
        self.indent -= 1
        self.append_code('}')
        self.gen_free_structs()
        self.indent -= 1
        self.append_code('}')

        return '\n'.join(self.code)
