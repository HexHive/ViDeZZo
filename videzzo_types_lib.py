import os
import uuid
import random
from render import Template

def dict_append(a, b):
    for k, v in b.items():
        a[k] = v

last_uuid = 0

def get_uuid():
    global last_uuid
    last_uuid = '{:010x}'.format(random.randint(0, 0xFFFFFFFFFFFFFFFF))[:10]
    return 'v' + last_uuid

def get_last_uuid():
    global last_uuid
    return 'v' + last_uuid

# topology: base -> target
# base name   +-----+-----+-----+
#             |<-size to spray->|
#             + (&target) | tag +
# target name +-----+-----+-----+
#             |<-size to alloc->|
def tag_value(value, tags):
    # tags = [{'op': '&', 'tag': '0xfffffffe'}]
    r = '{}{}'.format('(' * len(tags), value)
    for tag in tags:
        r += ' {} {})'.format(tag['op'], tag['tag'])
    return r

def alloc_base(type_name, name, size, chained='false'):
    return [{'event': 'alloc', 'kwargs': {
        'chained': chained, 'name': name, 'size': size, 'type': type_name}}]

def spray_addr(base_name, size_to_spray, target_name, target_addr_tag):
    # legacy
    # {'event': 'lock', 'kwargs': {'offset': base_name, 'size': size_to_spray}},
    # {'event': 'require', 'kwargs': {'size': size_to_alloc, 'name': target_name}},
    return [{'event': 'serialize', 'kwargs': {
        'id': 'INTERFACE_MEM_WRITE', 'offset': base_name, 'size': size_to_spray,
        'value': tag_value(target_name, target_addr_tag)}}]

def set_head_address(mmio_event, value, tag):
    if 'value' in mmio_event:
        value = mmio_event['value']
    else:
        value = tag_value(value, tag)
    return [{'event': 'serialize', 'kwargs': {
        'id': 'get_interface_id("{}", {})'.format(mmio_event['name'], mmio_event['type']),
        'offset': mmio_event['offset'], 'size': mmio_event['size'],
        'value': value}}]

def get_indicator(base_name, offset):
    return '{} + {}'.format(base_name, offset)

def write_pointer_field(base_name, offset, size, value, tag):
    return [{'event': 'serialize', 'kwargs': {
        'id': 'INTERFACE_MEM_WRITE', 'offset': get_indicator(base_name, offset),
        'size': size, 'value': tag_value(value, tag)}}]

def write_data_field(base_name, offset, size, value):
    return [{'event': 'serialize', 'kwargs': {
        'id': 'INTERFACE_MEM_WRITE', 'offset': get_indicator(base_name, offset),
        'size': size, 'value': value}}]

def get_random_data(size):
    size = int(size, 16)
    if size % 4 == 0:
        return 'get_data_from_pool4()'
    elif size % 2 == 0:
        return 'get_data_from_pool2()'
    else:
        return 'get_data_from_pool1()'

## Let's define some context-ops
POINTER_TAG      = 4
FLAG_TO_POINTER  = 5
POINTER_RING     = 6

PTR_ZERO = '0'
PTR_SELF = '1'
PTR_BUFFER = '2'
PTR_FLAGS = '3'
PTR_OBJECT = '4'
PTR_CONSTANT = '5'

## INTERNAL TABLES
objects = {}
def add_object(key, value):
    global objects
    objects[key] = value

def get_object(key):
    return objects[key]

def get_object_size(key):
    return hex(sum([int(field.split('#')[1], 16) for field in objects[key].keys()]))

point_tos = {}
def add_point_to(key, value):
    global point_tos
    point_tos[key] = value

def get_point_to(key):
    return point_tos[key]

tags = {}
def add_tag(key, value):
    global tags
    tags[key] = value

def get_tag(key):
    return tags[key]

flags = {}
def add_flag(key, value):
    global flags
    flags[key] = value

def get_flag(key):
    return flags[key]

def gen_flag(object_to_alloc, field_name):
    flag = get_flag('{}.{}'.format(object_to_alloc, field_name))
    segs = []
    #TODO fix this get_data_from_pool4 to get_xxx
    length_acc = 0
    for start, length in flag.items():
        value = 'get_data_from_pool4()'
        if isinstance(length, str):
            length, value = length.split('@')
            length = int(length)
        segs.append(('(({0} & ((1 << (0x{1:02x} + 1)) - 1)) << 0x{2:02x})'.format(value, length, length_acc)))
        length_acc += length
    return '({})'.format(' | '.join(segs))

arrays = {}
def add_array(key, value):
    global arrays
    arrays[key] = value

def get_array(key):
    return arrarys[key]

constants = {}
def add_constant(key, value):
    global constants
    constants[key] = value

def get_constant(key):
    return constants[key]

heads = {}
def add_head(key, value):
    global heads
    heads[key] = value

def get_head(key):
    return heads[key]

def fill_object(base_name, object_to_alloc):
    field_offset = '0x0'
    dma_events = []
    for field, field_type in get_object(object_to_alloc).items():
        field_name, field_size = field.split('#')
        if field_type == PTR_OBJECT:
            # pointer field and objects
            object_to_points = get_point_to('{}.{}'.format(object_to_alloc, field_name))
            uuid = get_uuid()
            dma_events += [{'event': 'switch', 'kwargs': {
                'modulo': len(object_to_points), 'uuid': uuid}}]
            for index, object_to_point in enumerate(object_to_points):
                dma_events += [{'event': 'goto_label', 'kwargs': {'label': '{}_{}'.format(uuid, index)}}]
                object_name_to_point = '{}_{}'.format(object_to_point, get_uuid())
                dma_events += alloc_base(
                    object_to_point, object_name_to_point, get_object_size(object_to_point))
                dma_events += fill_object(
                    object_name_to_point, object_to_point)
                dma_events += write_pointer_field(
                    base_name, field_offset, field_size, object_name_to_point, get_tag(object_to_point))
                dma_events += [{'event': 'goto', 'kwargs': {'label': '{}_out'.format(uuid)}}]
            dma_events += [{'event': 'goto_label', 'kwargs': {'label': '{}_out'.format(uuid)}}]
        elif field_type == PTR_SELF:
            # pointer field and itself
            dma_events += write_pointer_field(
                base_name, field_offset, field_size, base_name, get_tag(object_to_alloc))
        elif field_type == PTR_BUFFER:
            # pointer field and buffers
            buffer_name_to_point = 'buffer_{}'.format(get_uuid())
            dma_events += alloc_base('uint8_t', buffer_name_to_point, '0x100')
            dma_events += write_data_field(
                buffer_name_to_point, '0x0', '0x100', get_random_data('0x4'))
            dma_events += write_pointer_field(
                base_name, field_offset, field_size, buffer_name_to_point, [{'op': '|', 'tag': '0x0'}])
        elif field_type == PTR_FLAGS:
            # data field and flags
            dma_events += write_data_field(
                base_name, field_offset, field_size, gen_flag(object_to_alloc, field_name))
        elif field_type == PTR_CONSTANT:
            # data field and constant
            dma_events += write_data_field(
                base_name, field_offset, field_size, get_constant('{}.{}'.format(object_to_alloc, field_name)))
        elif field_type == PTR_ZERO:
            # data field and random values
            dma_events += write_data_field(
                base_name, field_offset, field_size, get_random_data(field_size))
        else:
            print('[-] wrong field_type, return []')
            return []
        field_offset = int(field_offset, 16)
        field_offset += int(field_size, 16)
        field_offset = hex(field_offset)
    return dma_events

def generate_events(head):
    head_structs = head['head_struct']
    head_name = head['head_name']
    uuid = get_uuid()
    dma_events = [{'event': 'switch', 'kwargs': {'modulo': len(head_structs), 'uuid': uuid}}]
    for index, head_struct in enumerate(head_structs):
        head_name = '{}_{}'.format(head_name, index)
        dma_events += [{'event': 'goto_label', 'kwargs': {'label': '{}_{}'.format(uuid, index)}}]
        dma_events += alloc_base(head_struct, head_name, get_object_size(head_struct))
        dma_events += fill_object(head_name, head_struct)
        target = head_name
        target_tag = get_tag(head_struct)
        if 'spray' in head:
            # alloc a base buffer
            target = '{}_base'.format(get_uuid())
            target_tag = [{'op': '|', 'tag': '0x0'}]
            spray_size = head['spray']['size']
            dma_events += alloc_base('uint8_t', target, spray_size)
            dma_events += spray_addr(target, spray_size, head_name, get_tag(head_struct))
        for mmio_event in head['io_events']:
            # print(target, target_tag)
            dma_events += set_head_address(mmio_event, target, target_tag)
        dma_events += [{'event': 'goto', 'kwargs': {'label': '{}_out'.format(uuid)}}]
    dma_events += [{'event': 'goto_label', 'kwargs': {'label': '{}_out'.format(uuid)}}]
    return dma_events

def get_devisor(size):
    # deprecated
    size = int(size, 16)
    if size % 4 == 0:
        return '0x4'
    elif size % 2 == 0:
        return '0x2'
    else:
        return '0x1'

def main_demo():
    parameters = {'callbacks': [], 'arrays': []}
    for key, value in arrays.items():
        array = {'name': key, 'size': hex(len(value)), 'elements': value}
        parameters['arrays'].append(array)

    idx = 0
    for name, head in heads.items():
        dma_events = generate_events(head)
        for dma_event in dma_events:
            dma_event['kwargs']['eid'] = get_uuid()
            # print(dma_event)
        callback = {
            'loc': head['instrumentation'],
            'dma_events': dma_events, 'id': idx, 'name': name}
        parameters['callbacks'].append(callback)
        idx += 1

    with open('template3.h') as f:
        lines = f.readlines()
    line = ''.join(lines)
    data = parameters
    data['is_alloc'] = lambda x: x == 'alloc'
    data['is_serialize'] = lambda x: x == 'serialize'
    data['is_switch'] = lambda x: x == 'switch'
    data['is_goto'] = lambda x: x == 'goto'
    data['is_goto_label'] = lambda x: x == 'goto_label'
    data['is_memory_write'] = lambda x: x in ['INTERFACE_MEM_WRITE']
    data['is_io_command'] = lambda x: x.startswith('get_interface_id')
    data['is_constant'] = lambda x: x.startswith('0x')
    data['is_not_variable'] = lambda x: 'get_data_from' in x or 'flags' in x
    data['to_hex'] = lambda x: hex(x)
    data['len'] = lambda x: len(x)
    data['not'] = lambda x: not x
    data['to_range'] = lambda x: range(0, x)
    data['get_divisor'] = get_devisor
    r = Template(line).render(data)
    with open('stateful_fuzz_callbacks.h', 'w') as f:
        f.write(r)
    print('[+] generate stateful_fuzz_callbacks.h')
