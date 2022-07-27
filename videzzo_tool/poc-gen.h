/*
 * Dependency-Aware Virtual-Device Fuzzing
 *
 * Copyright Qiang Liu <cyruscyliu@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 */

#include "videzzo.h"

#define __EVENT_TYPE_MMIO_WRITE(interface, type, addr, size, value) \
    event = event_ops[EVENT_TYPE_MMIO_WRITE].construct( \
         EVENT_TYPE_MMIO_WRITE, interface, addr, size, value, NULL); \
    append_event(input, event);

#define __EVENT_TYPE_MMIO_READ(interface, type, addr, size) \
    event = event_ops[EVENT_TYPE_MMIO_READ].construct( \
         EVENT_TYPE_MMIO_READ, interface, addr, size, 0, NULL); \
    append_event(input, event);

#define __EVENT_TYPE_COCK_STEP(interface, type, value) \
    event = event_ops[EVENT_TYPE_CLOCK_STEP].construct( \
         EVENT_TYPE_CLOCK_STEP, interface, 0, 0, value, NULL); \
    append_event(input, event);

static void construct_poc(Input *input) {
    Event *event;
    // append event for a PoC, e.g,
    // event = event_ops[EVENT_TYPE_MMIO_WRITE].construct(
    //     EVENT_TYPE_MMIO_WRITE, /*interface=*/0, /*addr=*/0,
    //     /*size=*/4, /*value=*/0, /*data=*/NULL);
    // append_event(input, event);
    __EVENT_TYPE_MMIO_WRITE(8, EVENT_TYPE_MMIO_WRITE, 0xe0023818, 0x4, 0x1f1e3a54)
    __EVENT_TYPE_MMIO_WRITE(8, EVENT_TYPE_MMIO_WRITE, 0xe0020428, 0x4, 0xffffffff)
    __EVENT_TYPE_MMIO_WRITE(8, EVENT_TYPE_MMIO_WRITE, 0xe0020430, 0x4, 0x00000001)
    __EVENT_TYPE_MMIO_WRITE(8, EVENT_TYPE_MMIO_WRITE, 0xe0020438, 0x4, 0x00000000)
    __EVENT_TYPE_MMIO_READ(7, EVENT_TYPE_MMIO_READ, 0xe003fa94, 0x4)
    __EVENT_TYPE_MMIO_WRITE(8, EVENT_TYPE_MMIO_WRITE, 0xe0020400, 0x4, 0x640de3df)
}
