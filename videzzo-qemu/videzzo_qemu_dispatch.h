/*
 * Type-Aawre Virtual-Device Fuzzing QEMU
 *
 * Copyright Red Hat Inc., 2021
 *
 * Authors:
 *  Qiang Liu <cyruscyliu@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#ifndef STATEFUL_FUZZ_DISPATCH_H
#define STATEFUL_FUZZ_DISPATCH_H

#include "videzzo_qemu.h"

//
// QEMU Dispatcher
//
void dispatch_mmio_read(Event *event, void *object) { 
    QTestState *s = (QTestState *)object;
    switch (event->size) {
        case Byte0: qtest_readb(s, event->addr); break;
        case Word: qtest_readw(s, event->addr); break;
        case Long: qtest_readl(s, event->addr); break;
        case Quad: qtest_readq(s, event->addr); break;
        default: fprintf(stderr, "wrong size of dispatch_mmio_read %d\n", size); break;
    }
}

void dispatch_pio_read(Event *event, void *object) {
    QTestState *s = (QTestState *)object;
    switch (event->size) {
        case Byte0: qtest_inb(s, event->addr); break;
        case Word: qtest_inw(s, event->addr); break;
        case Long: qtest_inl(s, event->addr); break;
        default: fprintf(stderr, "wrong size of dispatch_pio_read %d\n", size); break;
    }
}

void dispatch_mem_read(Event *event, void *object) {
    QTestState *s = (QTestState *)object;
    qtest_memread(s, event->addr, event->data, event->size);
}

void dispatch_mmio_write(Event *event, void *object) {
    QTestState *s = (QTestState *)object;
    switch (event->size) {
        case Byte0: qtest_writeb(s, event->addr, event->val & 0xFF); break;
        case Word: qtest_writew(s, event->addr, event->val & 0xFFFF); break;
        case Long: qtest_writel(s, event->addr, event->val & 0xFFFFFFFF); break;
        case Quad: qtest_writeq(s, event->addr, event->val); break;
        default: fprintf(stderr, "wrong size of dispatch_mmio_write %d\n", size); break;
    }
}

void dispatch_pio_write(Event *event, void *object) {
    QTestState *s = (QTestState *)object;
    switch (event->size) {
        case Byte0: qtest_outb(s, event->addr, event->val & 0xFF); break;
        case Word: qtest_outw(s, event->addr, event->val & 0xFFFF); break;
        case Long: qtest_outl(s, event->addr, event->val & 0xFFFFFFFF); break;
        default: fprintf(stderr, "wrong size of dispatch_pio_write %d\n", size); break;
    }
}

void dispatch_mem_write(Event *event, void *object) {
    QTestState *s = (QTestState *)object;
    qtest_memwrite(s, event->addr, event->data, size);
}

void dispatch_clock_step(Event *event, void *object) {
    QTestState *s = (QTestState *)object;
    qtest_clock_step(s, s->val);
}

#define FMT_timeval "%ld.%06ld"
void qtest_get_time(qemu_timeval *tv);
static void printf_qtest_prefix()
{
    qemu_timeval tv;
    qtest_get_time(&tv);
    printf("[R +" FMT_timeval "] ",
            (long) tv.tv_sec, (long) tv.tv_usec);
}

void dispatch_socket_write(Event *event, void *object) { //  }QTestState *s, const void *data, uint32_t size) {
    QTestState *s = (QTestState *)object;
    uint8_t D[SOCKET_WRITE_MAX_SIZE + 4];
    const uint8_t *ptr = &D;
    char *enc;
    uint32_t i;
    if (!sockfds_initialized)
        return;
    size_t size = event->size;
    if (size > SOCKET_WRITE_MAX_SIZE)
        return;
    // first four bytes are lenght
    uint32_t S = htonl(size);
    memcpy(D, (uint8_t *)&S, 4);
    memcpy(D + 4, data, size);
    size += 4;
    int ignore = write(sockfds[0], D, size);
    // to show what a socket write did
    if (getenv("FUZZ_SERIALIZE_QTEST")) {
        enc = g_malloc(2 * size + 1);
        for (i = 0; i < size; i++) {
            sprintf(&enc[i * 2], "%02x", ptr[i]);
        }
        printf_qtest_prefix();
        printf("sock %d 0x%x 0x%s\n", sockfds[0], size, enc);
    }
    (void) ignore;
    return;
}

#endif /* STATEFUL_FUZZ_DISPATCH_H */
