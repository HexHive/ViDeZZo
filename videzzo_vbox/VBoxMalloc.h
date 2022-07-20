/* $Id$ */
/** @file
 * VBoxMalloc.h - The VirtualBox ViDeZZo guest memory allocator.
 */

/*
 * Copyright (C) 2006-2022 Oracle Corporation
 *
 * This file is part of VirtualBox Open Source Edition (OSE), as
 * available from http://www.virtualbox.org. This file is free software;
 * you can redistribute it and/or modify it under the terms of the GNU
 * General Public License (GPL) as published by the Free Software
 * Foundation, in version 2 as it comes in the "COPYING" file of the
 * VirtualBox OSE distribution. VirtualBox OSE is distributed in the
 * hope that it will be useful, but WITHOUT ANY WARRANTY of any kind.
 * 
 * Authors: Qiang Liu <cyruscyliu@gmail.com>
 *
 * This code is initially copied from
 * - qemu/qtest/libqos/malloc.[c|h]
 * - qemu/qtest/libqos/malloc-pc.[c|h]
 */

#ifndef VBOX_MALLOC_H
#define VBOX_MALLOC_H

#include <stdint.h>
#include <inttypes.h>
#include <stddef.h>
#include <gmodule.h>

/*      $NetBSD: queue.h,v 1.52 2009/04/20 09:56:08 mschuett Exp $ */

/*
 * VBox version: Copy from QEMU, removed unused macros.
 *
 * QEMU version: Copy from netbsd, removed debug code, removed some of
 * the implementations.  Left in singly-linked lists, lists, simple
 * queues, and tail queues.
 */

/*
 * Copyright (c) 1991, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      @(#)queue.h     8.5 (Berkeley) 8/20/94
 */

#ifndef QEMU_SYS_QUEUE_H
#define QEMU_SYS_QUEUE_H

/*
 * This file defines four types of data structures: singly-linked lists,
 * lists, simple queues, and tail queues.
 *
 * A singly-linked list is headed by a single forward pointer. The
 * elements are singly linked for minimum space and pointer manipulation
 * overhead at the expense of O(n) removal for arbitrary elements. New
 * elements can be added to the list after an existing element or at the
 * head of the list.  Elements being removed from the head of the list
 * should use the explicit macro for this purpose for optimum
 * efficiency. A singly-linked list may only be traversed in the forward
 * direction.  Singly-linked lists are ideal for applications with large
 * datasets and few or no removals or for implementing a LIFO queue.
 *
 * A list is headed by a single forward pointer (or an array of forward
 * pointers for a hash table header). The elements are doubly linked
 * so that an arbitrary element can be removed without a need to
 * traverse the list. New elements can be added to the list before
 * or after an existing element or at the head of the list. A list
 * may only be traversed in the forward direction.
 *
 * A simple queue is headed by a pair of pointers, one the head of the
 * list and the other to the tail of the list. The elements are singly
 * linked to save space, so elements can only be removed from the
 * head of the list. New elements can be added to the list after
 * an existing element, at the head of the list, or at the end of the
 * list. A simple queue may only be traversed in the forward direction.
 *
 * A tail queue is headed by a pair of pointers, one to the head of the
 * list and the other to the tail of the list. The elements are doubly
 * linked so that an arbitrary element can be removed without a need to
 * traverse the list. New elements can be added to the list before or
 * after an existing element, at the head of the list, or at the end of
 * the list. A tail queue may be traversed in either direction.
 *
 * For details on the use of these macros, see the queue(3) manual page.
 */

typedef struct QTailQLink {
    void *tql_next;
    struct QTailQLink *tql_prev;
} QTailQLink;

/*
 * Tail queue definitions.  The union acts as a poor man template, as if
 * it were QTailQLink<type>.
 */
#define QTAILQ_HEAD(name, type)                                         \
union name {                                                            \
        struct type *tqh_first;       /* first element */               \
        QTailQLink tqh_circ;          /* link for circular backwards list */ \
}

#define QTAILQ_ENTRY(type)                                              \
union {                                                                 \
        struct type *tqe_next;        /* next element */                \
        QTailQLink tqe_circ;          /* link for circular backwards list */ \
}

/*
 * Tail queue functions.
 */
#define QTAILQ_INIT(head) do {                                          \
        (head)->tqh_first = NULL;                                       \
        (head)->tqh_circ.tql_prev = &(head)->tqh_circ;                  \
} while (/*CONSTCOND*/0)

#define QTAILQ_INSERT_HEAD(head, elm, field) do {                       \
        if (((elm)->field.tqe_next = (head)->tqh_first) != NULL)        \
            (head)->tqh_first->field.tqe_circ.tql_prev =                \
                &(elm)->field.tqe_circ;                                 \
        else                                                            \
            (head)->tqh_circ.tql_prev = &(elm)->field.tqe_circ;         \
        (head)->tqh_first = (elm);                                      \
        (elm)->field.tqe_circ.tql_prev = &(head)->tqh_circ;             \
} while (/*CONSTCOND*/0)

#define QTAILQ_INSERT_TAIL(head, elm, field) do {                       \
        (elm)->field.tqe_next = NULL;                                   \
        (elm)->field.tqe_circ.tql_prev = (head)->tqh_circ.tql_prev;     \
        (head)->tqh_circ.tql_prev->tql_next = (elm);                    \
        (head)->tqh_circ.tql_prev = &(elm)->field.tqe_circ;             \
} while (/*CONSTCOND*/0)

#define QTAILQ_INSERT_BEFORE(listelm, elm, field) do {                       \
        (elm)->field.tqe_circ.tql_prev = (listelm)->field.tqe_circ.tql_prev; \
        (elm)->field.tqe_next = (listelm);                                   \
        (listelm)->field.tqe_circ.tql_prev->tql_next = (elm);                \
        (listelm)->field.tqe_circ.tql_prev = &(elm)->field.tqe_circ;         \
} while (/*CONSTCOND*/0)

#define QTAILQ_REMOVE(head, elm, field) do {                            \
        if (((elm)->field.tqe_next) != NULL)                            \
            (elm)->field.tqe_next->field.tqe_circ.tql_prev =            \
                (elm)->field.tqe_circ.tql_prev;                         \
        else                                                            \
            (head)->tqh_circ.tql_prev = (elm)->field.tqe_circ.tql_prev; \
        (elm)->field.tqe_circ.tql_prev->tql_next = (elm)->field.tqe_next; \
        (elm)->field.tqe_circ.tql_prev = NULL;                          \
        (elm)->field.tqe_circ.tql_next = NULL;                          \
        (elm)->field.tqe_next = NULL;                                   \
} while (/*CONSTCOND*/0)

#define QTAILQ_FOREACH(var, head, field)                                \
        for ((var) = ((head)->tqh_first);                               \
                (var);                                                  \
                (var) = ((var)->field.tqe_next))

#define QTAILQ_FOREACH_SAFE(var, head, field, next_var)                 \
        for ((var) = ((head)->tqh_first);                               \
                (var) && ((next_var) = ((var)->field.tqe_next), 1);     \
                (var) = (next_var))

/*
 * Tail queue access methods.
 */
#define QTAILQ_NEXT(elm, field)          ((elm)->field.tqe_next)

#define QTAILQ_LINK_PREV(link)                                                 \
        ((link).tql_prev->tql_prev->tql_next)
#define QTAILQ_PREV(elm, headname, field)                                      \
        ((struct headname *) QTAILQ_LINK_PREV((elm)->field.tqe_circ))


#define field_at_offset(base, offset, type)                                    \
        ((type *) (((char *) (base)) + (offset)))

#endif /* QEMU_SYS_QUEUE_H */

// malloc.h
typedef enum {
    ALLOC_NO_FLAGS    = 0x00,
    ALLOC_LEAK_WARN   = 0x01,
    ALLOC_LEAK_ASSERT = 0x02,
    ALLOC_PARANOID    = 0x04
} VAllocOpts;

typedef struct MemBlock {
    QTAILQ_ENTRY(MemBlock) MLIST_ENTNAME;
    uint64_t size;
    uint64_t addr;
} MemBlock;

#define DEFAULT_PAGE_SIZE 4096
#define ALLOC_PAGE_SIZE  (4096)

typedef QTAILQ_HEAD(MemList, MemBlock) MemList;

typedef struct VGuestAllocator {
    VAllocOpts opts;
    uint64_t start;
    uint64_t end;
    uint32_t page_size;

    MemList *used;
    MemList *free;
} VGuestAllocator;

// malloc.c

static void mlist_delete(MemList *list, MemBlock *node) {
    g_assert(list && node);
    QTAILQ_REMOVE(list, node, MLIST_ENTNAME);
    g_free(node);
}

static MemBlock *mlist_find_key(MemList *head, uint64_t addr) {
    MemBlock *node;
    QTAILQ_FOREACH(node, head, MLIST_ENTNAME) {
        if (node->addr == addr) {
            return node;
        }
    }
    return NULL;
}

static MemBlock *mlist_find_space(MemList *head, uint64_t size) {
    MemBlock *node;

    QTAILQ_FOREACH(node, head, MLIST_ENTNAME) {
        if (node->size >= size) {
            return node;
        }
    }
    return NULL;
}

static MemBlock *mlist_sort_insert(MemList *head, MemBlock *insr) {
    MemBlock *node;
    g_assert(head && insr);

    QTAILQ_FOREACH(node, head, MLIST_ENTNAME) {
        if (insr->addr < node->addr) {
            QTAILQ_INSERT_BEFORE(node, insr, MLIST_ENTNAME);
            return insr;
        }
    }

    QTAILQ_INSERT_TAIL(head, insr, MLIST_ENTNAME);
    return insr;
}

static inline uint64_t mlist_boundary(MemBlock *node) {
    return node->size + node->addr;
}

static MemBlock *mlist_join(MemList *head, MemBlock *left, MemBlock *right) {
    g_assert(head && left && right);

    left->size += right->size;
    mlist_delete(head, right);
    return left;
}

static void mlist_coalesce(MemList *head, MemBlock *node) {
    g_assert(node);
    MemBlock *left;
    MemBlock *right;
    char merge;

    do {
        merge = 0;
        left = QTAILQ_PREV(node, MemBlock, MLIST_ENTNAME);
        right = QTAILQ_NEXT(node, MLIST_ENTNAME);

        /* clowns to the left of me */
        if (left && mlist_boundary(left) == node->addr) {
            node = mlist_join(head, left, node);
            merge = 1;
        }

        /* jokers to the right */
        if (right && mlist_boundary(node) == right->addr) {
            node = mlist_join(head, node, right);
            merge = 1;
        }

    } while (merge);
}

static MemBlock *mlist_new(uint64_t addr, uint64_t size) {
    MemBlock *block;

    if (!size) {
        return NULL;
    }
    block = g_new0(MemBlock, 1);

    block->addr = addr;
    block->size = size;

    return block;
}

static uint64_t mlist_fulfill(
        VGuestAllocator *s, MemBlock *freenode, uint64_t size) {
    uint64_t addr;
    MemBlock *usednode;

    g_assert(freenode);
    g_assert_cmpint(freenode->size, >=, size);

    addr = freenode->addr;
    if (freenode->size == size) {
        /* re-use this freenode as our used node */
        QTAILQ_REMOVE(s->free, freenode, MLIST_ENTNAME);
        usednode = freenode;
    } else {
        /* adjust the free node and create a new used node */
        freenode->addr += size;
        freenode->size -= size;
        usednode = mlist_new(addr, size);
    }

    mlist_sort_insert(s->used, usednode);
    return addr;
}

/* To assert the correctness of the list.
 * Used only if ALLOC_PARANOID is set. */
static void mlist_check(VGuestAllocator *s) {
    MemBlock *node;
    uint64_t addr = s->start > 0 ? s->start - 1 : 0;
    uint64_t next = s->start;

    QTAILQ_FOREACH(node, s->free, MLIST_ENTNAME) {
        g_assert_cmpint(node->addr, >, addr);
        g_assert_cmpint(node->addr, >=, next);
        addr = node->addr;
        next = node->addr + node->size;
    }

    addr = s->start > 0 ? s->start - 1 : 0;
    next = s->start;
    QTAILQ_FOREACH(node, s->used, MLIST_ENTNAME) {
        g_assert_cmpint(node->addr, >, addr);
        g_assert_cmpint(node->addr, >=, next);
        addr = node->addr;
        next = node->addr + node->size;
    }
}

static uint64_t mlist_alloc(VGuestAllocator *s, uint64_t size) {
    MemBlock *node;

    node = mlist_find_space(s->free, size);
    if (!node) {
        fprintf(stderr, "Out of guest memory.\n");
        g_assert_not_reached();
    }
    return mlist_fulfill(s, node, size);
}

static void mlist_free(VGuestAllocator *s, uint64_t addr) {
    MemBlock *node;

    if (addr == 0) {
        return;
    }

    node = mlist_find_key(s->used, addr);
    if (!node) {
        fprintf(stderr, "Error: no record found for an allocation at "
                "0x%016" PRIx64 ".\n",
                addr);
        g_assert_not_reached();
    }

    /* Rip it out of the used list and re-insert back into the free list. */
    QTAILQ_REMOVE(s->used, node, MLIST_ENTNAME);
    mlist_sort_insert(s->free, node);
    mlist_coalesce(s->free, node);
}

/*
 * Mostly for valgrind happiness, but it does offer
 * a chokepoint for debugging guest memory leaks, too.
 */
static void alloc_destroy(VGuestAllocator *allocator) {
    MemBlock *node;
    MemBlock *tmp;
    VAllocOpts mask;

    /* Check for guest leaks, and destroy the list. */
    QTAILQ_FOREACH_SAFE(node, allocator->used, MLIST_ENTNAME, tmp) {
        if (allocator->opts & (ALLOC_LEAK_WARN | ALLOC_LEAK_ASSERT)) {
            fprintf(stderr, "guest malloc leak @ 0x%016" PRIx64 "; "
                    "size 0x%016" PRIx64 ".\n",
                    node->addr, node->size);
        }
        if (allocator->opts & (ALLOC_LEAK_ASSERT)) {
            g_assert_not_reached();
        }
        g_free(node);
    }

    /* If we have previously asserted that there are no leaks, then there
     * should be only one node here with a specific address and size. */
    mask = (VAllocOpts)(ALLOC_LEAK_ASSERT | ALLOC_PARANOID);
    QTAILQ_FOREACH_SAFE(node, allocator->free, MLIST_ENTNAME, tmp) {
        if ((allocator->opts & mask) == mask) {
            if ((node->addr != allocator->start) ||
                (node->size != allocator->end - allocator->start)) {
                fprintf(stderr, "Free list is corrupted.\n");
                g_assert_not_reached();
            }
        }

        g_free(node);
    }

    g_free(allocator->used);
    g_free(allocator->free);
}

static uint64_t guest_alloc(VGuestAllocator *allocator, size_t size) {
    uint64_t rsize = size;
    uint64_t naddr;

    if (!size) {
        return 0;
    }

    rsize += (allocator->page_size - 1);
    rsize &= -allocator->page_size;
    g_assert_cmpint((allocator->start + rsize), <=, allocator->end);
    g_assert_cmpint(rsize, >=, size);

    naddr = mlist_alloc(allocator, rsize);
    if (allocator->opts & ALLOC_PARANOID) {
        mlist_check(allocator);
    }

    return naddr;
}

static void guest_free(VGuestAllocator *allocator, uint64_t addr) {
    if (!addr) {
        return;
    }
    mlist_free(allocator, addr);
    if (allocator->opts & ALLOC_PARANOID) {
        mlist_check(allocator);
    }
}

static void alloc_init(
        VGuestAllocator *s, VAllocOpts opts,
        uint64_t start, uint64_t end, size_t page_size) {
    MemBlock *node;

    s->opts = opts;
    s->start = start;
    s->end = end;

    s->used = g_new(MemList, 1);
    s->free = g_new(MemList, 1);
    QTAILQ_INIT(s->used);
    QTAILQ_INIT(s->free);

    node = mlist_new(s->start, s->end - s->start);
    QTAILQ_INSERT_HEAD(s->free, node, MLIST_ENTNAME);

    s->page_size = page_size;
}

static void alloc_set_flags(VGuestAllocator *allocator, VAllocOpts opts) {
    allocator->opts = (VAllocOpts)(allocator->opts | opts);
}

static void migrate_allocator(VGuestAllocator *src, VGuestAllocator *dst) {
    MemBlock *node, *tmp;
    MemList *tmpused, *tmpfree;

    /* The general memory layout should be equivalent,
     * though opts can differ. */
    g_assert_cmphex(src->start, ==, dst->start);
    g_assert_cmphex(src->end, ==, dst->end);

    /* Destroy (silently, regardless of options) the dest-list: */
    QTAILQ_FOREACH_SAFE(node, dst->used, MLIST_ENTNAME, tmp) {
        g_free(node);
    }
    QTAILQ_FOREACH_SAFE(node, dst->free, MLIST_ENTNAME, tmp) {
        g_free(node);
    }

    tmpused = dst->used;
    tmpfree = dst->free;

    /* Inherit the lists of the source allocator: */
    dst->used = src->used;
    dst->free = src->free;

    /* Source is now re-initialized, the source memory is 'invalid' now: */
    src->used = tmpused;
    src->free = tmpfree;
    QTAILQ_INIT(src->used);
    QTAILQ_INIT(src->free);
    node = mlist_new(src->start, src->end - src->start);
    QTAILQ_INSERT_HEAD(src->free, node, MLIST_ENTNAME);
    return;
}

static void pc_alloc_init(VGuestAllocator *s, uint64_t ram_size, VAllocOpts flags) {
    alloc_init(s, flags, 1 << 20, MIN(ram_size, 0xE0000000), ALLOC_PAGE_SIZE);
}

#endif /* VBOX_MALLOC_H */
