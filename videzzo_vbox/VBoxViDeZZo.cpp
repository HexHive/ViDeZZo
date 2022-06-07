/* $Id$ */
/** @file
 * VBoxViDeZZo - The VirtualBox ViDeZZo frontend for running VMs on servers.
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
 */

#include <VBox/com/com.h>
#include <VBox/com/string.h>
#include <VBox/com/array.h>
#include <VBox/com/Guid.h>
#include <VBox/com/ErrorInfo.h>
#include <VBox/com/errorprint.h>
#include <VBox/com/NativeEventQueue.h>

#include <VBox/com/VirtualBox.h>
#include <VBox/com/listeners.h>

using namespace com;

#define LOG_GROUP LOG_GROUP_GUI

#include <VBox/log.h>
#include <VBox/version.h>
#include <iprt/buildconfig.h>
#include <iprt/ctype.h>
#include <iprt/initterm.h>
#include <iprt/message.h>
#include <iprt/semaphore.h>
#include <iprt/path.h>
#include <iprt/stream.h>
#include <iprt/ldr.h>
#include <iprt/getopt.h>
#include <iprt/env.h>
#include <iprt/errcore.h>
#include <VBoxVideo.h>

#include <signal.h>
static void HandleSignal(int sig);

#include "PasswordInput.h"

////////////////////////////////////////////////////////////////////////////////

#define LogError(m,rc) \
    do { \
        Log(("VBoxViDeZZo: ERROR: " m " [rc=0x%08X]\n", rc)); \
        RTPrintf("%s\n", m); \
    } while (0)

////////////////////////////////////////////////////////////////////////////////

/* global weak references (for event handlers) */
static IConsole *gConsole = NULL;
static NativeEventQueue *gEventQ = NULL;

/* keep this handy for messages */
static com::Utf8Str g_strVMName;
static com::Utf8Str g_strVMUUID;

/* flag whether frontend should terminate */
static volatile bool g_fTerminateFE = false;

////////////////////////////////////////////////////////////////////////////////


#include "videzzo.h"
#ifdef CLANG_COV_DUMP
#include "clangcovdump.h"
#endif

//
// Fuzz Target Configs
//
static const ViDeZZoFuzzTargetConfig predefined_configs[] = {
};

static GHashTable *fuzzable_memoryregions;
static GPtrArray *fuzzable_pci_devices;
static QGuestAllocator *vbox_alloc;

bool sockfds_initialized = false;
int sockfds[2];

static int vnc_port;
bool vnc_client_needed = false;
bool vnc_client_initialized = false;

//
// vbox Dispatcher
//
static uint8_t vbox_readb(uint64_t addr) {
    uint8_t value;
    address_space_read(first_cpu->as, addr, MEMTXATTRS_UNSPECIFIED, &value, 1);
    return value;
}

static uint16_t vbox_readw(uint64_t addr) {
    uint16_t value;
    address_space_read(first_cpu->as, addr, MEMTXATTRS_UNSPECIFIED, &value, 2);
    return value;
}

static uint32_t vbox_readl(uint64_t addr) {
    uint32_t value;
    address_space_read(first_cpu->as, addr, MEMTXATTRS_UNSPECIFIED, &value, 4);
    return value;
}

static uint64_t vbox_readq(uint64_t addr) {
    uint64_t value;
    address_space_read(first_cpu->as, addr, MEMTXATTRS_UNSPECIFIED, &value, 8);
    return value;
}

uint64_t dispatch_mmio_read(Event *event) {
    switch (event->size) {
        case ViDeZZo_Byte: return vbox_readb(event->addr);
        case ViDeZZo_Word: return vbox_readw(event->addr);
        case ViDeZZo_Long: return vbox_readl(event->addr);
        case ViDeZZo_Quad: return vbox_readq(event->addr);
        default: fprintf(stderr, "wrong size of dispatch_mmio_read %d\n", event->size); return 0xffffffffffffffff;
    }
}

static uint8_t vbox_inb(uint16_t addr) {
    return cpu_inb(addr);
}

static uint16_t vbox_inw(uint16_t addr) {
    return cpu_inw(addr);
}

static uint32_t vbox_inl(uint16_t addr) {
    return cpu_inl(addr);
}

uint64_t dispatch_pio_read(Event *event) {
    switch (event->size) {
        case ViDeZZo_Byte: return vbox_inb(event->addr);
        case ViDeZZo_Word: return vbox_inw(event->addr);
        case ViDeZZo_Long: return vbox_inl(event->addr);
        default: fprintf(stderr, "wrong size of dispatch_pio_read %d\n", event->size); return 0xffffffffffffffff;
    }
}

static void vbox_memread(uint64_t addr, void *data, size_t size) {
    address_space_read(first_cpu->as, addr, MEMTXATTRS_UNSPECIFIED, data, size);
}

uint64_t dispatch_mem_read(Event *event) {
    vbox_memread(event->addr, event->data, event->size);
    return 0;
}

static void vbox_writeb(uint64_t addr, uint8_t value) {
    address_space_write(first_cpu->as, addr, MEMTXATTRS_UNSPECIFIED, &value, 1);
}

static void vbox_writew(uint64_t addr, uint16_t value) {
    address_space_write(first_cpu->as, addr, MEMTXATTRS_UNSPECIFIED, &value, 2);
}

static void vbox_writel(uint64_t addr, uint32_t value) {
    address_space_write(first_cpu->as, addr, MEMTXATTRS_UNSPECIFIED, &value, 4);
}

static void vbox_writeq(uint64_t addr, uint64_t value) {
    address_space_write(first_cpu->as, addr, MEMTXATTRS_UNSPECIFIED, &value, 8);
}

static bool xhci = false;
static bool pcnet = false;
static bool e1000e = false;
static bool vmxnet3 = false;
static bool dwc2 = false;

uint64_t dispatch_mmio_write(Event *event) {
    unsigned int pid, len;

    if (xhci && event->addr > 0xe0006100) {
        event->addr = 0xe0006000;
        event->valu = 0;
    }
    if (xhci && ((event->addr - 0xe0004020) % 0x20) == 0x8)
        event->valu = rand() % 3;
    if (pcnet && event->addr == 0xe0001010) {
        uint64_t tmp = (event->valu & 0xff) % 5;
        event->valu = (event->valu & 0xffffffffffffff00) | tmp;
    }
    if (vmxnet3 && event->addr == 0xe0002020) {
        if (rand() % 2) {
            event->valu = 0xCAFE0000 + rand() % 11;
        } else {
            event->valu = 0xF00D0000 + rand() % 10;
        }
    }
    if (dwc2 && (event->addr >= 0x3f980500) &&
            (event->addr < 0x3f980800)) {
        switch (event->addr & 0x1c) {
            case 0x0:
                // 0: 11, 11: 4, 15: 1, 16: 1, 17: 1, 18: 1
                // 18: 2, 20: 2, 22: 7, 29: 1, 30: 1, 31: 1
                event->valu = ((rand() % (1 << 11)) << 0)
                     | ((rand() % (1 << 4)) << 11)
                     | ((rand() % (1 << 1)) << 15)
                     | ((rand() % (1 << 1)) << 16)
                     | ((rand() % (1 << 1)) << 17)
                     | ((rand() % (1 << 2)) << 18)
                     | ((rand() % (1 << 2)) << 20)
                     | (0) << 22 // dwc2 -> storage.addr (0)
                     | ((rand() % (1 << 1)) << 29)
                     | ((rand() % (1 << 1)) << 30)
                     | ((rand() % (1 << 1)) << 31);
                break;
            case 0x4:
                // 0: 7, 7: 7, 14: 2, 16: 1, 17: 14, 31: 1
                event->valu = ((rand() % (1 << 7)) << 0)
                     | ((rand() % (1 << 7)) << 7)
                     | ((rand() % (1 << 2)) << 14)
                     | ((rand() % (1 << 1)) << 16)
                     | ((rand() % (1 << 14)) << 17)
                     | ((rand() % (1 << 1)) << 31);
                break;
            case 0x8:
                // 0...14, 14: 14, 18
                event->valu = ((rand() % (1 << 1)) << 0)
                     | ((rand() % (1 << 1)) << 1)
                     | ((rand() % (1 << 1)) << 2)
                     | ((rand() % (1 << 1)) << 3)
                     | ((rand() % (1 << 1)) << 4)
                     | ((rand() % (1 << 1)) << 5)
                     | ((rand() % (1 << 1)) << 6)
                     | ((rand() % (1 << 1)) << 7)
                     | ((rand() % (1 << 1)) << 8)
                     | ((rand() % (1 << 1)) << 9)
                     | ((rand() % (1 << 1)) << 10)
                     | ((rand() % (1 << 1)) << 11)
                     | ((rand() % (1 << 1)) << 12)
                     | ((rand() % (1 << 1)) << 13)
                     | ((rand() % (1 << 18)) << 14);
                break;
            case 0x10:
                // 0: 19, 19: 10, 29: 2, 31: 1
                pid = rand() % 4;
                // check and fault injection
                len = (pid == 3 ? 8 : (rand() % 2 ? 31 : rand() % (65536 + 65553)));
                event->valu = (len << 0)
                     | ((rand() % (1 << 10)) << 19)
                     | (pid << 29)
                     | ((rand() % (1 << 1)) << 31);
                break;
        }
    }
    switch (event->size) {
        case ViDeZZo_Byte: vbox_writeb(event->addr, event->valu & 0xFF); break;
        case ViDeZZo_Word: vbox_writew(event->addr, event->valu & 0xFFFF); break;
        case ViDeZZo_Long: vbox_writel(event->addr, event->valu & 0xFFFFFFFF); break;
        case ViDeZZo_Quad: vbox_writeq(event->addr, event->valu); break;
        default: fprintf(stderr, "wrong size of dispatch_mmio_write %d\n", event->size); break;
    }
    return 0;
}

static void vbox_outb(uint16_t addr, uint8_t value) {
    cpu_outb(addr, value);
}

static void vbox_outw(uint16_t addr, uint16_t value) {
    cpu_outw(addr, value);
}

static void vbox_outl(uint16_t addr, uint32_t value) {
    cpu_outl(addr, value);
}

uint64_t dispatch_pio_write(Event *event) {
    if (e1000e && event->addr == 0xc080)
        event->valu %= event->valu % 0xfffff;
    switch (event->size) {
        case ViDeZZo_Byte: vbox_outb(event->addr, event->valu & 0xFF); break;
        case ViDeZZo_Word: vbox_outw(event->addr, event->valu & 0xFFFF); break;
        case ViDeZZo_Long: vbox_outl(event->addr, event->valu & 0xFFFFFFFF); break;
        default: fprintf(stderr, "wrong size of dispatch_pio_write %d\n", event->size); break;
    }
    return 0;
}

static void vbox_memwrite(uint64_t addr, const void *data, size_t size) {
    address_space_write(first_cpu->as, addr, MEMTXATTRS_UNSPECIFIED, data, size);
}

uint64_t dispatch_mem_write(Event *event) {
    vbox_memwrite(event->addr, event->data, event->size);
    return 0;
}

uint64_t dispatch_clock_step(Event *event) {
    QTestState *s = (QTestState *)gfctx_get_object();
    qtest_clock_step(s, event->valu);
    return 0;
}

static GTimer *timer;
#define fmt_timeval "%.06f"
static void printf_qtest_prefix() {
    printf("[S +" fmt_timeval "] ", g_timer_elapsed(timer, NULL));
}

uint64_t dispatch_socket_write(Event *event) {
    uint8_t D[SOCKET_WRITE_MAX_SIZE + 4];
    uint8_t *ptr = D;
    char *enc;
    uint32_t i;
    if (!sockfds_initialized)
        return 0;
    size_t size = event->size;
    if (size > SOCKET_WRITE_MAX_SIZE)
        return 0;
    // first four bytes are lenght
    uint32_t S = htonl(size);
    memcpy(D, (uint8_t *)&S, 4);
    memcpy(D + 4, event->data, size);
    size += 4;
    int ignore = write(sockfds[0], D, size);
    // to show what a socket write did
    if (getenv("FUZZ_SERIALIZE_QTEST")) {
        enc = g_malloc(2 * size + 1);
        for (i = 0; i < size; i++) {
            sprintf(&enc[i * 2], "%02x", ptr[i]);
        }
        printf_qtest_prefix();
        printf("sock %d 0x%zx 0x%s\n", sockfds[0], size, enc);
    }
    (void) ignore;
    return 0;
}

// To avoid overlap between dyn-alloced and vbox-assumed buffers,
// where dyn-alloced buffers start from 1M,
// we enforce the dynamic alloc memory to be higher than 256M.
#define I386_MEM_LOW    0x10000000
#define I386_MEM_HIGH   0x20000000
#define RASPI2_RAM_LOW  (1 << 20)
#define RASPI2_RAM_HIGH (0x20000000)

uint64_t AroundInvalidAddress(uint64_t physaddr) {
    // TARGET_NAME=i386 -> i386/pc
    if (strcmp(TARGET_NAME, "i386") == 0) {
        if (physaddr < I386_MEM_HIGH - I386_MEM_LOW)
            return physaddr + I386_MEM_LOW;
        else
            return (physaddr - I386_MEM_LOW) % (I386_MEM_HIGH - I386_MEM_LOW) + I386_MEM_LOW;
    } else if (strcmp(TARGET_NAME, "arm") == 0) {
        return (physaddr - RASPI2_RAM_LOW) % (RASPI2_RAM_HIGH - RASPI2_RAM_LOW) + RASPI2_RAM_LOW;
    }
    return physaddr;
}

static uint64_t videzzo_malloc(size_t size) {
    // alloc a dma accessible buffer in guest memory
    return guest_alloc(vbox_alloc, size);
}

static bool videzzo_free(uint64_t addr) {
    // free the dma accessible buffer in guest memory
    guest_free(vbox_alloc, addr);
    return true;
}

uint64_t dispatch_mem_alloc(Event *event) {
    return videzzo_malloc(event->valu);
}

uint64_t dispatch_mem_free(Event *event) {
    return videzzo_free(event->valu);
}

//
// vbox specific initialization - Set up interfaces
//
// enumerate PCI devices
static inline void pci_enum(gpointer pcidev, gpointer bus) {
    PCIDevice *dev = pcidev;
    QPCIDevice *qdev;
    int i;

    qdev = qpci_device_find(bus, dev->devfn);
    g_assert(qdev != NULL);
    for (i = 0; i < 6; i++) {
        if (dev->io_regions[i].size) {
            qpci_iomap(qdev, i, NULL);
        }
    }
    qpci_device_enable(qdev);
    g_free(qdev);
}

#define INVLID_ADDRESS 0
#define   MMIO_ADDRESS 1
#define    PIO_ADDRESS 2

// parse memory region physical address
static uint8_t get_memoryregion_addr(MemoryRegion *mr, uint64_t *addr) {
    MemoryRegion *tmp_mr = mr;
    uint64_t tmp_addr = tmp_mr->addr;
    while (tmp_mr->container) {
        tmp_mr = tmp_mr->container;
        tmp_addr += tmp_mr->addr;
        if (strcmp(tmp_mr->name, "system") == 0) {
            *addr = tmp_addr;
            return MMIO_ADDRESS;
        // TODO fix me
        } else if (strcmp(tmp_mr->name, "nrf51-container") == 0) {
            *addr = tmp_addr;
            return MMIO_ADDRESS;
        } else if (strcmp(tmp_mr->name, "io") == 0) {
            *addr = tmp_addr;
            return PIO_ADDRESS;
        }
    }
    return INVLID_ADDRESS;
}

// insertion helper
static int insert_qom_composition_child(Object *obj, void *opaque) {
    g_array_append_val(opaque, obj);
    return 0;
}

// testing interface identifiction
typedef struct MemoryRegionPortioList {
    MemoryRegion mr;
    void *portio_opaque;
    MemoryRegionPortio ports[];
} MemoryRegionPortioList;

static void locate_fuzzable_objects(Object *obj, char *mrname) {
    GArray *children = g_array_new(false, false, sizeof(Object *));
    const char *name;
    MemoryRegion *mr;
    int i;

    if (obj == object_get_root()) {
        name = "";
    } else {
        name = object_get_canonical_path_component(obj);
    }

    uint64_t addr;
    uint8_t mr_type, max, min;
    uint8_t event_type1, event_type2;
    if (object_dynamic_cast(OBJECT(obj), TYPE_MEMORY_REGION)) {
        if (g_pattern_match_simple(mrname, name)) {
            mr = MEMORY_REGION(obj);
            g_hash_table_insert(fuzzable_memoryregions, mr, (gpointer)true);
            mr_type = get_memoryregion_addr(mr, &addr);
            // TODO: Improve to resolve the max/min in the future
            if (mr_type == MMIO_ADDRESS) {
                if (mr->ops->valid.min_access_size == 0 &&
                        mr->ops->valid.max_access_size == 0 &&
                        mr->ops->impl.min_access_size == 0 &&
                        mr->ops->impl.max_access_size == 0) {
                    min = 1;
                    max = 4;
                } else {
                    min = MAX(mr->ops->valid.min_access_size, mr->ops->impl.min_access_size);
                    max = MAX(mr->ops->valid.max_access_size, mr->ops->impl.max_access_size);
                }
                event_type1 = EVENT_TYPE_MMIO_READ;
                event_type2 = EVENT_TYPE_MMIO_WRITE;
            } else if (mr_type == PIO_ADDRESS) {
                MemoryRegionPortioList *mrpl = (MemoryRegionPortioList *)mr->opaque;
                if (mr->ops->valid.min_access_size == 0 &&
                        mr->ops->valid.max_access_size == 0 &&
                        mr->ops->impl.min_access_size == 0 &&
                        mr->ops->impl.max_access_size == 0 && mrpl) {
                    min = 1;
                    max = (((MemoryRegionPortio *)((MemoryRegionPortioList *)mr->opaque)->ports)[0]).size;
                    if (max == 0 || max > 4) { max = 4; }
                } else {
                    min = MAX(mr->ops->valid.min_access_size, mr->ops->impl.min_access_size);
                    max = MAX(mr->ops->valid.max_access_size, mr->ops->impl.max_access_size);
                }
                event_type1 = EVENT_TYPE_PIO_READ;
                event_type2 = EVENT_TYPE_PIO_WRITE;
            }
            // TODO: Deduplicate MemoryRegions in the future
            if (mr_type != INVLID_ADDRESS) {
                add_interface(event_type1, addr, mr->size, mr->name, min, max, true);
                add_interface(event_type2, addr, mr->size, mr->name, min, max, true);
            }
         }
     } else if(object_dynamic_cast(OBJECT(obj), TYPE_PCI_DEVICE)) {
            /*
             * Don't want duplicate pointers to the same PCIDevice, so remove
             * copies of the pointer, before adding it.
             */
            g_ptr_array_remove_fast(fuzzable_pci_devices, PCI_DEVICE(obj));
            g_ptr_array_add(fuzzable_pci_devices, PCI_DEVICE(obj));
     }

     object_child_foreach(obj, insert_qom_composition_child, children);

     for (i = 0; i < children->len; i++) {
         locate_fuzzable_objects(g_array_index(children, Object *, i), mrname);
     }
     g_array_free(children, TRUE);
}

//
// call into videzzo from vbox
//
extern "C" static void videzzo_vbox(void *opaque, uint8_t *Data, size_t Size) {
    QTestState *s = opaque;
    if (vnc_client_needed && !vnc_client_initialized) {
        init_vnc_client(s, vnc_port);
        vnc_client_initialized = true;
    }
    videzzo_execute_one_input(Data, Size, s, &flush_events);
}

//
// call into videzzo from vbox
//
size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
        size_t MaxSize, unsigned int Seed) {
    return ViDeZZoCustomMutator(Data, Size, MaxSize, Seed);
}

//
// vbox specific initialization - Usage
//
static void usage(void) {
    printf("Please specify the following environment variables:\n");
    printf("VBOX_FUZZ_ARGS= the command line arguments passed to vbox\n");
    videzzo_usage();
    exit(0);
}

//
// vbox specific initialization - LibFuzzer entries
//
static ViDeZZoFuzzTarget *fuzz_target;
static QTestState *fuzz_qts;
int LLVMFuzzerTestOneInput(unsigned char *Data, size_t Size) {
    /*
     * Do the pre-fuzz-initialization before the first fuzzing iteration,
     * instead of before the actual fuzz loop. This is needed since libfuzzer
     * may fork off additional workers, prior to the fuzzing loop, and if
     * pre_fuzz() sets up e.g. shared memory, this should be done for the
     * individual worker processes
     */
    static int pre_fuzz_done;
    if (!pre_fuzz_done && fuzz_target->pre_fuzz) {
        fuzz_target->pre_fuzz(fuzz_qts);
        pre_fuzz_done = true;
    }

    fuzz_target->fuzz(fuzz_qts, Data, Size);
    return 0;
}

static const char *fuzz_arch = TARGET_NAME;
static QTestState *qtest_setup(void) {
    qtest_server_set_send_handler(&qtest_client_inproc_recv, &fuzz_qts);
    return qtest_inproc_init(&fuzz_qts, false, fuzz_arch,
            &qtest_server_inproc_recv);
}

int LLVMFuzzerInitialize(int *argc, char ***argv, char ***envp) {
    char *target_name;
    const char *bindir;
    char *datadir;
    GString *cmd_line;

    /* Initialize qgraph and modules */
    qos_graph_init();
    module_call_init(MODULE_INIT_FUZZ_TARGET);
    module_call_init(MODULE_INIT_QOM);
    module_call_init(MODULE_INIT_LIBQOS);
    register_videzzo_vbox_targets

    vbox_init_exec_dir(**argv);
    target_name = strstr(**argv, "-target-");
    if (target_name) {        /* The binary name specifies the target */
        target_name += strlen("-target-");
        /*
         * With oss-fuzz, the executable is kept in the root of a directory (we
         * cannot assume the path). All data (including bios binaries) must be
         * in the same dir, or a subdir. Thus, we cannot place the pc-bios so
         * that it would be in exec_dir/../pc-bios.
         * As a workaround, oss-fuzz allows us to use argv[0] to get the
         * location of the executable. Using this we add exec_dir/pc-bios to
         * the datadirs.
         */
        bindir = vbox_get_exec_dir();
        datadir = g_build_filename(bindir, "pc-bios", NULL);
        if (g_file_test(datadir, G_FILE_TEST_IS_DIR)) {
            vbox_add_data_dir(datadir);
        } else {
            g_free(datadir);
        }
    } else if (*argc > 1) {  /* The target is specified as an argument */
        target_name = (*argv)[1];
        if (!strstr(target_name, "--fuzz-target=")) {
            usage();
        }
        target_name += strlen("--fuzz-target=");
    } else {
        usage();
    }

    /* Identify the fuzz target */
    fuzz_target = videzzo_get_fuzz_target(target_name);
    if (!fuzz_target) {
        usage();
    }

    fuzz_qts = qtest_setup();

    if (fuzz_target->pre_vm_init) {
        fuzz_target->pre_vm_init();
    }

    /* Run vbox's softmmu main with the fuzz-target dependent arguments */
    cmd_line = fuzz_target->get_init_cmdline(fuzz_target);
    g_string_append_printf(cmd_line, " -qtest /dev/null -qtest-log none");

    /* Split the runcmd into an argv and argc */
    wordexp_t result;
    wordexp(cmd_line->str, &result, 0);
    g_string_free(cmd_line, true);

    vbox_init(result.we_wordc, result.we_wordv, NULL);

    /* re-enable the rcu atfork, which was previously disabled in vbox_init */
    rcu_enable_atfork();

    /*
     * Disable vbox's signal handlers, since we manually control the main_loop,
     * and don't check for main_loop_should_exit
     */
    signal(SIGINT, SIG_DFL);
    signal(SIGHUP, SIG_DFL);
    signal(SIGTERM, SIG_DFL);

    return 0;
}

//
// vbox specific initialization - Register all targets
//
static QGuestAllocator *get_vbox_alloc(QTestState *qts) {
    QOSGraphNode *node;
    QOSGraphObject *obj;

    // TARGET_NAME=i386 -> i386/pc
    // TARGET_NAME=arm  -> arm/raspi2b
    if (strcmp(TARGET_NAME, "i386") == 0) {
        node = qos_graph_get_node("i386/pc");
    } else if (strcmp(TARGET_NAME, "arm") == 0) {
        node = qos_graph_get_node("arm/raspi2b");
    } else {
        g_assert(1 == 0);
    }

    g_assert(node->type == QNODE_MACHINE);

    obj = qos_machine_new(node, qts);
    qos_object_queue_destroy(obj);
    return obj->get_driver(obj, "memory");
}

// This is called in LLVMFuzzerTestOneInput
static void videzzo_vbox_pre(void *opaque) {
    QTestState *s = opaque;
    GHashTableIter iter;
    MemoryRegion *mr;
    QPCIBus *pcibus;
    char **mrnames;

    fuzzable_memoryregions = g_hash_table_new(NULL, NULL);
    fuzzable_pci_devices = g_ptr_array_new();

    mrnames = g_strsplit(getenv("vbox_FUZZ_MRNAME"), ",", -1);
    for (int i = 0; mrnames[i] != NULL; i++) {
        if (strncmp("*doorbell*", mrnames[i], strlen(mrnames[i])) == 0)
            xhci = true;
        if (strncmp("*pcnet-mmio*", mrnames[i], strlen(mrnames[i])) == 0)
            pcnet = true;
        if (strncmp("*e1000e-mmio*", mrnames[i], strlen(mrnames[i])) == 0)
            e1000e = true;
        if (strncmp("*vmxnet3-b1*", mrnames[i], strlen(mrnames[i])) == 0)
            vmxnet3 = true;
        if (strncmp("*dwc2-io*", mrnames[i], strlen(mrnames[i])) == 0)
            dwc2 = true;
        locate_fuzzable_objects(qdev_get_machine(), mrnames[i]);
    }

    if (strcmp(TARGET_NAME, "i386") == 0) {
        pcibus = qpci_new_pc(s, NULL);
        g_ptr_array_foreach(fuzzable_pci_devices, pci_enum, pcibus);
        qpci_free_pc(pcibus);
    }

    fprintf(stderr, "Matching objects by name ");
    for (int i = 0; mrnames[i] != NULL; i++) {
        fprintf(stderr, ", %s", mrnames[i]);
        locate_fuzzable_objects(qdev_get_machine(), mrnames[i]);
    }
    fprintf(stderr, "\n");
    g_strfreev(mrnames);

    fprintf(stderr, "This process will fuzz the following MemoryRegions:\n");
    g_hash_table_iter_init(&iter, fuzzable_memoryregions);
    while (g_hash_table_iter_next(&iter, (gpointer)&mr, NULL)) {
        printf("  * %s (size %lx)\n",
               object_get_canonical_path_component(&(mr->parent_obj)),
               (uint64_t)mr->size);
    }
    if (!g_hash_table_size(fuzzable_memoryregions)) {
        printf("No fuzzable memory regions found ...\n");
        exit(1);
    }

    fprintf(stderr, "This process will fuzz through the following interfaces:\n");
    if (get_number_of_interfaces() == 0) {
        printf("No fuzzable interfaces found ...\n");
        exit(2);
    } else {
        print_interfaces();
    }

    vbox_alloc = get_vbox_alloc(s);

#ifdef CLANG_COV_DUMP
    llvm_profile_initialize_file(true);
#endif
}

// This is called in LLVMFuzzerInitialize
static GString *videzzo_vbox_cmdline(ViDeZZoFuzzTarget *t) {
    GString *cmd_line = g_string_new(TARGET_NAME);
    if (!getenv("vbox_FUZZ_ARGS")) {
        usage();
    }
    g_string_append_printf(cmd_line, " -display none \
                                      -machine accel=qtest, \
                                      -m 512M %s ", getenv("vbox_FUZZ_ARGS"));
    return cmd_line;
}

// This is called in LLVMFuzzerInitialize
static GString *videzzo_vbox_predefined_config_cmdline(ViDeZZoFuzzTarget *t) {
    GString *args = g_string_new(NULL);
    const ViDeZZoFuzzTargetConfig *config;
    g_assert(t->opaque);
    int port = 0;

    config = t->opaque;
    if (config->socket && !sockfds_initialized) {
        init_sockets(sockfds);
        sockfds_initialized = true;
        port = sockfds[1];
    }
    if (config->display) {
        vnc_port = init_vnc();
        vnc_client_needed = true;
        port = remove_offset_from_vnc_port(vnc_port);
    }
    if (config->byte_address) {
        setenv("VIDEZZO_BYTE_ALIGNED_ADDRESS", "1", 1);
    }
    g_assert_nonnull(config->args);
    g_string_append_printf(args, config->args, port);
    gchar *args_str = g_string_free(args, FALSE);
    setenv("vbox_FUZZ_ARGS", args_str, 1);
    g_free(args_str);

    setenv("vbox_FUZZ_MRNAME", config->mrnames, 1);
    return videzzo_vbox_cmdline(t);
}

extern "C" static void register_videzzo_vbox_targets(void) {
    videzzo_add_fuzz_target(&(ViDeZZoFuzzTarget){
            .name = "videzzo-fuzz",
            .description = "Fuzz based on any vbox command-line args. ",
            .get_init_cmdline = videzzo_vbox_cmdline,
            .pre_fuzz = videzzo_vbox_pre,
            .fuzz = videzzo_vbox,
    });

    GString *name;
    const ViDeZZoFuzzTargetConfig *config;

    for (int i = 0; i < sizeof(predefined_configs) / sizeof(ViDeZZoFuzzTargetConfig); i++) {
        config = predefined_configs + i;
        if (strcmp(TARGET_NAME, config->arch) != 0)
            continue;
        name = g_string_new("videzzo-fuzz");
        g_string_append_printf(name, "-%s", config->name);
        videzzo_add_fuzz_target(&(ViDeZZoFuzzTarget){
                .name = name->str,
                .description = "Predefined videzzo-fuzz config.",
                .get_init_cmdline = videzzo_vbox_predefined_config_cmdline,
                .pre_fuzz = videzzo_vbox_pre,
                .fuzz = videzzo_vbox,
                .opaque = (void *)config
        });
    }
}

/**
 *  Handler for VirtualBoxClient events.
 */
class VirtualBoxClientEventListener
{
public:
    VirtualBoxClientEventListener()
    {
    }

    virtual ~VirtualBoxClientEventListener()
    {
    }

    HRESULT init()
    {
        return S_OK;
    }

    void uninit()
    {
    }

    STDMETHOD(HandleEvent)(VBoxEventType_T aType, IEvent *aEvent)
    {
        switch (aType)
        {
            case VBoxEventType_OnVBoxSVCAvailabilityChanged:
            {
                ComPtr<IVBoxSVCAvailabilityChangedEvent> pVSACEv = aEvent;
                Assert(pVSACEv);
                BOOL fAvailable = FALSE;
                pVSACEv->COMGETTER(Available)(&fAvailable);
                if (!fAvailable)
                {
                    LogRel(("VBoxViDeZZo: VBoxSVC became unavailable, exiting.\n"));
                    RTPrintf("VBoxSVC became unavailable, exiting.\n");
                    /* Terminate the VM as cleanly as possible given that VBoxSVC
                     * is no longer present. */
                    g_fTerminateFE = true;
                    gEventQ->interruptEventQueueProcessing();
                }
                break;
            }
            default:
                AssertFailed();
        }

        return S_OK;
    }

private:
};

/**
 *  Handler for machine events.
 */
class ConsoleEventListener
{
public:
    ConsoleEventListener() :
        mLastVRDEPort(-1),
        m_fIgnorePowerOffEvents(false),
        m_fNoLoggedInUsers(true)
    {
    }

    virtual ~ConsoleEventListener()
    {
    }

    HRESULT init()
    {
        return S_OK;
    }

    void uninit()
    {
    }

    STDMETHOD(HandleEvent)(VBoxEventType_T aType, IEvent *aEvent)
    {
        switch (aType)
        {
            case VBoxEventType_OnMouseCapabilityChanged:
            {

                ComPtr<IMouseCapabilityChangedEvent> mccev = aEvent;
                Assert(!mccev.isNull());

                BOOL fSupportsAbsolute = false;
                mccev->COMGETTER(SupportsAbsolute)(&fSupportsAbsolute);

                /* Emit absolute mouse event to actually enable the host mouse cursor. */
                if (fSupportsAbsolute && gConsole)
                {
                    ComPtr<IMouse> mouse;
                    gConsole->COMGETTER(Mouse)(mouse.asOutParam());
                    if (mouse)
                    {
                        mouse->PutMouseEventAbsolute(-1, -1, 0, 0 /* Horizontal wheel */, 0);
                    }
                }
                break;
            }
            case VBoxEventType_OnStateChanged:
            {
                ComPtr<IStateChangedEvent> scev = aEvent;
                Assert(scev);

                MachineState_T machineState;
                scev->COMGETTER(State)(&machineState);

                /* Terminate any event wait operation if the machine has been
                 * PoweredDown/Saved/Aborted. */
                if (machineState < MachineState_Running && !m_fIgnorePowerOffEvents)
                {
                    g_fTerminateFE = true;
                    gEventQ->interruptEventQueueProcessing();
                }

                break;
            }
            case VBoxEventType_OnVRDEServerInfoChanged:
            {
                ComPtr<IVRDEServerInfoChangedEvent> rdicev = aEvent;
                Assert(rdicev);

                if (gConsole)
                {
                    ComPtr<IVRDEServerInfo> info;
                    gConsole->COMGETTER(VRDEServerInfo)(info.asOutParam());
                    if (info)
                    {
                        LONG port;
                        info->COMGETTER(Port)(&port);
                        if (port != mLastVRDEPort)
                        {
                            if (port == -1)
                                RTPrintf("VRDE server is inactive.\n");
                            else if (port == 0)
                                RTPrintf("VRDE server failed to start.\n");
                            else
                                RTPrintf("VRDE server is listening on port %d.\n", port);

                            mLastVRDEPort = port;
                        }
                    }
                }
                break;
            }
            case VBoxEventType_OnCanShowWindow:
            {
                ComPtr<ICanShowWindowEvent> cswev = aEvent;
                Assert(cswev);
                cswev->AddVeto(NULL);
                break;
            }
            case VBoxEventType_OnShowWindow:
            {
                ComPtr<IShowWindowEvent> swev = aEvent;
                Assert(swev);
                /* Ignore the event, WinId is either still zero or some other listener assigned it. */
                NOREF(swev); /* swev->COMSETTER(WinId)(0); */
                break;
            }
            case VBoxEventType_OnGuestPropertyChanged:
            {
                ComPtr<IGuestPropertyChangedEvent> pChangedEvent = aEvent;
                Assert(pChangedEvent);

                HRESULT hrc;

                ComPtr <IMachine> pMachine;
                if (gConsole)
                {
                    hrc = gConsole->COMGETTER(Machine)(pMachine.asOutParam());
                    if (FAILED(hrc) || !pMachine)
                        hrc = VBOX_E_OBJECT_NOT_FOUND;
                }
                else
                    hrc = VBOX_E_INVALID_VM_STATE;

                if (SUCCEEDED(hrc))
                {
                    Bstr strKey;
                    hrc = pChangedEvent->COMGETTER(Name)(strKey.asOutParam());
                    AssertComRC(hrc);

                    Bstr strValue;
                    hrc = pChangedEvent->COMGETTER(Value)(strValue.asOutParam());
                    AssertComRC(hrc);

                    Utf8Str utf8Key = strKey;
                    Utf8Str utf8Value = strValue;
                    LogRelFlow(("Guest property \"%s\" has been changed to \"%s\"\n",
                                utf8Key.c_str(), utf8Value.c_str()));

                    if (utf8Key.equals("/VirtualBox/GuestInfo/OS/NoLoggedInUsers"))
                    {
                        LogRelFlow(("Guest indicates that there %s logged in users\n",
                                    utf8Value.equals("true") ? "are no" : "are"));

                        /* Check if this is our machine and the "disconnect on logout feature" is enabled. */
                        BOOL fProcessDisconnectOnGuestLogout = FALSE;

                        /* Does the machine handle VRDP disconnects? */
                        Bstr strDiscon;
                        hrc = pMachine->GetExtraData(Bstr("VRDP/DisconnectOnGuestLogout").raw(),
                                                    strDiscon.asOutParam());
                        if (SUCCEEDED(hrc))
                        {
                            Utf8Str utf8Discon = strDiscon;
                            fProcessDisconnectOnGuestLogout = utf8Discon.equals("1")
                                                            ? TRUE : FALSE;
                        }

                        LogRelFlow(("VRDE: hrc=%Rhrc: Host %s disconnecting clients (current host state known: %s)\n",
                                    hrc, fProcessDisconnectOnGuestLogout ? "will handle" : "does not handle",
                                    m_fNoLoggedInUsers ? "No users logged in" : "Users logged in"));

                        if (fProcessDisconnectOnGuestLogout)
                        {
                            bool fDropConnection = false;
                            if (!m_fNoLoggedInUsers) /* Only if the property really changes. */
                            {
                                if (   utf8Value == "true"
                                    /* Guest property got deleted due to reset,
                                     * so it has no value anymore. */
                                    || utf8Value.isEmpty())
                                {
                                    m_fNoLoggedInUsers = true;
                                    fDropConnection = true;
                                }
                            }
                            else if (utf8Value == "false")
                                m_fNoLoggedInUsers = false;
                            /* Guest property got deleted due to reset,
                             * take the shortcut without touching the m_fNoLoggedInUsers
                             * state. */
                            else if (utf8Value.isEmpty())
                                fDropConnection = true;

                            LogRelFlow(("VRDE: szNoLoggedInUsers=%s, m_fNoLoggedInUsers=%RTbool, fDropConnection=%RTbool\n",
                                        utf8Value.c_str(), m_fNoLoggedInUsers, fDropConnection));

                            if (fDropConnection)
                            {
                                /* If there is a connection, drop it. */
                                ComPtr<IVRDEServerInfo> info;
                                hrc = gConsole->COMGETTER(VRDEServerInfo)(info.asOutParam());
                                if (SUCCEEDED(hrc) && info)
                                {
                                    ULONG cClients = 0;
                                    hrc = info->COMGETTER(NumberOfClients)(&cClients);

                                    LogRelFlow(("VRDE: connected clients=%RU32\n", cClients));
                                    if (SUCCEEDED(hrc) && cClients > 0)
                                    {
                                        ComPtr <IVRDEServer> vrdeServer;
                                        hrc = pMachine->COMGETTER(VRDEServer)(vrdeServer.asOutParam());
                                        if (SUCCEEDED(hrc) && vrdeServer)
                                        {
                                            LogRel(("VRDE: the guest user has logged out, disconnecting remote clients.\n"));
                                            hrc = vrdeServer->COMSETTER(Enabled)(FALSE);
                                            AssertComRC(hrc);
                                            HRESULT hrc2 = vrdeServer->COMSETTER(Enabled)(TRUE);
                                            if (SUCCEEDED(hrc))
                                                hrc = hrc2;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if (FAILED(hrc))
                        LogRelFlow(("VRDE: returned error=%Rhrc\n", hrc));
                }

                break;
            }

            default:
                AssertFailed();
        }
        return S_OK;
    }

    void ignorePowerOffEvents(bool fIgnore)
    {
        m_fIgnorePowerOffEvents = fIgnore;
    }

private:

    long mLastVRDEPort;
    bool m_fIgnorePowerOffEvents;
    bool m_fNoLoggedInUsers;
};

typedef ListenerImpl<VirtualBoxClientEventListener> VirtualBoxClientEventListenerImpl;
typedef ListenerImpl<ConsoleEventListener> ConsoleEventListenerImpl;

VBOX_LISTENER_DECLARE(VirtualBoxClientEventListenerImpl)
VBOX_LISTENER_DECLARE(ConsoleEventListenerImpl)

static void
HandleSignal(int sig)
{
    RT_NOREF(sig);
    LogRel(("VBoxViDeZZo: received singal %d\n", sig));
    g_fTerminateFE = true;
}

////////////////////////////////////////////////////////////////////////////////

static void show_usage()
{
    RTPrintf("Usage:\n"
             "   -s, -startvm, --startvm <name|uuid>   Start given VM (required argument)\n"
             "   -v, -vrde, --vrde on|off|config       Enable or disable the VRDE server\n"
             "                                           or don't change the setting (default)\n"
             "   -e, -vrdeproperty, --vrdeproperty <name=[value]> Set a VRDE property:\n"
             "                                     \"TCP/Ports\" - comma-separated list of\n"
             "                                       ports the VRDE server can bind to; dash\n"
             "                                       between two port numbers specifies range\n"
             "                                     \"TCP/Address\" - interface IP the VRDE\n"
             "                                       server will bind to\n"
             "   --settingspw <pw>                 Specify the VirtualBox settings password\n"
             "   --settingspwfile <file>           Specify a file containing the\n"
             "                                       VirtualBox settings password\n"
             "   --password <file>|-               Specify the VM password. Either file containing\n"
             "                                     the VM password or \"-\" to read it from console\n"
             "   --password-id <id>                Specify the password id for the VM password\n"
             "   -start-paused, --start-paused     Start the VM in paused state\n"
             "\n");
}

/*
 * Simplified version of showProgress() borrowed from VBoxManage.
 * Note that machine power up/down operations are not cancelable, so
 * we don't bother checking for signals.
 */
HRESULT
showProgress(const ComPtr<IProgress> &progress)
{
    BOOL fCompleted = FALSE;
    ULONG ulLastPercent = 0;
    ULONG ulCurrentPercent = 0;
    HRESULT hrc;

    com::Bstr bstrDescription;
    hrc = progress->COMGETTER(Description(bstrDescription.asOutParam()));
    if (FAILED(hrc))
    {
        RTStrmPrintf(g_pStdErr, "Failed to get progress description: %Rhrc\n", hrc);
        return hrc;
    }

    RTStrmPrintf(g_pStdErr, "%ls: ", bstrDescription.raw());
    RTStrmFlush(g_pStdErr);

    hrc = progress->COMGETTER(Completed(&fCompleted));
    while (SUCCEEDED(hrc))
    {
        progress->COMGETTER(Percent(&ulCurrentPercent));

        /* did we cross a 10% mark? */
        if (ulCurrentPercent / 10  >  ulLastPercent / 10)
        {
            /* make sure to also print out missed steps */
            for (ULONG curVal = (ulLastPercent / 10) * 10 + 10; curVal <= (ulCurrentPercent / 10) * 10; curVal += 10)
            {
                if (curVal < 100)
                {
                    RTStrmPrintf(g_pStdErr, "%u%%...", curVal);
                    RTStrmFlush(g_pStdErr);
                }
            }
            ulLastPercent = (ulCurrentPercent / 10) * 10;
        }

        if (fCompleted)
            break;

        gEventQ->processEventQueue(500);
        hrc = progress->COMGETTER(Completed(&fCompleted));
    }

    /* complete the line. */
    LONG iRc = E_FAIL;
    hrc = progress->COMGETTER(ResultCode)(&iRc);
    if (SUCCEEDED(hrc))
    {
        if (SUCCEEDED(iRc))
            RTStrmPrintf(g_pStdErr, "100%%\n");
        else
        {
            RTStrmPrintf(g_pStdErr, "\n");
            RTStrmPrintf(g_pStdErr, "Operation failed: %Rhrc\n", iRc);
        }
        hrc = iRc;
    }
    else
    {
        RTStrmPrintf(g_pStdErr, "\n");
        RTStrmPrintf(g_pStdErr, "Failed to obtain operation result: %Rhrc\n", hrc);
    }
    RTStrmFlush(g_pStdErr);
    return hrc;
}


/**
 *  Entry point.
 */
extern "C" DECLEXPORT(int) TrustedMain(int argc, char **argv, char **envp)
{
    RT_NOREF(envp);
    const char *vrdePort = NULL;
    const char *vrdeAddress = NULL;
    const char *vrdeEnabled = NULL;
    unsigned cVRDEProperties = 0;
    const char *aVRDEProperties[16];
    unsigned fPaused = 0;

    LogFlow(("VBoxViDeZZo STARTED.\n"));
    RTPrintf(VBOX_PRODUCT " ViDeZZo Interface " VBOX_VERSION_STRING "\n"
             "(C) 2008-" VBOX_C_YEAR " " VBOX_VENDOR "\n"
             "All rights reserved.\n\n");

    enum eViDeZZoOptions
    {
        OPT_SETTINGSPW = 0x100,
        OPT_SETTINGSPW_FILE,
        OPT_COMMENT,
        OPT_PAUSED,
        OPT_VMPW,
        OPT_VMPWID
    };

    static const RTGETOPTDEF s_aOptions[] =
    {
        { "-startvm", 's', RTGETOPT_REQ_STRING },
        { "--startvm", 's', RTGETOPT_REQ_STRING },
        { "-vrdpport", 'p', RTGETOPT_REQ_STRING },     /* VRDE: deprecated. */
        { "--vrdpport", 'p', RTGETOPT_REQ_STRING },    /* VRDE: deprecated. */
        { "-vrdpaddress", 'a', RTGETOPT_REQ_STRING },  /* VRDE: deprecated. */
        { "--vrdpaddress", 'a', RTGETOPT_REQ_STRING }, /* VRDE: deprecated. */
        { "-vrdp", 'v', RTGETOPT_REQ_STRING },         /* VRDE: deprecated. */
        { "--vrdp", 'v', RTGETOPT_REQ_STRING },        /* VRDE: deprecated. */
        { "-vrde", 'v', RTGETOPT_REQ_STRING },
        { "--vrde", 'v', RTGETOPT_REQ_STRING },
        { "-vrdeproperty", 'e', RTGETOPT_REQ_STRING },
        { "--vrdeproperty", 'e', RTGETOPT_REQ_STRING },
        { "--settingspw", OPT_SETTINGSPW, RTGETOPT_REQ_STRING },
        { "--settingspwfile", OPT_SETTINGSPW_FILE, RTGETOPT_REQ_STRING },
        { "--password", OPT_VMPW, RTGETOPT_REQ_STRING },
        { "--password-id", OPT_VMPWID, RTGETOPT_REQ_STRING },
        { "-comment", OPT_COMMENT, RTGETOPT_REQ_STRING },
        { "--comment", OPT_COMMENT, RTGETOPT_REQ_STRING },
        { "-start-paused", OPT_PAUSED, 0 },
        { "--start-paused", OPT_PAUSED, 0 }
    };

    const char *pcszNameOrUUID = NULL;

    // parse the command line
    int ch;
    const char *pcszSettingsPw = NULL;
    const char *pcszSettingsPwFile = NULL;
    const char *pcszVmPassword = NULL;
    const char *pcszVmPasswordId = NULL;
    RTGETOPTUNION ValueUnion;
    RTGETOPTSTATE GetState;
    RTGetOptInit(&GetState, argc, argv, s_aOptions, RT_ELEMENTS(s_aOptions), 1, 0 /* fFlags */);
    while ((ch = RTGetOpt(&GetState, &ValueUnion)))
    {
        switch(ch)
        {
            case 's':
                pcszNameOrUUID = ValueUnion.psz;
                break;
            case 'p':
                RTPrintf("Warning: '-p' or '-vrdpport' are deprecated. Use '-e \"TCP/Ports=%s\"'\n", ValueUnion.psz);
                vrdePort = ValueUnion.psz;
                break;
            case 'a':
                RTPrintf("Warning: '-a' or '-vrdpaddress' are deprecated. Use '-e \"TCP/Address=%s\"'\n", ValueUnion.psz);
                vrdeAddress = ValueUnion.psz;
                break;
            case 'v':
                vrdeEnabled = ValueUnion.psz;
                break;
            case 'e':
                if (cVRDEProperties < RT_ELEMENTS(aVRDEProperties))
                    aVRDEProperties[cVRDEProperties++] = ValueUnion.psz;
                else
                     RTPrintf("Warning: too many VRDE properties. Ignored: '%s'\n", ValueUnion.psz);
                break;
            case OPT_SETTINGSPW:
                pcszSettingsPw = ValueUnion.psz;
                break;
            case OPT_SETTINGSPW_FILE:
                pcszSettingsPwFile = ValueUnion.psz;
                break;
            case OPT_VMPW:
                pcszVmPassword = ValueUnion.psz;
                break;
            case OPT_VMPWID:
                pcszVmPasswordId = ValueUnion.psz;
                break;
            case OPT_PAUSED:
                fPaused = true;
                break;
            case 'h':
                show_usage();
                return 0;
            case OPT_COMMENT:
                /* nothing to do */
                break;
            case 'V':
                RTPrintf("%sr%s\n", RTBldCfgVersion(), RTBldCfgRevisionStr());
                return 0;
            default:
                ch = RTGetOptPrintError(ch, &ValueUnion);
                show_usage();
                return ch;
        }
    }

    if (!pcszNameOrUUID)
    {
        show_usage();
        return 1;
    }

    HRESULT rc;
    int irc;

    rc = com::Initialize();
#ifdef VBOX_WITH_XPCOM
    if (rc == NS_ERROR_FILE_ACCESS_DENIED)
    {
        char szHome[RTPATH_MAX] = "";
        com::GetVBoxUserHomeDirectory(szHome, sizeof(szHome));
        RTPrintf("Failed to initialize COM because the global settings directory '%s' is not accessible!", szHome);
        return 1;
    }
#endif
    if (FAILED(rc))
    {
        RTPrintf("VBoxViDeZZo: ERROR: failed to initialize COM!\n");
        return 1;
    }

    ComPtr<IVirtualBoxClient> pVirtualBoxClient;
    ComPtr<IVirtualBox> virtualBox;
    ComPtr<ISession> session;
    ComPtr<IMachine> machine;
    bool fSessionOpened = false;
    ComPtr<IEventListener> vboxClientListener;
    ComPtr<IEventListener> vboxListener;
    ComObjPtr<ConsoleEventListenerImpl> consoleListener;

    do
    {
        rc = pVirtualBoxClient.createInprocObject(CLSID_VirtualBoxClient);
        if (FAILED(rc))
        {
            RTPrintf("VBoxViDeZZo: ERROR: failed to create the VirtualBoxClient object!\n");
            com::ErrorInfo info;
            if (!info.isFullAvailable() && !info.isBasicAvailable())
            {
                com::GluePrintRCMessage(rc);
                RTPrintf("Most likely, the VirtualBox COM server is not running or failed to start.\n");
            }
            else
                GluePrintErrorInfo(info);
            break;
        }

        rc = pVirtualBoxClient->COMGETTER(VirtualBox)(virtualBox.asOutParam());
        if (FAILED(rc))
        {
            RTPrintf("Failed to get VirtualBox object (rc=%Rhrc)!\n", rc);
            break;
        }
        rc = pVirtualBoxClient->COMGETTER(Session)(session.asOutParam());
        if (FAILED(rc))
        {
            RTPrintf("Failed to get session object (rc=%Rhrc)!\n", rc);
            break;
        }

        if (pcszSettingsPw)
        {
            CHECK_ERROR(virtualBox, SetSettingsSecret(Bstr(pcszSettingsPw).raw()));
            if (FAILED(rc))
                break;
        }
        else if (pcszSettingsPwFile)
        {
            int rcExit = settingsPasswordFile(virtualBox, pcszSettingsPwFile);
            if (rcExit != RTEXITCODE_SUCCESS)
                break;
        }

        ComPtr<IMachine> m;

        rc = virtualBox->FindMachine(Bstr(pcszNameOrUUID).raw(), m.asOutParam());
        if (FAILED(rc))
        {
            LogError("Invalid machine name or UUID!\n", rc);
            break;
        }

        /* add VM password if required */
        if (pcszVmPassword && pcszVmPasswordId)
        {
            com::Utf8Str strPassword;
            if (!RTStrCmp(pcszVmPassword, "-"))
            {
                /* Get password from console. */
                RTEXITCODE rcExit = readPasswordFromConsole(&strPassword, "Enter the password:");
                if (rcExit == RTEXITCODE_FAILURE)
                    break;
            }
            else
            {
                RTEXITCODE rcExit = readPasswordFile(pcszVmPassword, &strPassword);
                if (rcExit != RTEXITCODE_SUCCESS)
                    break;
            }
            CHECK_ERROR_BREAK(m, AddEncryptionPassword(Bstr(pcszVmPasswordId).raw(),
                                                       Bstr(strPassword).raw()));
        }
        Bstr bstrVMId;
        rc = m->COMGETTER(Id)(bstrVMId.asOutParam());
        AssertComRC(rc);
        if (FAILED(rc))
            break;
        g_strVMUUID = bstrVMId;

        Bstr bstrVMName;
        rc = m->COMGETTER(Name)(bstrVMName.asOutParam());
        AssertComRC(rc);
        if (FAILED(rc))
            break;
        g_strVMName = bstrVMName;

        Log(("VBoxViDeZZo: Opening a session with machine (id={%s})...\n",
             g_strVMUUID.c_str()));

        // set session name
        CHECK_ERROR_BREAK(session, COMSETTER(Name)(Bstr("headless").raw()));
        // open a session
        CHECK_ERROR_BREAK(m, LockMachine(session, LockType_VM));
        fSessionOpened = true;

        /* get the console */
        ComPtr<IConsole> console;
        CHECK_ERROR_BREAK(session, COMGETTER(Console)(console.asOutParam()));

        /* get the mutable machine */
        CHECK_ERROR_BREAK(console, COMGETTER(Machine)(machine.asOutParam()));

        ComPtr<IDisplay> display;
        CHECK_ERROR_BREAK(console, COMGETTER(Display)(display.asOutParam()));

        /* initialize global references */
        gConsole = console;
        gEventQ = com::NativeEventQueue::getMainEventQueue();

        /* VirtualBoxClient events registration. */
        {
            ComPtr<IEventSource> pES;
            CHECK_ERROR(pVirtualBoxClient, COMGETTER(EventSource)(pES.asOutParam()));
            ComObjPtr<VirtualBoxClientEventListenerImpl> listener;
            listener.createObject();
            listener->init(new VirtualBoxClientEventListener());
            vboxClientListener = listener;
            com::SafeArray<VBoxEventType_T> eventTypes;
            eventTypes.push_back(VBoxEventType_OnVBoxSVCAvailabilityChanged);
            CHECK_ERROR(pES, RegisterListener(vboxClientListener, ComSafeArrayAsInParam(eventTypes), true));
        }

        /* Console events registration. */
        {
            ComPtr<IEventSource> es;
            CHECK_ERROR(console, COMGETTER(EventSource)(es.asOutParam()));
            consoleListener.createObject();
            consoleListener->init(new ConsoleEventListener());
            com::SafeArray<VBoxEventType_T> eventTypes;
            eventTypes.push_back(VBoxEventType_OnMouseCapabilityChanged);
            eventTypes.push_back(VBoxEventType_OnStateChanged);
            eventTypes.push_back(VBoxEventType_OnVRDEServerInfoChanged);
            eventTypes.push_back(VBoxEventType_OnCanShowWindow);
            eventTypes.push_back(VBoxEventType_OnShowWindow);
            eventTypes.push_back(VBoxEventType_OnGuestPropertyChanged);
            CHECK_ERROR(es, RegisterListener(consoleListener, ComSafeArrayAsInParam(eventTypes), true));
        }

        /* Default is to use the VM setting for the VRDE server. */
        enum VRDEOption
        {
            VRDEOption_Config,
            VRDEOption_Off,
            VRDEOption_On
        };
        VRDEOption enmVRDEOption = VRDEOption_Config;
        BOOL fVRDEEnabled;
        ComPtr <IVRDEServer> vrdeServer;
        CHECK_ERROR_BREAK(machine, COMGETTER(VRDEServer)(vrdeServer.asOutParam()));
        CHECK_ERROR_BREAK(vrdeServer, COMGETTER(Enabled)(&fVRDEEnabled));

        if (vrdeEnabled != NULL)
        {
            /* -vrde on|off|config */
            if (!strcmp(vrdeEnabled, "off") || !strcmp(vrdeEnabled, "disable"))
                enmVRDEOption = VRDEOption_Off;
            else if (!strcmp(vrdeEnabled, "on") || !strcmp(vrdeEnabled, "enable"))
                enmVRDEOption = VRDEOption_On;
            else if (strcmp(vrdeEnabled, "config"))
            {
                RTPrintf("-vrde requires an argument (on|off|config)\n");
                break;
            }
        }

        Log(("VBoxViDeZZo: enmVRDE %d, fVRDEEnabled %d\n", enmVRDEOption, fVRDEEnabled));

        if (enmVRDEOption != VRDEOption_Off)
        {
            /* Set other specified options. */

            /* set VRDE port if requested by the user */
            if (vrdePort != NULL)
            {
                Bstr bstr = vrdePort;
                CHECK_ERROR_BREAK(vrdeServer, SetVRDEProperty(Bstr("TCP/Ports").raw(), bstr.raw()));
            }
            /* set VRDE address if requested by the user */
            if (vrdeAddress != NULL)
            {
                CHECK_ERROR_BREAK(vrdeServer, SetVRDEProperty(Bstr("TCP/Address").raw(), Bstr(vrdeAddress).raw()));
            }

            /* Set VRDE properties. */
            if (cVRDEProperties > 0)
            {
                for (unsigned i = 0; i < cVRDEProperties; i++)
                {
                    /* Parse 'name=value' */
                    char *pszProperty = RTStrDup(aVRDEProperties[i]);
                    if (pszProperty)
                    {
                        char *pDelimiter = strchr(pszProperty, '=');
                        if (pDelimiter)
                        {
                            *pDelimiter = '\0';

                            Bstr bstrName = pszProperty;
                            Bstr bstrValue = &pDelimiter[1];
                            CHECK_ERROR_BREAK(vrdeServer, SetVRDEProperty(bstrName.raw(), bstrValue.raw()));
                        }
                        else
                        {
                            RTPrintf("Error: Invalid VRDE property '%s'\n", aVRDEProperties[i]);
                            RTStrFree(pszProperty);
                            rc = E_INVALIDARG;
                            break;
                        }
                        RTStrFree(pszProperty);
                    }
                    else
                    {
                        RTPrintf("Error: Failed to allocate memory for VRDE property '%s'\n", aVRDEProperties[i]);
                        rc = E_OUTOFMEMORY;
                        break;
                    }
                }
                if (FAILED(rc))
                    break;
            }

        }

        if (enmVRDEOption == VRDEOption_On)
        {
            /* enable VRDE server (only if currently disabled) */
            if (!fVRDEEnabled)
            {
                CHECK_ERROR_BREAK(vrdeServer, COMSETTER(Enabled)(TRUE));
            }
        }
        else if (enmVRDEOption == VRDEOption_Off)
        {
            /* disable VRDE server (only if currently enabled */
            if (fVRDEEnabled)
            {
                CHECK_ERROR_BREAK(vrdeServer, COMSETTER(Enabled)(FALSE));
            }
        }

        /* Disable the host clipboard before powering up */
        console->COMSETTER(UseHostClipboard)(false);

        Log(("VBoxViDeZZo: Powering up the machine...\n"));


        /**
         * @todo We should probably install handlers earlier so that
         * we can undo any temporary settings we do above in case of
         * an early signal and use RAII to ensure proper cleanup.
         */
        signal(SIGPIPE, SIG_IGN);
        signal(SIGTTOU, SIG_IGN);

        struct sigaction sa;
        RT_ZERO(sa);
        sa.sa_handler = HandleSignal;
        sigaction(SIGHUP,  &sa, NULL);
        sigaction(SIGINT,  &sa, NULL);
        sigaction(SIGTERM, &sa, NULL);
        sigaction(SIGUSR1, &sa, NULL);
        /* Don't touch SIGUSR2 as IPRT could be using it for RTThreadPoke(). */

        ComPtr <IProgress> progress;
        if (!fPaused)
            CHECK_ERROR_BREAK(console, PowerUp(progress.asOutParam()));
        else
            CHECK_ERROR_BREAK(console, PowerUpPaused(progress.asOutParam()));

        rc = showProgress(progress);
        if (FAILED(rc))
        {
            com::ProgressErrorInfo info(progress);
            if (info.isBasicAvailable())
            {
                RTPrintf("Error: failed to start machine. Error message: %ls\n", info.getText().raw());
            }
            else
            {
                RTPrintf("Error: failed to start machine. No error message available!\n");
            }
            break;
        }

        /*
         * Pump vbox events forever
         */
        LogRel(("VBoxViDeZZo: starting event loop\n"));
        for (;;)
        {
            irc = gEventQ->processEventQueue(RT_INDEFINITE_WAIT);

            /*
             * interruptEventQueueProcessing from another thread is
             * reported as VERR_INTERRUPTED, so check the flag first.
             */
            if (g_fTerminateFE)
            {
                LogRel(("VBoxViDeZZo: processEventQueue: %Rrc, termination requested\n", irc));
                break;
            }

            if (RT_FAILURE(irc))
            {
                LogRel(("VBoxViDeZZo: processEventQueue: %Rrc\n", irc));
                RTMsgError("event loop: %Rrc", irc);
                break;
            }
        }

        Log(("VBoxViDeZZo: event loop has terminated...\n"));

        /* we don't have to disable VRDE here because we don't save the settings of the VM */
    }
    while (0);

    /*
     * Get the machine state.
     */
    MachineState_T machineState = MachineState_Aborted;
    if (!machine.isNull())
    {
        rc = machine->COMGETTER(State)(&machineState);
        if (SUCCEEDED(rc))
            Log(("machine state = %RU32\n", machineState));
        else
            Log(("IMachine::getState: %Rhrc\n", rc));
    }
    else
    {
        Log(("machine == NULL\n"));
    }

    /*
     * Turn off the VM if it's running
     */
    if (   gConsole
        && (   machineState == MachineState_Running
            || machineState == MachineState_Teleporting
            || machineState == MachineState_LiveSnapshotting
            /** @todo power off paused VMs too? */
           )
       )
    do
    {
        consoleListener->getWrapped()->ignorePowerOffEvents(true);

        ComPtr<IProgress> pProgress;
        if (!machine.isNull())
            CHECK_ERROR_BREAK(machine, SaveState(pProgress.asOutParam()));
        else
            CHECK_ERROR_BREAK(gConsole, PowerDown(pProgress.asOutParam()));

        rc = showProgress(pProgress);
        if (FAILED(rc))
        {
            com::ErrorInfo info;
            if (!info.isFullAvailable() && !info.isBasicAvailable())
                com::GluePrintRCMessage(rc);
            else
                com::GluePrintErrorInfo(info);
            break;
        }
    } while (0);

    /* VirtualBox callback unregistration. */
    if (vboxListener)
    {
        ComPtr<IEventSource> es;
        CHECK_ERROR(virtualBox, COMGETTER(EventSource)(es.asOutParam()));
        if (!es.isNull())
            CHECK_ERROR(es, UnregisterListener(vboxListener));
        vboxListener.setNull();
    }

    /* Console callback unregistration. */
    if (consoleListener)
    {
        ComPtr<IEventSource> es;
        CHECK_ERROR(gConsole, COMGETTER(EventSource)(es.asOutParam()));
        if (!es.isNull())
            CHECK_ERROR(es, UnregisterListener(consoleListener));
        consoleListener.setNull();
    }

    /* VirtualBoxClient callback unregistration. */
    if (vboxClientListener)
    {
        ComPtr<IEventSource> pES;
        CHECK_ERROR(pVirtualBoxClient, COMGETTER(EventSource)(pES.asOutParam()));
        if (!pES.isNull())
            CHECK_ERROR(pES, UnregisterListener(vboxClientListener));
        vboxClientListener.setNull();
    }

    /* No more access to the 'console' object, which will be uninitialized by the next session->Close call. */
    gConsole = NULL;

    if (fSessionOpened)
    {
        /*
         * Close the session. This will also uninitialize the console and
         * unregister the callback we've registered before.
         */
        Log(("VBoxViDeZZo: Closing the session...\n"));
        session->UnlockMachine();
    }

    /* Must be before com::Shutdown */
    session.setNull();
    virtualBox.setNull();
    pVirtualBoxClient.setNull();
    machine.setNull();

    com::Shutdown();

    LogRel(("VBoxViDeZZo: exiting\n"));
    return FAILED(rc) ? 1 : 0;
}

#ifndef VBOX_WITH_HARDENING
int LLVMFuzzerInitialize(int *argc, char ***argv, char ***envp)
{
    int rc = RTR3InitExe(*argc, argv, RTR3INIT_FLAGS_TRY_SUPLIB);
    if (RT_SUCCESS(rc)) {
        rc = TrustedMain(argc, argv, envp);
        if 
        return 0;
    } else {
        RTPrintf("VBoxViDeZZo: Runtime initialization failed: %Rrc - %Rrf\n", rc, rc);
        return 1;
    }
}
#endif /* !VBOX_WITH_HARDENING */
