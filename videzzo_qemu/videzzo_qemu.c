/*
 * Type-Aware Virtual Device Fuzzing
 *
 * Copyright Red Hat Inc., 2021
 *
 * Authors: Qiang Liu <cyruscyliu@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 */
#include "videzzo_qemu.h"
#include "videzzo.h"
#ifdef CLANG_COV_DUMP
#include "clangcovdump.h"
#endif

//
// QEMU Dispatcher
//
uint64_t dispatch_mmio_read(Event *event) {
    QTestState *s = (QTestState *)gfctx_get_object();
    switch (event->size) {
        case ViDeZZo_Byte: return qtest_readb(s, event->addr);
        case ViDeZZo_Word: return qtest_readw(s, event->addr);
        case ViDeZZo_Long: return qtest_readl(s, event->addr);
        case ViDeZZo_Quad: return qtest_readq(s, event->addr);
        default: fprintf(stderr, "wrong size of dispatch_mmio_read %d\n", event->size); return 0xffffffffffffffff;
    }
}

uint64_t dispatch_pio_read(Event *event) {
    QTestState *s = (QTestState *)gfctx_get_object();
    switch (event->size) {
        case ViDeZZo_Byte: return qtest_inb(s, event->addr);
        case ViDeZZo_Word: return qtest_inw(s, event->addr);
        case ViDeZZo_Long: return qtest_inl(s, event->addr);
        default: fprintf(stderr, "wrong size of dispatch_pio_read %d\n", event->size); return 0xffffffffffffffff;
    }
}

uint64_t dispatch_mem_read(Event *event) {
    QTestState *s = (QTestState *)gfctx_get_object();
    qtest_memread(s, event->addr, event->data, event->size);
    return 0;
}

uint64_t dispatch_mmio_write(Event *event) {
    QTestState *s = (QTestState *)gfctx_get_object();
    switch (event->size) {
        case ViDeZZo_Byte: qtest_writeb(s, event->addr, event->valu & 0xFF); break;
        case ViDeZZo_Word: qtest_writew(s, event->addr, event->valu & 0xFFFF); break;
        case ViDeZZo_Long: qtest_writel(s, event->addr, event->valu & 0xFFFFFFFF); break;
        case ViDeZZo_Quad: qtest_writeq(s, event->addr, event->valu); break;
        default: fprintf(stderr, "wrong size of dispatch_mmio_write %d\n", event->size); break;
    }
    return 0;
}

uint64_t dispatch_pio_write(Event *event) {
    QTestState *s = (QTestState *)gfctx_get_object();
    switch (event->size) {
        case ViDeZZo_Byte: qtest_outb(s, event->addr, event->valu & 0xFF); break;
        case ViDeZZo_Word: qtest_outw(s, event->addr, event->valu & 0xFFFF); break;
        case ViDeZZo_Long: qtest_outl(s, event->addr, event->valu & 0xFFFFFFFF); break;
        default: fprintf(stderr, "wrong size of dispatch_pio_write %d\n", event->size); break;
    }
    return 0;
}

uint64_t dispatch_mem_write(Event *event) {
    QTestState *s = (QTestState *)gfctx_get_object();
    qtest_memwrite(s, event->addr, event->data, event->size);
    return 0;
}

uint64_t dispatch_clock_step(Event *event) {
    QTestState *s = (QTestState *)gfctx_get_object();
    qtest_clock_step(s, event->valu);
    return 0;
}

#define fmt_timeval "%ld.%06ld"
void qtest_get_time(qemu_timeval *tv);
static void printf_qtest_prefix()
{
    qemu_timeval tv;
    qtest_get_time(&tv);
    printf("[r +" fmt_timeval "] ",
            (long) tv.tv_sec, (long) tv.tv_usec);
}

uint64_t dispatch_socket_write(Event *event) {
    QTestState *s = (QTestState *)gfctx_get_object();
    uint8_t D[SOCKET_WRITE_MAX_SIZE + 4];
    uint8_t *ptr = &D;
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

uint64_t AroundInvalidAddress(uint64_t physaddr) {
    // TARGET_NAME=i386 -> i386/pc
    if (strncmp(TARGET_NAME, "i386", 4) == 0) {
        if (physaddr < I386_MEM_HIGH - I386_MEM_LOW)
            return physaddr + I386_MEM_LOW;
        else
            return (physaddr - I386_MEM_LOW) % (I386_MEM_HIGH - I386_MEM_LOW) + I386_MEM_LOW;
    }
    return physaddr;
}

uint64_t dispatch_mem_alloc(Event *event) {
    QTestState *s = (QTestState *)gfctx_get_object();
    return videzzo_malloc(event->valu);
}

uint64_t dispatch_mem_free(Event *event) {
    QTestState *s = (QTestState *)gfctx_get_object();
    return videzzo_free(event->valu);
}


//
// QEMU specific initialization - Set up interfaces
//
// enumerate PCI devices
static inline void pci_enum(gpointer pcidev, gpointer bus)
{
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
static int insert_qom_composition_child(Object *obj, void *opaque)
{
    g_array_append_val(opaque, obj);
    return 0;
}

// testing interface identifiction
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

static void videzzo_qemu_pre(QTestState *s) {
    GHashTableIter iter;
    MemoryRegion *mr;
    QPCIBus *pcibus;
    char **mrnames;
    ViDeZZoFuzzer = 1;

    if (getenv("QTEST_LOG")) {
        qtest_log_enabled = 1;
    }
    if (getenv("QEMU_FUZZ_TIMEOUT")) {
        timeout = g_ascii_strtoll(getenv("QEMU_FUZZ_TIMEOUT"), NULL, 0);
    }

    fuzzable_memoryregions = g_hash_table_new(NULL, NULL);
    fuzzable_pci_devices = g_ptr_array_new();

    mrnames = g_strsplit(getenv("QEMU_FUZZ_MRNAME"), ",", -1);
    for (int i = 0; mrnames[i] != NULL; i++) {
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

    videzzo_alloc = get_videzzo_alloc(s);
    counter_shm_init();

#ifdef CLANG_COV_DUMP
    llvm_profile_initialize_file(true);
#endif
}

//
// QEMU specific initialization - Show usage
//
static void usage(void) {
    printf("Please specify the following environment variables:\n");
    printf("QEMU_FUZZ_ARGS= the command line arguments passed to qemu\n");
    printf("QEMU_FUZZ_OBJECTS= "
            "a space separated list of QOM type names for objects to fuzz\n");
    printf("Optionally: QEMU_FUZZ_TIMEOUT= Specify a custom timeout (us). "
            "0 to disable. %d by default\n", timeout);
    exit(0);
}

//
// call into videzzo from QEMU
//
static void videzzo_qemu(QTestState *s, uint8_t *Data, size_t Size) {
    if (vnc_client_needed && !vnc_client_initialized) {
        init_vnc_client(s);
    }
    videzzo_execute_one_input(Data, Size, s, &flush_events);
}

//
// call into videzzo from QEMU
//
size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
        size_t MaxSize, unsigned int Seed) {
    // for generic fuzz targets
    if (!ViDeZZoFuzzer)
        return LLVMFuzzerMutate(Data, Size, MaxSize);

    return ViDeZZoCustomMutator(Data, Size, MaxSize, Seed);
}

//
// QEMU specific initialization - Register all targets
//
static void register_videzzo_qemu_targets(void) {
    fuzz_add_target(&(FuzzTarget){
            .name = "videzzo-fuzz",
            .description = "Fuzz based on any qemu command-line args. ",
            .get_init_cmdline = videzzo_qemu_cmdline,
            .pre_fuzz = videzzo_qemu_pre,
            .fuzz = videzzo_qemu,
    });

    GString *name;
    const videzzo_qemu_config *config;

    for (int i = 0;
         i < sizeof(predefined_configs) / sizeof(videzzo_qemu_config);
         i++) {
        config = predefined_configs + i;
        if (strcmp(TARGET_NAME, config->arch) != 0)
            continue;
        name = g_string_new("videzzo-fuzz");
        g_string_append_printf(name, "-%s", config->name);
        fuzz_add_target(&(FuzzTarget){
                .name = name->str,
                .description = "Predefined videzzo-fuzz config.",
                .get_init_cmdline = videzzo_qemu_predefined_config_cmdline,
                .pre_fuzz = videzzo_qemu_pre,
                .fuzz = videzzo_qemu,
                .opaque = (void *)config
        });
    }
}

fuzz_target_init(register_videzzo_qemu_targets);
