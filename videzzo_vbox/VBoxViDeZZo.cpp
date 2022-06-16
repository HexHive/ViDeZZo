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

/* without this, include/VBox/vmm/pdmtask.h does not import PDMTASKTYPE enum */
#define VBOX_IN_VMM 1

#include "PDMInternal.h"

/* needed by machineDebugger COM VM getter */
#include <VBox/vmm/vm.h>
#include <VBox/vmm/uvm.h>

#include <VBox/vmm/iem.h>
#include <VBox/vmm/pgm.h>
#include <VBox/vmm/iom.h>
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

#include <signal.h>
static void HandleSignal(int sig);

#include "VBoxManage.h"

#include <wordexp.h>
#include "videzzo.h"
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

bool g_fDetailedProgress = false;
HRESULT showProgress(ComPtr<IProgress> progress, uint32_t fFlags)
{
    fprintf(stderr, "VBoxViDeZZo doesn't support showProcess");
}

////////////////////////////////////////////////////////////////////////////////

#define TARGET_NAME "i386"

#include "videzzo.h"
#ifdef CLANG_COV_DUMP
#include "clangcovdump.h"
#endif

static RTUUID uuid;
static char uuid_str[64];

//
// Fuzz Target Configs
// https://www.virtualbox.org/manual/ch08.html#vboxmanage-modifyvm
//
static const ViDeZZoFuzzTargetConfig predefined_configs[] = {
    {
        .arch = "i386",
        .name = "pcnet",
        .args = "--nic1 nat --nictype1 Am79C970A",
        .file = "srv/VBox/Devices/Network/DevPCNet.cpp",
        .mrnames = "*PCnet*,*PCnet APROM*",
        .byte_address = true,
        .socket = false,
        .display = false,
    }
};

bool sockfds_initialized = false;
int sockfds[2];

static int vnc_port;
bool vnc_client_needed = false;
bool vnc_client_initialized = false;

PVMCC pVM;
PVMCPUCC pVCpu;

//
// vbox Dispatcher
//
static uint8_t vbox_readb(uint64_t addr) {
    uint8_t value;
    PGMPhysRead(pVM, addr, &value, 1, PGMACCESSORIGIN_HM);
    return value;
}

static uint16_t vbox_readw(uint64_t addr) {
    uint16_t value;
    PGMPhysRead(pVM, addr, &value, 2, PGMACCESSORIGIN_HM);
    return value;
}

static uint32_t vbox_readl(uint64_t addr) {
    uint32_t value;
    PGMPhysRead(pVM, addr, &value, 4, PGMACCESSORIGIN_HM);
    return value;
}

static uint64_t vbox_readq(uint64_t addr) {
    uint64_t value;
    PGMPhysRead(pVM, addr, &value, 8, PGMACCESSORIGIN_HM);
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
    uint32_t value;
    IOMIOPortRead(pVM, pVCpu, addr, &value, 1);
    return (uint8_t)(value & 0xff);
}

static uint16_t vbox_inw(uint16_t addr) {
    uint32_t value;
    IOMIOPortRead(pVM, pVCpu, addr, &value, 2);
    return (uint16_t)(value & 0xffff);
}

static uint32_t vbox_inl(uint16_t addr) {
    uint32_t value;
    IOMIOPortRead(pVM, pVCpu, addr, &value, 4);
    return value;
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
    PGMPhysRead(pVM, addr, data, size, PGMACCESSORIGIN_HM);
}

uint64_t dispatch_mem_read(Event *event) {
    vbox_memread(event->addr, event->data, event->size);
    return 0;
}

static void vbox_writeb(uint64_t addr, uint8_t value) {
    PGMPhysWrite(pVM, addr, &value, 1, PGMACCESSORIGIN_HM);
}

static void vbox_writew(uint64_t addr, uint16_t value) {
    PGMPhysWrite(pVM, addr, &value, 2, PGMACCESSORIGIN_HM);
}

static void vbox_writel(uint64_t addr, uint32_t value) {
    PGMPhysWrite(pVM, addr, &value, 4, PGMACCESSORIGIN_HM);
}

static void vbox_writeq(uint64_t addr, uint64_t value) {
    PGMPhysWrite(pVM, addr, &value, 8, PGMACCESSORIGIN_HM);
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
    IOMIOPortWrite(pVM, pVCpu, addr, value, 1);
}

static void vbox_outw(uint16_t addr, uint16_t value) {
    IOMIOPortWrite(pVM, pVCpu, addr, value, 2);
}

static void vbox_outl(uint16_t addr, uint32_t value) {
    IOMIOPortWrite(pVM, pVCpu, addr, value, 4);
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
    PGMPhysWrite(pVM, addr, data, size, PGMACCESSORIGIN_HM);
}

uint64_t dispatch_mem_write(Event *event) {
    vbox_memwrite(event->addr, event->data, event->size);
    return 0;
}

uint64_t dispatch_clock_step(Event *event) {
    return 0;
}

static GTimer *timer;
#define fmt_timeval "%.06f"
static void printf_qtest_prefix() {
    printf("[S +" fmt_timeval "] ", g_timer_elapsed(timer, NULL));
}

uint64_t dispatch_socket_write(Event *event) {
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
    if (physaddr < I386_MEM_HIGH - I386_MEM_LOW)
        return physaddr + I386_MEM_LOW;
    else
        return (physaddr - I386_MEM_LOW) % (I386_MEM_HIGH - I386_MEM_LOW) + I386_MEM_LOW;
}

static uint64_t videzzo_malloc(size_t size) {
    // alloc a dma accessible buffer in guest memory
    // return guest_alloc(vbox_alloc, size);
    return 0;
}

static bool videzzo_free(uint64_t addr) {
    // free the dma accessible buffer in guest memory
    // guest_free(vbox_alloc, addr);
    return true;
}

uint64_t dispatch_mem_alloc(Event *event) {
    return videzzo_malloc(event->valu);
}

uint64_t dispatch_mem_free(Event *event) {
    return videzzo_free(event->valu);
}

//
// VBox specific initialization - Set up interfaces
//

//
// call into videzzo from vbox
//
static void videzzo_vbox(void *opaque, uint8_t *Data, size_t Size) {
    /*
    QTestState *s = opaque;
    if (vnc_client_needed && !vnc_client_initialized) {
        init_vnc_client(s, vnc_port);
        vnc_client_initialized = true;
    }
    */
    videzzo_execute_one_input(Data, Size, opaque, &flush_events);
}

//
// VBox specific initialization - Usage
//
static void usage(void) {
    printf("Please specify the following environment variables:\n");
    printf("VBOX_FUZZ_ARGS= the command line arguments passed to vbox\n");
    videzzo_usage();
    exit(0);
}

//
// VBox specific initialization - Register all targets
//

// This is called in LLVMFuzzerTestOneInput
static void videzzo_vbox_pre(void *opaque) {
#ifdef CLANG_COV_DUMP
    llvm_profile_initialize_file(true);
#endif
}

// This is called in LLVMFuzzerTestOneInput
static void videzzo_vbox_post(void *opaque) {
}

// This is called in LLVMFuzzerInitialize
static GString *videzzo_vbox_cmdline(ViDeZZoFuzzTarget *t) {
    if (!getenv("VBOX_FUZZ_ARGS")) {
        usage();
    }
    GString *cmd_line = g_string_new("modifyvm");
    g_string_append_printf(cmd_line, " %s", uuid_str);
    g_string_append_printf(cmd_line, " %s", getenv("VBOX_FUZZ_ARGS"));
    return cmd_line;
}

// This is called in LLVMFuzzerInitialize
static GString *videzzo_vbox_predefined_config_cmdline(ViDeZZoFuzzTarget *t) {
    GString *args = g_string_new(NULL);
    const ViDeZZoFuzzTargetConfig *config;
    g_assert(t->opaque);
    int port = 0;

    config = (ViDeZZoFuzzTargetConfig *)t->opaque;
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
    setenv("VBOX_FUZZ_ARGS", args_str, 1);
    g_free(args_str);

    setenv("VBOX_FUZZ_MRNAME", config->mrnames, 1);
    return videzzo_vbox_cmdline(t);
}

ViDeZZoFuzzTarget generic_target = {
    .name = "videzzo-fuzz",
    .description = "Fuzz based on any VBox command-line args. ",
    .get_init_cmdline = videzzo_vbox_cmdline,
    .pre_fuzz = videzzo_vbox_pre,
    .fuzz = videzzo_vbox,
    .post_fuzz = videzzo_vbox_post
};

// This is called in LLVMFuzzerInitialize
static void register_videzzo_vbox_targets(void)
{
    videzzo_add_fuzz_target(&generic_target);
    GString *name;
    ViDeZZoFuzzTarget *target;
    const ViDeZZoFuzzTargetConfig *config;

    for (int i = 0; i < sizeof(predefined_configs) / sizeof(ViDeZZoFuzzTargetConfig); i++) {
        config = predefined_configs + i;
        if (strcmp(TARGET_NAME, config->arch) != 0)
            continue;
        name = g_string_new("videzzo-fuzz");
        g_string_append_printf(name, "-%s", config->name);
        target = (ViDeZZoFuzzTarget *)calloc(sizeof(ViDeZZoFuzzTarget), 1);
        target->name = name->str;
        target->description = "Predefined videzzo-fuzz config.";
        target->get_init_cmdline = videzzo_vbox_predefined_config_cmdline;
        target->pre_fuzz = videzzo_vbox_pre;
        target->fuzz = videzzo_vbox;
        target->post_fuzz = videzzo_vbox_post;
        target->opaque = (void *)config;
        videzzo_add_fuzz_target(target);
        free(target);
    }
}
 
int LLVMFuzzerInitialize(int *argc, char ***argv, char ***envp)
{
    char *target_name = nullptr;
    GString *generic_cmd_line = nullptr, *modifyvm_cmd_line = nullptr;
    ViDeZZoFuzzTarget *fuzz_target;
    int rc;
    HRESULT hrc;
    wordexp_t result;
    ComPtr<IVirtualBoxClient> virtualBoxClient;
    ComPtr<IVirtualBox> virtualBox;
    ComPtr<ISession> session;

    // step 1: initialize fuzz targets
    register_videzzo_vbox_targets();

    // step 2: find which fuzz target to run
    rc = parse_fuzz_target_name(argc, argv, &target_name);
    if (rc == NAME_INVALID)
        usage();

    // step 3: get the fuzz target
    fuzz_target = videzzo_get_fuzz_target(target_name);
    if (!fuzz_target) {
        usage();
    }
    save_fuzz_target(fuzz_target);
    // we make it in advance to avoid any initialization of vbox
    modifyvm_cmd_line = fuzz_target->get_init_cmdline(fuzz_target);
    
    // step 4: prepare before VBox init
    RTUuidCreate(&uuid);
    RTUuidToStr(&uuid, uuid_str, sizeof(uuid_str));
    // VBoxManage createvm --name UUID --register --basefolder `pwd`
    generic_cmd_line = g_string_new("createvm");
    g_string_append_printf(generic_cmd_line, " --name %s --register --basefolder `pwd`", uuid_str);
    wordexp(generic_cmd_line->str, &result, 0);
    g_string_free(generic_cmd_line, true);
    // Prepare RTR3 context
    RTR3InitExe(result.we_wordc, &result.we_wordv, 0);

    hrc = com::Initialize();
    hrc = virtualBoxClient.createInprocObject(CLSID_VirtualBoxClient);
    hrc = virtualBoxClient->COMGETTER(VirtualBox)(virtualBox.asOutParam());
    hrc = session.createInprocObject(CLSID_Session);

    // step 5: construct VBox init cmds and init VBox
    // VBoxManage modifyvm UUID --key1 value1 --key2 value2
    wordexp(modifyvm_cmd_line->str, &result, 0);
    g_string_free(modifyvm_cmd_line, true);
    HandlerArg handlerArg0 = {(int)result.we_wordc, result.we_wordv, virtualBox, session};
    handleModifyVM(&handlerArg0);

    generic_cmd_line = g_string_new("startvm");
    g_string_append_printf(generic_cmd_line, " %s", uuid_str);
    wordexp(generic_cmd_line->str, &result, 0);
    g_string_free(generic_cmd_line, true);
    HandlerArg handlerArg1 = {(int)result.we_wordc, result.we_wordv, virtualBox, session};
    handleStartVM(&handlerArg1);

    // step 6: clean
    session->UnlockMachine();
    NativeEventQueue::getMainEventQueue()->processEventQueue(0);
    virtualBox.setNull();
    virtualBoxClient.setNull();
    NativeEventQueue::getMainEventQueue()->processEventQueue(0);
    com::Shutdown();

    return 0;
}
