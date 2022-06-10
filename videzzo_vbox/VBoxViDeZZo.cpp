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

/* flag whether frontend should terminate */
static volatile bool g_fTerminateFE = false;

////////////////////////////////////////////////////////////////////////////////

#define TARGET_NAME "i386"

#include "videzzo.h"
#ifdef CLANG_COV_DUMP
#include "clangcovdump.h"
#endif

//
// Fuzz Target Configs
//
static const ViDeZZoFuzzTargetConfig predefined_configs[] = {
    {
        .arch = "i386",
        .name = "pcnet",
        .args = "-machine q35 -nodefaults "
        "-device pcnet,netdev=net0 -netdev user,id=net0",
        .mrnames = "*pcnet-mmio*,*pcnet-io*",
        .file = "srv/VBox/Devices/Network/DevPCNet.cpp",
        .socket = true,
        .byte_address = true,
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
// call into videzzo from vbox
//
size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
        size_t MaxSize, unsigned int Seed) {
    return ViDeZZoCustomMutator(Data, Size, MaxSize, Seed);
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
// VBox specific initialization - LibFuzzer entries
//
static ViDeZZoFuzzTarget *fuzz_target;
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
        fuzz_target->pre_fuzz(NULL);
        pre_fuzz_done = true;
    }

    fuzz_target->fuzz(NULL, Data, Size);
    return 0;
}

static const char *fuzz_arch = TARGET_NAME;

//
// VBox specific initialization - Register all targets
//

// This is called in LLVMFuzzerTestOneInput
static void videzzo_vbox_pre(void *opaque) {
#ifdef CLANG_COV_DUMP
    llvm_profile_initialize_file(true);
#endif
}

static void videzzo_vbox_init_pre(void) { }

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
    setenv("vbox_FUZZ_ARGS", args_str, 1);
    g_free(args_str);

    setenv("vbox_FUZZ_MRNAME", config->mrnames, 1);
    return videzzo_vbox_cmdline(t);
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


// This is called in LLVMFuzzerInitialize
static int VBoxViDeZZoMain(int argc, char **argv, char **envp)
{
    RT_NOREF(envp);
    const char *vrdePort = NULL;
    const char *vrdeAddress = NULL;
    const char *vrdeEnabled = NULL;
    unsigned cVRDEProperties = 0;
    const char *aVRDEProperties[16];
    unsigned fPaused = 0;

    LogFlow(("VBoxViDeZZo STARTED.\n"));

    static const RTGETOPTDEF s_aOptions[] =
    {
        { "-startvm", 's', RTGETOPT_REQ_STRING },
        { "--startvm", 's', RTGETOPT_REQ_STRING },
    };
    const char *pcszNameOrUUID = NULL;

    // parse the command line
    int ch;
    RTGETOPTUNION ValueUnion;
    RTGETOPTSTATE GetState;
    RTGetOptInit(&GetState, argc, argv, s_aOptions, RT_ELEMENTS(s_aOptions), 1, /*fFlags=*/0);
    ch = RTGetOpt(&GetState, &ValueUnion);
    Assert(ch == 's');
    pcszNameOrUUID = ValueUnion.psz;
    if (!pcszNameOrUUID) return 1;

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

        ComPtr<IMachine> m;

        rc = virtualBox->FindMachine(Bstr(pcszNameOrUUID).raw(), m.asOutParam());
        if (FAILED(rc))
        {
            LogError("Invalid machine name or UUID!\n", rc);
            break;
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
        CHECK_ERROR_BREAK(session, COMSETTER(Name)(Bstr("ViDeZZo").raw()));
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
        CHECK_ERROR_BREAK(console, PowerUp(progress.asOutParam()));

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
    }
    while (0);
    return 0;
}

ViDeZZoFuzzTarget generic_target = {
    .name = "videzzo-fuzz",
    .description = "Fuzz based on any VBox command-line args. ",
    .get_init_cmdline = videzzo_vbox_cmdline,
    .pre_vm_init = videzzo_vbox_init_pre,
    .pre_fuzz = videzzo_vbox_pre,
    .fuzz = videzzo_vbox,
};

// This is called in LLVMFuzzerInitialize
static void register_videzzo_vbox_targets(void) {
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
        target->pre_vm_init = videzzo_vbox_init_pre;
        target->pre_fuzz = videzzo_vbox_pre;
        target->fuzz = videzzo_vbox;
        target->opaque = (void *)config;
        videzzo_add_fuzz_target(target);
    }
}
 
int LLVMFuzzerInitialize(int *argc, char ***argv, char ***envp)
{
    char *target_name = nullptr;
    int rc;

    // step 1: initialize fuzz targets
    register_videzzo_vbox_targets();

    // step 2: find which fuzz target to run
    rc = parse_fuzz_target_name(argc, argv, target_name);
    if (rc == NAME_INVALID)
        usage();

    // step 3: get the fuzz target
    fuzz_target = videzzo_get_fuzz_target(target_name);
    if (!fuzz_target) {
        usage();
    }
    
    // step 4: run callback before VBox init
    if (fuzz_target->pre_vm_init) {
        fuzz_target->pre_vm_init();
    }

    // step 5: construct VBox init cmds and init VBox
    // TODO: any cmds construction
    rc = RTR3InitExe(*argc, argv, RTR3INIT_FLAGS_TRY_SUPLIB);
    if (RT_SUCCESS(rc)) {
        rc = VBoxViDeZZoMain(*argc, *argv, *envp);
        if (RT_FAILURE(rc)) {
            RTPrintf("VBoxViDeZZo: VBoxViDeZZoMain failed: %Rrc - %Rrf\n", rc, rc);
            return 1;
        }
        // TODO: any signal hooking
        return 0;
    } else {
        RTPrintf("VBoxViDeZZo: Runtime initialization failed: %Rrc - %Rrf\n", rc, rc);
        return 1;
    }
}
