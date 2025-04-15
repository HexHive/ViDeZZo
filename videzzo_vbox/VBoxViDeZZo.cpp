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

#include "VBoxManage.h"

#include <wordexp.h>
#include "videzzo.h"
#include "videzzo_fork.h"

/* without this, include/VBox/vmm/pdmtask.h does not import PDMTASKTYPE enum */
#define VBOX_IN_VMM 1

#include "PDMInternal.h"
#include "IOMInternal.h" // must be in front of vm.h
#include "VMInternal.h" // must be in front of uvm.h

/* needed by machineDebugger COM VM getter */
#include <VBox/vmm/vm.h>
#include <VBox/vmm/uvm.h>
#include <VBox/vmm/vmmr3vtable.h>
#include <VBox/vmm/vmcc.h>

////////////////////////////////////////////////////////////////////////////////

#define LogError(m,rc) \
    do { \
        Log(("VBoxViDeZZo: ERROR: " m " [rc=0x%08X]\n", rc)); \
        RTPrintf("%s\n", m); \
    } while (0)

////////////////////////////////////////////////////////////////////////////////

static NativeEventQueue *gEventQ = NULL;

#define TARGET_NAME "i386"

#include "videzzo.h"
#include "VBoxMalloc.h"

static RTUUID uuid;
static char uuid_str[64];

static PVM pVM;
static PVMCPUCC pVCpu;
static ComPtr<IMachine> machine;
static ComPtr<IConsole> console;
static VGuestAllocator vbox_malloc;

//
// Fuzz Target Configs
// https://www.virtualbox.org/manual/ch08.html#vboxmanage-modifyvm
//
// Unhandled DMA channels
// - DevSB16.cpp, Dev3C501.cpp, DevDP8390.cpp, DevFdc.cpp
// Skipped devices
// - PDMDEVREG g_DeviceIommuAmd
// - PDMDEVREG g_DevicePCI
// - PDMDEVREG g_DevicePCIBridge
// - PDMDEVREG g_DevicePciIch9
// - PDMDEVREG g_DevicePciIch9Bridge
// - PDMDEVREG g_DeviceLPC
// - PDMDEVREG g_DeviceEFI
// - PDMDEVREG g_DeviceFlash
// - PDMDEVREG g_DeviceSmc (Apple System Management Controller)
// - PDMDEVREG g_DeviceGIMDev (Guest Interface Manager Device)
// - PDMDEVREG g_DeviceVirtualKD (Device stub/loader for fast Windows kernel-mode debugging)
// - PDMDEVREG g_DeviceINIP (Internal Network IP stack device/service)
// - PDMDEVREG g_DevicePlayground (debug purpose)
// - PDMDEVREG g_DeviceSample (debug purpose)
// - PDMDEVREG g_DeviceQemuFwCfg (debug purpose)
// Confusing devices
// - PDMDEVREG g_DeviceVirtioNet
// - PDMDEVREG g_DeviceOxPcie958
// - PDMDEVREG g_DeviceVirtioSCSI
// - PDMDEVREG g_DeviceBusMouse
static const ViDeZZoFuzzTargetConfig predefined_configs[] = {
    {
        .arch = "i386",
        .name = "hda",
        .args = "--audio-controller=hda --memory 2048",
        .file = "src/VBox/Devices/Audio/DevHda.cpp",
        .mrnames = "*HDA*",
        .byte_address = true,
        .socket = false,
        .display = false,
    }, {
        .arch = "i386",
        .name = "ac97",
        .args = "--audio-controller=ac97 --memory 2048",
        .file = "src/VBox/Devices/Audio/DevIchAc97.cpp",
        .mrnames = "*ICHAC97 NAM*,*ICHAC97 NABM*",
        .byte_address = true,
        .socket = false,
        .display = false,
    }, {
        .arch = "i386",
        .name = "sb16",
        .args = "--audio-controller=sb16 --memory 2048",
        .file = "src/VBox/Devices/Audio/DevSB16.cpp",
        .mrnames = "*SB16 - Mixer*,*SB16 - DSP*,*DMA*",
        .byte_address = true,
        .socket = false,
        .display = false,
    }, {
        .arch = "i386",
        .name = "vga",
        .args = "--graphicscontroller=vmsvga --memory 2048", // vboxvga, vmsvga, and vboxsvga share this
        .file = "src/VBox/Devices/Graphics/DevVGA.cpp",
        .mrnames = "*VRam*,*VGA*", // *VMSVGA*
        .byte_address = false, // TODO: PIO and MMIO should be seperated!
        .socket = false,
        .display = false,
    }, {
        .arch = "i386",
        .name = "pckbd",
        .args = "--keyboard ps2 --memory 2048",
        .file = "src/VBox/Devices/Input/DevPS2.cpp",
        .mrnames = "*PC Keyboard - Data*,*PC Keyboard - Command / Status*",
        .byte_address = true,
        .socket = false,
        .display = false,
    }, {
        .arch = "i386",
        .name = "3c501",
        .args = "--nic1 nat --nictype1 3C501 --memory 2048",
        .file = "src/VBox/Devices/Network/Dev3C501.cpp",
        .mrnames = "*3C501*",
        .byte_address = true,
        .socket = false,
        .display = false,
    }, {
        .arch = "i386",
        .name = "ne2000", // ne1000 and ne2000 share this
        .args = "--nic1 nat --nictype1 NE2000 --memory 2048",
        .file = "src/VBox/Devices/Network/DevDP8390.cpp",
        .mrnames = "*DP8390-Core*,*DPNIC-NE*",
        .byte_address = true,
        .socket = false,
        .display = false,
    }, {
        .arch = "i386",
        .name = "wd8013", // wd8003 and wd8013 share this
        .args = "--nic1 nat --nictype1 WD8013 --memory 2048",
        .file = "src/VBox/Devices/Network/DevDP8390.cpp",
        .mrnames = "*DPNIC-WD*,*DP8390-Core*,*DPNIC - WD Shared RAM*",
        .byte_address = true,
        .socket = false,
        .display = false,
    }, {
        .arch = "i386",
        .name = "3c503",
        .args = "--nic1 nat --nictype1 3C503 --memory 2048",
        .file = "src/VBox/Devices/Network/DevDP8390.cpp",
        .mrnames = "*DP8390-Core*,*DPNIC-EL*,*DPNIC - 3C503 Shared RAM*",
        .byte_address = true,
        .socket = false,
        .display = false,
    }, {
        .arch = "i386",
        .name = "e1000", // 82540EM, 82543GC, and 82545EM share this
        .args = "--nic1 nat --nictype1 82540EM --memory 2048",
        .file = "src/VBox/Devices/Network/DevE1000.cpp",
        .mrnames = "*E1000*",
        .byte_address = true,
        .socket = false,
        .display = false,
    }, {
        .arch = "i386",
        .name = "pcnet", // Am79C970A, Am79C973, and Am79C960 share this
        .args = "--nic1 nat --nictype1 Am79C970A --memory 2048",
        .file = "srv/VBox/Devices/Network/DevPCNet.cpp",
        .mrnames = "*PCnet*,*PCnet APROM*",
        .byte_address = true,
        .socket = false,
        .display = false,
    }, /* { // I do not have a parallel port ...
        .arch = "i386",
        .name = "parallel",
        .args = "--lptmode1 \"/dev/parport3\" --lpt1 0x378 7",
        .file = "src/VBox/Devices/Parallel/DevParallel.cpp",
        .mrnames = "*Parallel*,*Parallel ECP*",
        .byte_address = true,
        .socket = false,
        .display = false,
    }, */ {
        .arch = "i386",
        .name = "acpi",
        .args = "--acpi on --memory 2048",
        .file = "src/VBox/Devices/PC/DevACPI.cpp",
        .mrnames = "*ACPI*",
        .byte_address = true,
        .socket = false,
        .display = false,
    }, {
        .arch = "i386",
        .name = "dma",
        .args = "--memory 2048",
        .file = "src/VBox/Devices/PC/DevDMA.cpp",
        .mrnames = "*DMA*",
        .byte_address = true,
        .socket = false,
        .display = false,
    }, {
        .arch = "i386",
        .name = "hpet",
        .args = "--hpet on --memory 2048",
        .file = "src/VBox/Devices/PC/DevHPET.cpp",
        .mrnames = "*HPET Memory*",
        .byte_address = false,
        .socket = false,
        .display = false,
    }, {
        .arch = "i386",
        .name = "ioapic",
        .args = "--ioapic on --memory 2048",
        .file = "src/VBox/Devices/PC/DevIoApic.cpp",
        .mrnames = "*APIC*",
        .byte_address = false,
        .socket = false,
        .display = false,
    }, {
        .arch = "i386",
        .name = "pcarch",
        .args = "--memory 2048",
        .file = "src/VBox/Devices/PC/DevPcArch.cpp",
        .mrnames = "*Math Co-Processor (DOS/OS2 mode)*,*PS/2 system control port A (A20 and more)*",
        .byte_address = true,
        .socket = false,
        .display = false,
    }, {
        .arch = "i386",
        .name = "pcbios",
        .args = "--memory 2048",
        .file = "src/VBox/Devices/PC/DevPcBios.cpp",
        .mrnames = "*Bochs PC BIOS*",
        .byte_address = true,
        .socket = false,
        .display = false,
    }, {
        .arch = "i386",
        .name = "i8259",
        .args = "--memory 2048",
        .file = "src/VBox/Devices/PC/DevPIC.cpp",
        .mrnames = "*i8259*",
        .byte_address = true,
        .socket = false,
        .display = false,
    }, {
        .arch = "i386",
        .name = "i8254",
        .args = "--memory 2048",
        .file = "src/VBox/Devices/PC/DevPit-i8254.cpp",
        .mrnames = "*i8254*",
        .byte_address = true,
        .socket = false,
        .display = false,
    }, {
        .arch = "i386",
        .name = "rtc",
        .args = "--memory 2048",
        .file = "src/VBox/Devices/PC/DevRTC.cpp",
        .mrnames = "*MC146818*",
        .byte_address = true,
        .socket = false,
        .display = false,
    }, {
        .arch = "i386",
        .name = "tpm",
        .args = "--tpm-type 2.0 --memory 2048", // 1.2, 2.0, host and swtpm share this
        .file = "src/VBox/Devices/Security/DevTpm.cpp",
        .mrnames = "*TPM MMIO*",
        .byte_address = false,
        .socket = false,
        .display = false,
    }, {
        .arch = "i386",
        .name = "serial",
        .args = "--uart1 0x3f8 4 --uartmode1 disconnected --uarttype1 16550A --memory 2048", // 16450, 16550A, and 16750 share this
        .file = "src/VBox/Devices/Serial/DevSerial.cpp",
        .mrnames = "*SERIAL*",
        .byte_address = true,
        .socket = false,
        .display = false,
    }, {
        // for those storage devices
        // this makes it clear
        // BUS TYPE: ide, sata, scsi, floppy, sas, usb, and pcie
        // CONTROLLER CHIPSET TYPE:
        // LSILogic, LSILogicSAS, BusLogic, IntelAhci, PIIX3, PIIX4, ICH6, I82078, USB, NVMe, and VirtIO
        // however, a usb is mapped to a certain controller
        .arch = "i386",
        .name = "ahci",
        .args = "--sata on --memory 2048", // sata: IntelAhci
        .file = "src/VBox/Devices/Storage/DevAHCI.cpp",
        .mrnames = "*AHCI*",
        .byte_address = true,
        .socket = false,
        .display = false,
    }, /* { // TODO
        .arch = "i386",
        .name = "piix3ide",
        .args = "--hda --idecontroller PIIX3", // ide: PIIX3, PIIX4 and ICH6
        .file = "src/VBox/Devices/Storage/DevATA.cpp",
        .mrnames = "*ATA*",
        .byte_address = true,
        .socket = false,
        .display = false,
    }, */ {
        .arch = "i386",
        .name = "buslogic",
        .args = "--scsi on --scsitype BusLogic --memory 2048", // scsi: BusLogic
        .file = "src/VBox/Devices/Storage/DevBusLogic.cpp",
        .mrnames = "*BusLogic*",
        .byte_address = true,
        .socket = false,
        .display = false,
    }, {
        .arch = "i386",
        .name = "floppy",
        .args = nullptr,
        .file = "src/VBox/Devices/Storage/DevFdc.cpp",
        .mrnames = "*FDC*,*DMA*",
        .byte_address = true,
        .socket = false,
        .display = false,
    }, {
        .arch = "i386",
        .name = "lsilogicscsi",
        .args = "--scsi on --scsitype LsiLogic --memory 2048", // scsi: LsiLogic; LsiLogic and siLogicSAS share this
        .file = "src/VBox/Devices/Storage/DevLsiLogicSCSI.cpp",
        .mrnames = "*LsiLogic*",
        .byte_address = true,
        .socket = false,
        .display = false,
    }, {
        .arch = "i386",
        .name = "ohci",
        .args = "--usbohci on --memory 2048",
        .file = "src/VBox/Devices/USB/DevOHCI.cpp",
        .mrnames = "*USB OHCI*",
        .byte_address = false,
        .socket = false,
        .display = false,
    }, {
        .arch = "i386",
        .name = "vboxvmm",
        .args = "--memory 2048",
        .file = "src/VBox/Devices/VMMDev/VMMDev.cpp",
        .mrnames = "*VMMDev*",
        .byte_address = true,
        .socket = false,
        .display = false,
    }, {
        .arch = "i386",
        .name = "apic",
        .args = "--memory 2048",
        .file = "src/VBox/VMM/VMMAll/APICAll.cpp",
        .mrnames = "*APIC*",
        .byte_address = false,
        .socket = false,
        .display = false,
    }
};

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
    switch (__disimm_around_event_size(event->size, 8)) {
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
    switch (__disimm_around_event_size(event->size, 4)) {
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

static bool pcnet = false;
static bool e1000e = false;
static bool vmxnet3 = false;
static bool dwc2 = false;

uint64_t dispatch_mmio_write(Event *event) {
    unsigned int pid, len;

    if ((!DisableInputProcessing) && pcnet && event->addr == 0xe0001010) {
        uint64_t tmp = rand() % 5;
        event->valu = (event->valu & 0xffffffffffffff00) | tmp;
    }
    if ((!DisableInputProcessing) && vmxnet3 && event->addr == 0xe0002020) {
        if (rand() % 2) {
            event->valu = 0xCAFE0000 + rand() % 11;
        } else {
            event->valu = 0xF00D0000 + rand() % 10;
        }
    }
    if ((!DisableInputProcessing) && dwc2 && (event->addr >= 0x3f980500) &&
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

    switch (__disimm_around_event_size(event->size, 8)) {
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
    switch (__disimm_around_event_size(event->size, 4)) {
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

__attribute__ ((visibility ("default"))) uint64_t AroundInvalidAddress(uint64_t physaddr) {
    // TARGET_NAME=i386 -> i386/pc
    if (physaddr < I386_MEM_HIGH - I386_MEM_LOW)
        return physaddr + I386_MEM_LOW;
    else
        return (physaddr - I386_MEM_LOW) % (I386_MEM_HIGH - I386_MEM_LOW) + I386_MEM_LOW;
}

static uint64_t videzzo_malloc(size_t size) {
    // alloc a dma accessible buffer in guest memory
    return guest_alloc(&vbox_malloc, size);
}

static bool videzzo_free(uint64_t addr) {
    // free the dma accessible buffer in guest memory
    guest_free(&vbox_malloc, addr);
    return true;
}

uint64_t dispatch_mem_alloc(Event *event) {
    return videzzo_malloc(event->valu);
}

uint64_t dispatch_mem_free(Event *event) {
    return videzzo_free(event->valu);
}

void flush_events(void *opaque) {
    gEventQ->processEventQueue(0);
}

//
// call into videzzo from vbox
//
static int videzzo_vbox(uint8_t *Data, size_t Size) {
    /*
    QTestState *s = opaque;
    if (vnc_client_needed && !vnc_client_initialized) {
        init_vnc_client(s, vnc_port);
        vnc_client_initialized = true;
    }
    */
    return videzzo_execute_one_input(Data, Size, pVM, &flush_events);
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
// VBox specific initialization - Set up interfaces
// VBox specific initialization - Register all targets
//
static GHashTable *fuzzable_pioregions;
static GHashTable *fuzzable_mmioregions;

void locate_fuzzable_objects(char *mrname) {
    PPDMDEVINS pDevIns;
    PVM internalPVM;
    PPDMPCIDEV pPciDev;
    int i;
    uint64_t addr;
    uint32_t size;
    uint8_t min, max;

    for (pDevIns = pVM->pdm.s.pDevInstances;
            pDevIns; pDevIns = pDevIns->Internal.s.pNextR3) {
        // set bus master bit
        pPciDev = pDevIns->apPciDevs[0];
        if (pPciDev != NULL) {
            PDMPciDevSetCommand(pPciDev, PDMPciDevGetCommand(pPciDev) | VBOX_PCI_COMMAND_MASTER);
        }
        internalPVM = pDevIns->Internal.s.pVMR3;
        // PIO
        for (i = 0; i < internalPVM->iom.s.cIoPortRegs; i++) {
            PIOMIOPORTENTRYR3 pRegEntry_PIO = &(internalPVM->iom.s.paIoPortRegs[i]);
            if (g_pattern_match_simple(mrname, pRegEntry_PIO->pszDesc)) {
                g_hash_table_insert(fuzzable_pioregions, pRegEntry_PIO, (gpointer)true);
                if (!pRegEntry_PIO->fMapped)
                    continue;
                addr = pRegEntry_PIO->uPort;
                size = pRegEntry_PIO->cPorts;
                if (!interface_exists(EVENT_TYPE_PIO_READ, addr, size)) {
                    add_interface(EVENT_TYPE_PIO_READ, addr, size, pRegEntry_PIO->pszDesc, 1, 4, true);
                    add_interface(EVENT_TYPE_PIO_WRITE, addr, size, pRegEntry_PIO->pszDesc, 1, 4, true);
                }
            }
        }
        // MMIO
        for (i = 0; i < internalPVM->iom.s.cMmioRegs; i++) {
            PIOMMMIOENTRYR3 pRegEntry_MMIO = &(internalPVM->iom.s.paMmioRegs[i]);
            if (g_pattern_match_simple(mrname, pRegEntry_MMIO->pszDesc)) {
                g_hash_table_insert(fuzzable_mmioregions, pRegEntry_MMIO, (gpointer)true);
                if (!pRegEntry_MMIO->fMapped)
                    continue;
                addr = pRegEntry_MMIO->GCPhysMapping;
                size = pRegEntry_MMIO->cbRegion;
                if (!interface_exists(EVENT_TYPE_MMIO_READ, addr, size)) {
                    add_interface(EVENT_TYPE_MMIO_READ, addr, size, pRegEntry_MMIO->pszDesc, 1, 4, true);
                    add_interface(EVENT_TYPE_MMIO_WRITE, addr, size, pRegEntry_MMIO->pszDesc, 1, 4, true);
                }
            }
        }
    }
}

// This is called in LLVMFuzzerTestOneInput
static void videzzo_vbox_pre() {
    GHashTableIter iter;
    char **mrnames;

    fuzzable_pioregions = g_hash_table_new(NULL, NULL);
    fuzzable_mmioregions = g_hash_table_new(NULL, NULL);

    // step 1: find target memory regions
    fprintf(stderr, "Matching objects by name ");

    // enumeration: we have to implement a small BIOS to
    // enumerate all devicess as we choose PowerUpPaused
    // !!!pretend to be EMT!!!
    PUVMCPU pUVCpu = pVCpu->pUVCpu;
    PUVM pUVM = pUVCpu->pUVM;
    int rc = RTTlsSet(pUVM->vm.s.idxTLS, pUVCpu);
    // pci_bios_init_device
    IOMIOPortWrite(pVM, pVCpu, 0x0410, 19200509, 4);

    mrnames = g_strsplit(getenv("VBOX_FUZZ_MRNAME"), ",", -1);
    for (int i = 0; mrnames[i] != NULL; i++) {
        fprintf(stderr, ", %s", mrnames[i]);
        locate_fuzzable_objects(mrnames[i]);
    }
    fprintf(stderr, "\n");
    g_strfreev(mrnames);

    fprintf(stderr, "This process will fuzz the following MemoryRegions:\n");
    g_hash_table_iter_init(&iter, fuzzable_pioregions);
    PIOMIOPORTENTRYR3 pRegEntry_PIO;
    while (g_hash_table_iter_next(&iter, (gpointer *)&pRegEntry_PIO, NULL)) {
        printf("  * %s (size %lx)\n", pRegEntry_PIO->pDevIns->pReg->szName, (uint64_t)pRegEntry_PIO->cPorts);
    }
    g_hash_table_iter_init(&iter, fuzzable_mmioregions);
    PIOMMMIOENTRYR3 pRegEntry_MMIO;
    while (g_hash_table_iter_next(&iter, (gpointer *)&pRegEntry_MMIO, NULL)) {
        printf("  * %s (size %lx)\n", pRegEntry_MMIO->pDevIns->pReg->szName, (uint64_t)pRegEntry_MMIO->cbRegion);
    }

    if (g_hash_table_size(fuzzable_pioregions) == 0 &&
            g_hash_table_size(fuzzable_mmioregions) == 0) {
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
    
    // step 2: get allocator
    pc_alloc_init(&vbox_malloc, 2 * 1024 * 1024 * 1024, ALLOC_NO_FLAGS);

    // step 3: get VM to be running
    pVM->enmVMState = VMSTATE_RUNNING;

    if (getenv("VIDEZZO_FORK")) {
        counter_shm_init();
    }
}

static ComPtr<IVirtualBoxClient> virtualBoxClient;
static ComPtr<IVirtualBox> virtualBox;
static ComPtr<ISession> session;

// This is called in LLVMFuzzerInitialize
static GString *videzzo_vbox_cmdline(ViDeZZoFuzzTarget *t) {
    if (!getenv("VBOX_FUZZ_ARGS")) {
        usage();
    }
    GString *cmd_line = g_string_new(NULL);
    g_string_append_printf(cmd_line, "%s %s", uuid_str, getenv("VBOX_FUZZ_ARGS"));
    return cmd_line;
}

// This is called in LLVMFuzzerInitialize
static GString *videzzo_vbox_predefined_config_cmdline(ViDeZZoFuzzTarget *t) {
    GString *args = g_string_new(NULL);
    const ViDeZZoFuzzTargetConfig *config;
    g_assert(t->opaque);
    int port = 0;

    config = (ViDeZZoFuzzTargetConfig *)t->opaque;
    setenv("VBOX_FUZZ_MRNAME", config->mrnames, 1);
    if (config->byte_address) {
        setenv("VIDEZZO_BYTE_ALIGNED_ADDRESS", "1", 1);
    }
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
    if (config->args == nullptr) {
        g_string_free(args, true);
        return nullptr;
    }
    g_assert_nonnull(config->args);
    g_string_append_printf(args, config->args, port);
    gchar *args_str = g_string_free(args, FALSE);
    setenv("VBOX_FUZZ_ARGS", args_str, 1);
    g_free(args_str);

    return videzzo_vbox_cmdline(t);
}

ViDeZZoFuzzTarget generic_target = {
    .name = "videzzo-fuzz",
    .description = "Fuzz based on any VBox command-line args. ",
    .get_init_cmdline = videzzo_vbox_cmdline,
    .pre_fuzz = videzzo_vbox_pre,
    .fuzz = videzzo_vbox,
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
        target->opaque = (void *)config;
        videzzo_add_fuzz_target(target);
        free(target);
    }
}
 
// This is called in LLVMFuzzerInitialize
bool g_fDetailedProgress = false;
// we have to override this: defined in VBoxManage.h
HRESULT showProgress(ComPtr<IProgress> progress, uint32_t fFlags) {
    fprintf(stderr, "VBoxViDeZZo doesn't support showProcess");
}
// we are going to use this: copyed from VBoxHeadless
HRESULT showProgress1(const ComPtr<IProgress> &progress) {
    BOOL fCompleted = FALSE;
    ULONG ulLastPercent = 0;
    ULONG ulCurrentPercent = 0;
    HRESULT hrc;

    com::Bstr bstrDescription;
    hrc = progress->COMGETTER(Description(bstrDescription.asOutParam()));

    RTStrmPrintf(g_pStdErr, "%ls: ", bstrDescription.raw());
    RTStrmFlush(g_pStdErr);

    hrc = progress->COMGETTER(Completed(&fCompleted));
    while (SUCCEEDED(hrc)) {
        progress->COMGETTER(Percent(&ulCurrentPercent));

        /* did we cross a 10% mark? */
        if (ulCurrentPercent / 10  >  ulLastPercent / 10) {
            /* make sure to also print out missed steps */
            for (ULONG curVal = (ulLastPercent / 10) * 10 + 10; curVal <= (ulCurrentPercent / 10) * 10; curVal += 10) {
                if (curVal < 100) {
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
    if (SUCCEEDED(hrc)) {
        if (SUCCEEDED(iRc))
            RTStrmPrintf(g_pStdErr, "100%%\n");
        else {
            RTStrmPrintf(g_pStdErr, "\n");
            RTStrmPrintf(g_pStdErr, "Operation failed: %Rhrc\n", iRc);
        }
        hrc = iRc;
    } else {
        RTStrmPrintf(g_pStdErr, "\n");
        RTStrmPrintf(g_pStdErr, "Failed to obtain operation result: %Rhrc\n", hrc);
    }
    RTStrmFlush(g_pStdErr);
    return hrc;
}

// refer to src/VBox/Frontends/VBoxHeadless/VBoxHeadless.cpp
static void cleanup(int sig) {
    HRESULT hrc;
    RT_NOREF(sig);
    LogRel(("VBoxViDeZZo: received signal %d\n", sig));

    MachineState_T machineState = MachineState_Aborted;
    hrc = machine->COMGETTER(State)(&machineState);
    if (SUCCEEDED(hrc))
        Log(("machine state = %RU32\n", machineState));
    else
        Log(("IMachine::getState: %Rhrc\n", hrc));

    if (console && (machineState == MachineState_Running
            || machineState == MachineState_Teleporting
            || machineState == MachineState_LiveSnapshotting
            /** @todo power off paused VMs too? */)) {
        do {
            ComPtr<IProgress> progress;
            hrc = console->PowerDown(progress.asOutParam());
            hrc = showProgress1(progress);
        } while (0);
    }

    console = NULL;
    session->UnlockMachine();

    session.setNull();
    virtualBox.setNull();
    virtualBoxClient.setNull();
    machine.setNull();

    com::Shutdown();

    exit(0);
}

void find_and_apply_madvise() {
    FILE *maps_file = fopen("/proc/self/maps", "r");
    if (!maps_file) {
        perror("fopen");
        return;
    }

    char line[256];
    unsigned long start, end;
    char permissions[5];
    char path[256];

    // Iterate through each line in /proc/self/maps
    while (fgets(line, sizeof(line), maps_file)) {
        // Parse the line to extract the memory region info
        if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %s", &start, &end, permissions, path) == 4) {
            // Check if the path matches VBoxVMM.so and permissions include rw-
            if (strstr(path, "VBoxVMM.so") && strcmp(permissions, "rw-p") == 0) {
                // Apply madvise with MADV_DONTFORK on the found segment
                if (madvise((void *)start, end - start, MADV_DOFORK) != 0) {
                    perror("madvise");
                } else {
                    printf("Applied MADV_DONTFORK on segment: %lx-%lx\n", start, end);
                }
                break;
            }
        }
    }

    fclose(maps_file);
}

int LLVMFuzzerInitialize(int *argc, char ***argv, char ***envp)
{
    char *target_name = nullptr;
    GString *generic_cmd_line = nullptr, *modifyvm_cmd_line = nullptr, *storageattach_cmd_line = nullptr;
    ViDeZZoFuzzTarget *fuzz_target;
    int rc;
    HRESULT hrc;
    wordexp_t result;
    ComPtr<IMachine> m;
    ComPtr<IMachineDebugger> machineDebugger;
    ComPtr<IProgress> progress;

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
    RTUuidCreate(&uuid);
    RTUuidToStr(&uuid, uuid_str, sizeof(uuid_str));
    modifyvm_cmd_line = fuzz_target->get_init_cmdline(fuzz_target);
    
    // step 4: prepare before VBox init
    // Prepare RTR3 context
    RTR3InitExe(0, nullptr, 0);

    hrc = com::Initialize();
    hrc = virtualBoxClient.createInprocObject(CLSID_VirtualBoxClient);
    hrc = virtualBoxClient->COMGETTER(VirtualBox)(virtualBox.asOutParam());
    hrc = virtualBoxClient->COMGETTER(Session)(session.asOutParam());

    // step 5: construct VBox init cmds and init VBox
    // VBoxManage createvm --name UUID --uuid UUID --register --basefolder `pwd`
    generic_cmd_line = g_string_new(NULL);
    g_string_append_printf(generic_cmd_line, "--name vbox_vm_%s --uuid %s --register --basefolder `pwd`", uuid_str, uuid_str);
    wordexp(generic_cmd_line->str, &result, 0);
    g_string_free(generic_cmd_line, true);
    HandlerArg handlerArg0 = {(int)result.we_wordc, result.we_wordv, virtualBox, session};
    handleCreateVM(&handlerArg0);

    if (modifyvm_cmd_line) {
        // VBoxManage modifyvm UUID --key1 value1 --key2 value2
        wordexp(modifyvm_cmd_line->str, &result, 0);
        g_string_free(modifyvm_cmd_line, true);
        HandlerArg handlerArg1 = {(int)result.we_wordc, result.we_wordv, virtualBox, session};
        handleModifyVM(&handlerArg1);
    }

    if (!strcmp(fuzz_target->name, "videzzo-fuzz-floppy")) {
        // add the sata
        storageattach_cmd_line = g_string_new(NULL);
        g_string_append_printf(storageattach_cmd_line,
            "%s --name \"floppy01\" --add floppy", uuid_str);
        wordexp(storageattach_cmd_line->str, &result, 0);
        HandlerArg handlerArg2 = {(int)result.we_wordc, result.we_wordv, virtualBox, session};
        handleStorageController(&handlerArg2);
        g_string_free(storageattach_cmd_line, true);
        // add an hard disk
        storageattach_cmd_line = g_string_new(NULL);
        // VBoxManage createhd --filename `pwd`/videzzo.iso --size 80000 --format VDI
        g_string_append_printf(storageattach_cmd_line,
            "%s --storagectl \"floppy01\" --port 0 --device 0 --type fdd --medium emptydrive", uuid_str);
        wordexp(storageattach_cmd_line->str, &result, 0);
        HandlerArg handlerArg3 = {(int)result.we_wordc, result.we_wordv, virtualBox, session};
        handleStorageAttach(&handlerArg3);
        g_string_free(storageattach_cmd_line, true);
    }

    // console and debugger
    // refer to src/VBox/Frontends/VBoxHeadless/VBoxHeadless.cpp
    hrc = virtualBox->FindMachine(Bstr(uuid_str).raw(), m.asOutParam());
    // set session name
    hrc = session->COMSETTER(Name)(Bstr("videzzo").raw());
    // open a session
    hrc = m->LockMachine(session, LockType_VM);
    // get the console
    hrc = session->COMGETTER(Console)(console.asOutParam());
    // get the mutatble machine
    hrc = console->COMGETTER(Machine)(machine.asOutParam());
    // get the machine debugger
    hrc = console->COMGETTER(Debugger)(machineDebugger.asOutParam());
    // get the event queue
    gEventQ = com::NativeEventQueue::getMainEventQueue();

    // or VBoxManage startvm UUID --type headless
    hrc = console->PowerUpPaused(progress.asOutParam());

    hrc = showProgress1(progress);

    // src/VBox/Debugger/VBoxDbgGui.cpp
    // More: https://blog.doyensec.com/2022/04/26/vbox-fuzzing.html
    LONG64 llUVM = 0;
    LONG64 llVMMFunctionTable = 0;
    PUVM pUVM;
    PCVMMR3VTABLE pVMM;

    hrc = machineDebugger->GetUVMAndVMMFunctionTable(
        (int64_t)VMMR3VTABLE_MAGIC_VERSION, &llVMMFunctionTable, &llUVM);
    pUVM = (PUVM)(intptr_t)llUVM;
    pVMM = (PCVMMR3VTABLE)(intptr_t)llVMMFunctionTable;
    pVM = pUVM->pVM;
    pVCpu = VMCC_GET_CPU_0(pVM);

    // signals
    // refer to src/VBox/Frontends/VBoxHeadless/VBoxHeadless.cpp
    // not necessary
    // signal(SIGPIPE, SIG_IGN);
    // signal(SIGTTOU, SIG_IGN);

    // signal(SIGHUP,  SIG_DFL);
    // signal(SIGINT,  SIG_DFL);
    // signal(SIGTERM, SIG_DFL);
    // signal(SIGUSR1, SIG_DFL);

    // disable MADV_DONTFORK on VBoxVMM.so
    find_and_apply_madvise();

    return 0;
}
