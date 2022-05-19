/*
 * Type-Aware Virtual-Device Fuzzing QEMU
 *
 * Copyright Red Hat Inc., 2021
 *
 * Authors:
 *  Qiang Liu <cyruscyliu@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef QEMU_VIDEZZO_H
#define QEMU_VIDEZZO_H

#include "qemu/osdep.h"
#include <wordexp.h>
#include "hw/core/cpu.h"
#include "tests/qtest/libqos/libqtest.h"
#include "exec/address-spaces.h"
#include "string.h"
#include "exec/memory.h"
#include "exec/ramblock.h"
#include "exec/address-spaces.h"
#include "hw/qdev-core.h"
#include "hw/pci/pci.h"
#include "hw/boards.h"
#include "exec/ioport.h"
#include "tests/qtest/libqos/pci-pc.h"
#include "tests/qtest/libqos/qos_external.h"
#include "tests/qtest/libqos/qgraph_internal.h"

bool ViDeZZoFuzzer;
static void usage(void);

static GHashTable *fuzzable_memoryregions;
static GPtrArray *fuzzable_pci_devices;
extern QTestState *get_qtest_state(void);

static QGuestAllocator *qemu_alloc;

// To avoid overlap between dyn-alloced and QEMU-assumed buffers,
// where dyn-alloced buffers start from 1M,
// we enforce the dynamic alloc memory to be higher than 256M.
#define I386_MEM_LOW  0x10000000
#define I386_MEM_HIGH 0x20000000
#define RASPI2_RAM_LOW  (1 << 20)
#define RASPI2_RAM_HIGH (0x20000000)

typedef struct MemoryRegionPortioList {
    MemoryRegion mr;
    void *portio_opaque;
    MemoryRegionPortio ports[];
} MemoryRegionPortioList;

//
// Fuzz Target Configs
//
static inline gchar *generic_fuzzer_virtio_9p_args(void){
    char tmpdir[] = "/tmp/qemu-fuzz.XXXXXX";
    g_assert_nonnull(mkdtemp(tmpdir));

    return g_strdup_printf("-machine q35 -nodefaults "
    "-device virtio-9p,fsdev=hshare,mount_tag=hshare "
    "-fsdev local,id=hshare,path=%s,security_model=mapped-xattr,"
    "writeout=immediate,fmode=0600,dmode=0700", tmpdir);
}

#define COMMON_USB_CMD \
    "-usb " \
    "-device usb-kbd -device usb-mouse -device usb-tablet " \
    "-netdev user,id=net0 -device usb-net,netdev=net0 " \
    "-device usb-ccid -device usb-wacom-tablet "
#define COMMON_USB_CMD_1 \
    "-usb " \
    "-device usb-kbd "
#define COMMON_USB_CMD_2 \
    "-usb " \
    "-drive file=null-co://,if=none,format=raw,id=disk0 -device usb-storage,drive=disk0 " \
    "-chardev null,id=cd0 -device usb-braille,chardev=cd0 " \
    "-chardev null,id=cd1 -device usb-serial,chardev=cd1 " \
    "-device usb-kbd -device usb-mouse -device usb-tablet " \
    "-device usb-bot -device usb-ccid -device usb-ccid -device usb-wacom-tablet -device usb-audio"
#define COMMON_USB_CMD_STORAGE \
    "-usb " \
    "-drive file=null-co://,if=none,format=raw,id=disk0 -device usb-storage,port=1,drive=disk0"

static const videzzo_qemu_config predefined_configs[] = {
    {
        .arch = "i386",
        .name = "xhci",
        .args = "-machine q35 -nodefaults "
        "-drive file=null-co://,if=none,format=raw,id=disk0 "
        "-device qemu-xhci,id=xhci -device usb-tablet,bus=xhci.0 "
        "-device usb-bot -device usb-storage,drive=disk0 "
        "-chardev null,id=cd0 -chardev null,id=cd1 "
        "-device usb-braille,chardev=cd0 -device usb-ccid -device usb-ccid "
        "-device usb-kbd -device usb-mouse -device usb-serial,chardev=cd1 "
        "-device usb-tablet -device usb-wacom-tablet -device usb-audio",
        .mrnames = "*capabilities*,*operational*,*runtime*,*doorbell*",
        .file = "hw/usb/hcd-xhci.c",
        .socket = false,
    },{
        .arch = "i386",
        .name = "ehci",
        // suitable for ich9-usb-ehci1, ich9-usb-ehci2 and usb-ehci
        .args = "-machine q35 -nodefaults "
        "-device ich9-usb-ehci1,bus=pcie.0,addr=1d.7,"
        "multifunction=on,id=ich9-ehci-1 "
        "-device ich9-usb-uhci1,bus=pcie.0,addr=1d.0,"
        "multifunction=on,masterbus=ich9-ehci-1.0,firstport=0 "
        "-device ich9-usb-uhci2,bus=pcie.0,addr=1d.1,"
        "multifunction=on,masterbus=ich9-ehci-1.0,firstport=2 "
        "-device ich9-usb-uhci3,bus=pcie.0,addr=1d.2,"
        "multifunction=on,masterbus=ich9-ehci-1.0,firstport=4 "
        "-drive if=none,id=usbcdrom,media=cdrom "
        "-device usb-tablet,bus=ich9-ehci-1.0,port=1,usb_version=1 "
        "-device usb-storage,bus=ich9-ehci-1.0,port=2,drive=usbcdrom",
        .mrnames = "*capabilities*,*operational*,*ports*",
        .file = "hw/usb/hcd-ehci.c",
        .socket = false,
    },{
        .arch = "i386",
        .name = "ohci",
        .args = "-machine q35 -nodefaults -device pci-ohci,num-ports=6 "
        COMMON_USB_CMD,
        .mrnames = "*ohci*",
        .file = "hw/usb/hcd-ohci.c",
        .socket = false,
    },{
        .arch = "i386",
        .name = "uhci",
        // suitable for piix3-usb-uhci, piix4-usb-uhci, ich9-usb-uchi[1-6]
        .args = "-machine q35 -nodefaults -device piix3-usb-uhci,id=uhci,addr=1d.0 "
        "-drive id=drive0,if=none,file=null-co://,file.read-zeroes=on,format=raw "
        "-device usb-tablet,bus=uhci.0,port=1",
        .mrnames = "*uhci*",
        .file = "hw/usb/hcd-uhci.c",
        .socket = false,
    },{
        .arch = "i386",
        .name = "vmxnet3",
        .args = "-machine q35 -nodefaults "
        "-device vmxnet3,netdev=net0 -netdev user,id=net0",
        .mrnames = "*vmxnet3-b0*,*vmxnet3-b1*",
        .file = "hw/net/vmxnet3.c",
        .socket = true,
    },{
        .arch = "i386",
        .name = "ne2000",
        .args = "-machine q35 -nodefaults "
        "-device ne2k_pci,netdev=net0 -netdev user,id=net0",
        .mrnames = "*ne2000*",
        .file = "hw/net/ne2000.c",
        .socket = true,
        .byte_address = true,
    },{
        .arch = "i386",
        .name = "pcnet",
        .args = "-machine q35 -nodefaults "
        "-device pcnet,netdev=net0 -netdev user,id=net0",
        .mrnames = "*pcnet-mmio*,*pcnet-io*",
        .file = "hw/net/pcnet-pci.c",
        .socket = true,
        .byte_address = true,
    },{
        .arch = "i386",
        .name = "rtl8139",
        .args = "-machine q35 -nodefaults "
        "-device rtl8139,netdev=net0 -netdev user,id=net0",
        .mrnames = "*rtl8139*",
        .file = "hw/net/rtl8139.c",
        .socket = true,
        .byte_address = true,
    },{
        .arch = "i386",
        .name = "i82550",
        .args = "-machine q35 -nodefaults "
        "-device i82550,netdev=net0 -netdev user,id=net0",
        .mrnames = "*eepro100-mmio*,*eepro100-io*,*eepro100-flash*",
        .file = "hw/net/eepro100.c",
        .socket = true,
        .byte_address = true,
    },{
        .arch = "i386",
        .name = "e1000",
        .args = "-M q35 -nodefaults "
        "-device e1000,netdev=net0 -netdev user,id=net0",
        .mrnames = "*e1000-mmio*,*e1000-io*",
        .file = "hw/net/e1000.c",
        .socket = true,
    },{
        .arch = "i386",
        .name = "e1000e",
        .args = "-M q35 -nodefaults "
        "-device e1000e,netdev=net0 -netdev user,id=net0",
        .mrnames = "*e1000e-mmio*,*e1000e-io*",
        .file = "hw/net/e1000e.c",
        .socket = true,
    },{
        .arch = "i386",
        .name = "ac97",
        .args = "-machine q35 -nodefaults "
        "-device ac97,audiodev=snd0 -audiodev none,id=snd0 -nodefaults",
        .mrnames = "*ac97-nam*,*ac97-nabm*",
        .file = "hw/audio/ac97.c",
        .socket = false,
        .byte_address = true,
    },{
        .arch = "i386",
        .name = "cs4231a",
        .args = "-machine q35 -nodefaults "
        "-device cs4231a,audiodev=snd0 -audiodev none,id=snd0 -nodefaults",
        .mrnames = "*cs4231a*,*dma-chan*,*dma-page*,*dma-pageh*,*dma-cont*",
        .file = "hw/audio/cs4231a.c",
        .socket = false,
        .byte_address = true,
    },{
        .arch = "i386",
        .name = "cs4231",
        .args = "-machine q35 -nodefaults "
        "-device cs4231,audiodev=snd0 -audiodev none,id=snd0 -nodefaults",
        .mrnames = "*cs4231*,*dma-chan*,*dma-page*,*dma-pageh*,*dma-cont*",
        .file = "hw/audio/cs4231.c",
        .socket = false,
    },{
        .arch = "i386",
        .name = "es1370",
        .args = "-machine q35 -nodefaults "
        "-device es1370,audiodev=snd0 -audiodev none,id=snd0 -nodefaults",
        .mrnames = "*es1370*",
        .file = "hw/audio/es1370.c",
        .socket = false,
    },{
        .arch = "i386",
        .name = "sb16",
        .args = "-machine q35 -nodefaults "
        "-device sb16,audiodev=snd0 -audiodev none,id=snd0 -nodefaults",
        .mrnames = "*sb16*,*dma-chan*,*dma-page*,*dma-pageh*,*dma-cont*",
        .file = "hw/audio/sb16.c hw/dma/i8257.c",
        .socket = false,
        .byte_address = true,
    },{
        .arch = "i386",
        .name = "intel-hda",
        .args = "-machine q35 -nodefaults -device intel-hda,id=hda0 "
        "-device hda-output,bus=hda0.0 -device hda-micro,bus=hda0.0 "
        "-device hda-duplex,bus=hda0.0",
        .mrnames = "*intel-hda*",
        .file = "hw/audio/intel-hda.c",
        .socket = false,
        .byte_address = true,
    },{
        // i386, mipsel and ppc
        .arch = "i386",
        .name = "ati",
        .args = "-machine q35 -nodefaults -device ati-vga,romfile=\"\" "
        "-display vnc=localhost:%d -L ../pc-bios/",
        .mrnames = "*ati.mmregs*",
        .file = "hw/display/ati.c",
        .socket = false,
        .display = true,
    },{
        .arch = "i386",
        .name = "cirrus-vga",
        .args = "-machine q35 -nodefaults -device cirrus-vga "
        "-display vnc=localhost:%d -L ../pc-bios/",
        .mrnames = "*cirrus-io*,*cirrus-low-memory*,"
        "*cirrus-linear-io*,*cirrus-bitblt-mmio*,*cirrus-mmio*",
        .file = "hw/display/cirrus-vga.c",
        .socket = false,
        .display = true,
        .byte_address = true,
    },{
        .arch = "i386",
        // the real thing we test is the fdc not the floopy
        .name = "fdc",
        .args = "-machine pc -nodefaults "
        "-drive id=disk0,file=null-co://,file.read-zeroes=on,if=none,format=raw "
        "-device floppy,unit=0,drive=disk0",
        .mrnames = "*fdc*,*dma-chan*,*dma-page*,*dma-pageh*,*dma-cont*",
        .file = "hw/block/fdc.c",
        .socket = false,
        .byte_address = true,
    },{
        .arch = "i386",
        // sdhci -> sdhci-pci (pci) (i386)
        // sdhci -> sysbus-sdhci (sysbus) (arm)
        // sdhci + mmio -> cadence-sdhci (arm)
        .name = "sdhci-v3",
        .args = "-nodefaults -device sdhci-pci,sd-spec-version=3 "
        "-device sd-card,drive=mydrive "
        "-drive if=none,index=0,file=null-co://,format=raw,id=mydrive -nographic",
        .mrnames = "*sdhci*",
        .file = "hw/sd/sdhci-pci.c hw/sd/sdhci.c",
        .socket = false,
    },{
        .arch = "i386",
        .name = "ahci-hd",
        .args = "-machine q35 -nodefaults "
        "-drive file=null-co://,if=none,format=raw,id=disk0 "
        "-device ide-hd,drive=disk0",
        .mrnames = "*ahci*",
        .file = "hw/ide/ahci.c",
        .socket = false,
    },{
        .arch = "i386",
        .name = "ahci-cd",
        .args = "-machine q35 -nodefaults "
        "-drive file=null-co://,if=none,format=raw,id=disk0 "
        "-device ide-cd,drive=disk0",
        .mrnames = "*ahci*",
        .file = "hw/ide/ahci.c",
        .socket = false,
    },{
        .arch = "i386",
        .name = "lsi53c895a",
        .args = "-machine q35 -nodefaults "
        "-device lsi53c895a,id=scsi0 "
        "-device scsi-hd,drive=drive0,bus=scsi0.0,channel=0,scsi-id=0,lun=0 "
        "-drive file=null-co://,if=none,format=raw,id=drive0 "
        "-device scsi-hd,drive=drive1,bus=scsi0.0,channel=0,scsi-id=1,lun=0 "
        "-drive file=null-co://,if=none,format=raw,id=drive1",
        .mrnames = "*lsi-mmio*,*lsi-ram*,*lsi-io*",
        .file = "hw/scsi/lsi53c895a.c",
        .socket = false,
        .byte_address = true,
    },{
        .arch = "i386",
        .name = "megasas",
        .args = "-machine q35 -nodefaults "
        "-device megasas -device scsi-cd,drive=null0 "
        "-blockdev driver=null-co,read-zeroes=on,node-name=null0",
        .mrnames = "*megasas-mmio*,*megasas-io*,*megasas-queue*",
        .file = "hw/scsi/megasas.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "smc91c111",
        .args = "-machine mainstone",
        .mrnames = "*smc91c111-mmio*",
        .file = "hw/net/smc91c111.c",
        .socket = true,
    },{
        .arch = "arm",
        .name = "dwc2",
        // arm supports raspi0/1ap/2b, aarch64 supports raspi3
        .args = "-machine raspi2b -m 1G -nodefaults "
        COMMON_USB_CMD_STORAGE,
        .mrnames = "*dwc2-io*,*dwc2-fifo*",
        .file = "hw/usb/hcd-dwc2.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "bcm2835_thermal",
        // arm supports raspi0/1ap/2b, aarch64 supports raspi3
        .args = "-machine raspi2b -m 1G -nodefaults",
        .mrnames = "*bcm2835-thermal*",
        .file = "hw/misc/bcm2835-thermal.c",
        .socket = false,
    }
};

#endif /* QEMU_VIDEZZO_H */
