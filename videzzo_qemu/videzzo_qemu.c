/*
 * Dependency-Aware Virtual-Device Fuzzing QEMU
 *
 * Copyright Red Hat Inc., 2021
 *
 * Authors:
 *  Qiang Liu <cyruscyliu@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include <wordexp.h>
#include "hw/core/cpu.h"
#include "tests/qtest/libqtest.h"
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
#include "tests/qtest/libqos/qgraph.h"
#include "tests/qtest/libqos/qgraph_internal.h"
#include "qemu/cutils.h"
#include "qemu/datadir.h"
#include "qemu/main-loop.h"
#include "sysemu/qtest.h"
#include "sysemu/sysemu.h"
#include "videzzo.h"
#ifdef CLANG_COV_DUMP
#include "clangcovdump.h"
#ifdef __cplusplus
extern "C" int __llvm_profile_runtime;
#else
int __llvm_profile_runtime;
#endif
#endif

//
// Fuzz Target Configs
//
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

static const ViDeZZoFuzzTargetConfig predefined_configs[] = {
    {
        .arch = "i386",
        .name = "xhci",
        .args = "-machine q35 -nodefaults "
        "-drive file=null-co://,if=none,format=raw,id=disk0 "
        "-device qemu-xhci,id=xhci -device usb-storage,drive=disk0 "
        "-device usb-bot -device usb-tablet,bus=xhci.0 "
        "-chardev null,id=cd0 -chardev null,id=cd1 "
        "-device usb-braille,chardev=cd0 -device usb-ccid -device usb-ccid "
        "-device usb-kbd -device usb-mouse -device usb-serial,chardev=cd1 "
        "-device usb-tablet -device usb-wacom-tablet -device usb-audio",
        .mrnames = "*capabilities*,*operational*,*runtime*,*doorbell*,*usb3 port*",
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
        "-drive file=null-co://,if=none,format=raw,id=disk0 "
        "-device usb-storage,bus=ich9-ehci-1.0,port=1,drive=disk0 "
        "-device usb-tablet,bus=ich9-ehci-1.0,port=2,usb_version=1",
        .mrnames = "*capabilities*,*operational*,*ports*",
        .file = "hw/usb/hcd-ehci.c",
        .socket = false,
    },{
        .arch = "i386",
        .name = "ohci",
        .args = "-machine q35 -nodefaults -device pci-ohci,num-ports=6 "
        COMMON_USB_CMD_STORAGE,
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
        .name = "qxl",
        .args = "-machine q35 -nodefaults -device qxl "
        "-display vnc=localhost:%d -L ../pc-bios/",
        .mrnames = "*qxl-ioports*",
        .file = "hw/display/qxl.c",
        .socket = false,
        .display = true,
    },{
        .arch = "i386",
        .name = "vmware-svga",
        .args = "-machine q35 -nodefaults -device vmware-svga "
        "-display vnc=localhost:%d -L ../pc-bios/",
        .mrnames = "*vmsvga-io*",
        .file = "hw/display/vmware-svga.c",
        .socket = false,
        .display = true,
        .byte_address = true,
    },{
        .arch = "i386",
        .name = "std-vga",
        .args = "-machine q35 -nodefaults -device VGA "
        "-display vnc=localhost:%d -L ../pc-bios/",
        "*bochs dispi interface*,*qemu extended regs*,*vga.mmio*",
        .mrnames = "*vga-lowmem*,*vga ioports remapped*,"
        "*bochs dispi interface*,*qemu extended regs*,*vga.mmio*",
        .file = "hw/display/vga.c",
        .socket = false,
        .display = true,
    },{
        .arch = "i386",
        .name = "secondary-vga",
        .args = "-machine q35 -nodefaults -device secondary-vga "
        "-display vnc=localhost:%d -L ../pc-bios/",
        "*bochs dispi interface*,*qemu extended regs*,*vga.mmio*",
        .mrnames = "*vga-lowmem*,*vga ioports remapped*,"
        "*bochs dispi interface*,*qemu extended regs*,*vga.mmio*",
        .file = "hw/display/vga.c",
        .socket = false,
        .display = true,
    },{
        .arch = "i386",
        .name = "bochs-display",
        .args = "-machine q35 -nodefaults -device bochs-display "
        "-display vnc=localhost:%d -L ../pc-bios/",
        .mrnames = "*bochs dispi interface*,*qemu extended regs*,*bochs-display-mmio*",
        .file = "hw/display/bochs-display.c",
        .socket = false,
        .display = true,
    },{
        .arch = "i386",
        .name = "parallel",
        .args = "-machine q35 -nodefaults "
        "-parallel file:/dev/null",
        .mrnames = "*parallel*",
        .file = "hw/char/parallel.c",
        .socket = false,
    },{
        .arch = "i386",
        .name = "kvaser-can",
        .args = "-machine q35 -nodefaults "
        "-object can-bus,id=canbus0 -device kvaser_pci,canbus=canbus0",
        // "-object can-host-socketcan,id=canhost0,if=can0,canbus=canbus0",
        .mrnames = "*kvaser_pci-s5920*,*kvaser_pci-sja*,*kvaser_pci-xilinx*",
        .socket = true,
    },{
        .arch = "i386",
        .name = "pcm3680-can",
        .args = "-machine q35 -nodefaults "
        "-object can-bus,id=canbus "
        "-device pcm3680_pci,canbus0=canbus,canbus1=canbus",
        // "-object can-host-socketcan,id=canhost0,if=can0,canbus=canbus0",
        .mrnames = "*pcm3680i_pci-sja1*,*pcm3680i_pci-sja2*",
        .socket = true,
    },/*{
        .arch = "i386",
        .name = "mioe3680-can",
        .args = "-machine q35 -nodefaults "
        "-object can-bus,id=canbus "
        "-device mioe3680_pci,canbus0=canbus",
        // "-object can-host-socketcan,id=canhost0,if=can0,canbus=canbus0",
        .mrnames = "*mioe3680_pci-sja1*,*mioe3680_pci-sja2*",
        .socket = false,
    },*/{
        .arch = "i386",
        .name = "ctu-can",
        .args = "-machine q35 -nodefaults "
        "-object can-bus,id=canbus0-bus "
        "-device ctucan_pci,canbus0=canbus0-bus,canbus1=canbus0-bus",
        // "-object can-host-socketcan,if=can0,canbus=canbus0-bus,id=canbus0-socketcan",
        .mrnames = "*ctucan_pci-core0*,*ctucan_pci-core1*",
        .socket = true,
    },{
        .arch = "i386",
        .name = "rocker",
        .args = "-machine q35 -nodefaults "
        "-device rocker,name=sw1,len-ports=4,ports[0]=dev0,"
        "ports[1]=dev1,ports[2]=dev2,ports[3]=dev3 "
        "-netdev socket,udp=127.0.0.1:1204,localaddr=127.0.0.1:1215,id=dev0 "
        "-netdev socket,udp=127.0.0.1:1205,localaddr=127.0.0.1:1219,id=dev1 "
        "-netdev socket,udp=127.0.0.1:1206,localaddr=127.0.0.1:1211,id=dev2 "
        "-netdev socket,udp=127.0.0.1:1207,localaddr=127.0.0.1:1223,id=dev3",
        .mrnames = "*rocker-mmio*",
        .file = "hw/net/rocker/rocker.c",
        .socket = true,
    },{
        .arch = "i386",
        .name = "virtio-net",
        .args = "-M q35 -nodefaults "
        "-device virtio-net,netdev=net0,mq=on,hash=on,rss=on -netdev user,id=net0",
        .mrnames = "*virtio*",
        .file = "hw/net/virtio-net.c",
        .socket = false,
        .byte_address = true,
    },{
        .arch = "i386",
        .name = "virtio-blk",
        .args = "-machine q35 -device virtio-blk,drive=disk0 "
        "-drive file=null-co://,id=disk0,if=none,format=raw",
        .mrnames = "*virtio*",
        .file = "hw/block/virtio-blk.c",
        .socket = false,
        .byte_address = true,
    },{
        .arch = "i386",
        .name = "virtio-scsi",
        .args = "-machine q35 -device virtio-scsi,num_queues=8 "
        "-device scsi-hd,drive=disk0 "
        "-drive file=null-co://,id=disk0,if=none,format=raw",
        .mrnames = "*scsi*,*virtio*",
        .file = "hw/scsi/virtio-scsi.c",
        .socket = false,
        .byte_address = true,
    },{
        .arch = "i386",
        .name = "virtio-gpu",
        .args = "-machine q35 -nodefaults -device virtio-gpu",
        .mrnames = "*virtio*",
        .file = "hw/display/virtio-gpu.c",
        .socket = false,
        .byte_address = true,
    },{
        .arch = "i386",
        .name = "virtio-vga",
        .args = "-machine q35 -nodefaults -device virtio-vga",
        .mrnames = "*virtio*",
        .file = "hw/display/virtio-vga.c",
        .socket = false,
        .byte_address = true,
    },{
        .arch = "i386",
        .name = "virtio-rng",
        .args = "-machine q35 -nodefaults -device virtio-rng",
        .mrnames = "*virtio*",
        .file = "hw/virtio/virtio-rng.c",
        .socket = false,
        .byte_address = true,
    },{
        .arch = "i386",
        .name = "virtio-balloon",
        .args = "-machine q35 -nodefaults -device virtio-balloon",
        .mrnames = "*virtio*",
        .file = "hw/virtio/virtio-balloon.c",
        .socket = false,
        .byte_address = true,
    },{
        .arch = "i386",
        .name = "virtio-serial",
        .args = "-machine q35 -nodefaults -device virtio-serial",
        .mrnames = "*virtio*",
        .file = "hw/virtio/virtio-serial-pci.c",
        .socket = false,
        .byte_address = true,
    },{
        .arch = "i386",
        .name = "virtio-mouse",
        .args = "-machine q35 -nodefaults -device virtio-mouse",
        .mrnames = "*virtio*",
        .file = "hw/virtio/virtio-input-pci.c",
        .socket = false,
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
        .name = "nvme",
        .args = "-machine pc -nodefaults "
        "-drive id=nvm,file=null-co://,file.read-zeroes=on,if=none,format=raw "
        "-object memory-backend-file,id=mb,share=on,mem-path=/tmp/nvm-mb,size=4096 "
        "-device nvme,cmb_size_mb=32,serial=deadbeef,drive=nvm,pmrdev=mb",
        .mrnames = "*nvme*,*nvme-cmb*",
        .file = "hw/block/nvme.c",
        .socket = false,
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
    },/*{
        .arch = "i386",
        .name = "ide-hd",
        .args = "-machine pc -nodefaults "
        "-drive file=null-co://,if=none,format=raw,id=disk0 "
        "-device ide-hd,drive=disk0",
        .mrnames = "*ide*",
        .file = "hw/ide/qdev.c",
        .socket = false,
    },{
        .arch = "i386",
        .name = "ide-atapi",
        .args = "-machine pc -nodefaults "
        "-drive file=null-co://,if=none,format=raw,id=disk0 "
        "-device ide-cd,drive=disk0",
        .mrnames = "*ide*",
        .file = "hw/ide/qdev.c",
        .socket = false,
    },*/{
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
    },/*{
        .arch = "i386",
        .name = "piix3-ide",
        // suitable for piix3-ide, piix4-ide and piix3-ide-xen
        .args = "-machine q35 -nodefaults -device piix3-ide",
        .mrnames = "*piix-bmdma*,*bmdma*",
        .file = "hw/ide/piix.c",
        .socket = false,
    },*/{
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
        .name = "am53c974",
        .args = "-machine q35 -nodefaults "
        "-device am53c974,id=scsi "
        "-device scsi-hd,drive=disk0 "
        "-drive id=disk0,if=none,file=null-co://,format=raw",
        .mrnames = "*esp-io*",
        // because sysbus-esp is not supported in i386/arm/aarch
        // we ignore hw/scsi/esp.c
        .file = "hw/scsi/esp-pci.c",
        .socket = false,
    },{
        .arch = "i386",
        .name = "fw-cfg",
        .args = "-machine q35 -nodefaults "
        "-fw_cfg name=videzzo,string=fuzz "
        "-fw_cfg name=is,string=promising ",
        "*fwcfg*",
        .mrnames = "*fwcfg.ctl*,*fwcfg.data*,*fwcfg.dma*,"
        "*fwcfg*",
        .file = "hw/nvram/fw_cfg.c",
        .socket = false,
    },/*{
        .arch = "arm",
        .name = "tusb6010",
        .args = "-machine n810 -m 128M -usb",
        .mrnames = "*tusb-async*",
        .file = "hw/usb/tusb6010.c",
        .socket = false,
    },*/{
        .arch = "arm",
        .name = "imx-usb-phy",
        .args = "-machine sabrelite",
        .mrnames = "*imx-usbphy*",
        .file = "hw/usb/imx-usb-phy.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "chipidea",
        .args = "-machine sabrelite -nodefaults "
        COMMON_USB_CMD_1,
        "*usb-chipidea.dc*,*usb-chipidea.endpoints*",
        .mrnames = "*usb-chipidea.misc*,"
        "*usb-chipidea.dc*,*usb-chipidea.endpoints*",
        .file = "hw/usb/chipidea.c",
        .socket = false,
    },{
        .arch = "aarch64",
        .name = "versal-usb2",
        .args = "-machine xlnx-versal-virt -nodefaults "
        COMMON_USB_CMD,
        .mrnames = "*versal.usb2Ctrl_alias*",
        .file = "hw/usb/xlnx-versal-usb2-ctrl-regs.c",
        .socket = false,
    },{
        // duplicated
        .arch = "aarch64",
        .name = "dwc3",
        .args = "-machine xlnx-versal-virt -nodefaults "
        COMMON_USB_CMD,
        .mrnames = "*versal.dwc3_alias*",
        .file = "hw/usb/hcd-dwc3.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "xgmac",
        .args = "-machine midway",
        .mrnames = "*xgmac*",
        .file = "hw/net/xgmac.c",
        .socket = true,
    },{
        .arch = "arm",
        .name = "stellaris-enet",
        .args = "-machine lm3s6965evb",
        .mrnames = "*stellaris_enet*",
        .file = "hw/net/stellaris_enet.c",
        .socket = false,
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
    }, {
        .arch = "arm",
        .name = "npcm7xx-emc",
        .args = "-machine npcm750-evb",
        .mrnames = "*npcm7xx-emc*",
        .file = "hw/net/npcm7xx_emc.c",
        .socket = false,
    },/*{
        .arch = "arm",
        .name = "msf2-emac",
        .args= "-machine emcraft-sf2",
        .mrnames = "*msf2-emac*",
        .file = "hw/net/msf2-emac.c",
        .socket = false,
    },*/{
        .arch = "arm",
        .name = "lan9118",
        .args = "-machine smdkc210",
        .mrnames = "*lan9118-mmio*",
        .file = "hw/net/lan9118.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "imx-fec",
        .args = "-machine sabrelite",
        .mrnames = "*imx.fec*",
        .file = "hw/net/imx_fec.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "ftgmac100",
        .args = "-machine palmetto-bmc",
        .mrnames = "*ftgmac100*,*aspeed-mmi*",
        .file = "hw/net/ftgmac100.c",
        .socket = false,
    },{
        .arch = "aarch64",
        .name = "cadence-gem",
        .args = "-machine xlnx-versal-virt "
        "-net nic,model=cadence_gem,netdev=net0 -netdev user,id=net0",
        .mrnames = "*enet*",
        .file = "hw/net/cadence_gem.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "allwinner-sun8i-emac",
        .args = "-machine orangepi-pc -m 1G",
        .mrnames = "*allwinner-sun8i-emac*",
        .file = "hw/net/allwinner-sun8i-emac.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "allwinner-emac",
        .args = "-machine cubieboard -nodefaults "
        "-net nic,model=allwinner-emac,netdev=net0 -netdev user,id=net0",
        .mrnames = "*aw_emac*",
        .file = "hw/net/allwinner-emac.c",
        .socket = false,
    },{
        // https://patchwork.ozlabs.org/project/qemu-devel/patch/1596575505-163040-2-git-send-email-fnu.vikram@xilinx.com/
        // apt-get install iproute2
        // ip link add dev vcan0 type vcan
        // ip link set up vcan0
        .arch = "aarch64",
        .name = "xlnx-zynqmp-can",
        .args = "-machine xlnx-zcu102,canbus0=canbus0 "
        "-object can-bus,id=canbus0",
        // "-object can-host-socketcan,id=socketcan0,if=vcan0,canbus=canbus0",
        .mrnames = "*xlnx.zynqmp-can*",
        .file = "hw/net/can/xlnx-zynqmp-can.c",
        .socket = false,
    },{
        .arch = "aarch64",
        .name = "xlnx-dp",
        .args = "-machine xlnx-zcu102",
        .mrnames = "*.core*,*.v_blend*,*.av_buffer_manager*,*.audio*",
        .file = "hw/display/xlnx_dp.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "exynos4210-fimd",
        .args = "-machine smdkc210",
        .mrnames = "*exynos4210.fimd*",
        .file = "hw/display/exynos4210_fimd.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "omap-dss",
        .args = "-machine n810 -m 128M",
        .mrnames = "*omap.diss1*,*omap.disc1*,*omap.rfbi1*,*omap.venc1*,*omap.im3*",
        .file = "hw/net/omap_dss.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "omap-lcdc",
        .args = "-machine sx1-v1 -m 32M",
        .mrnames = "*omap.lcdc*",
        .file = "hw/net/omap_lcdc.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "pl110",
        .args = "-machine integratorcp",
        .mrnames = "*pl110*",
        .file = "hw/display/pl110.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "pxa2xx-lcd",
        .args = "-machine verdex",
        .mrnames = "*pxa2xx-lcd-controller*",
        .file = "hw/display/pxa2xx_lcd.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "tc6393xb",
        .args = "-machine tosa",
        .mrnames = "*tc6393xb*",
        .file = "hw/display/tc6393xb.c",
        .socket = false,
        .byte_address = true,
    },{
        .arch = "arm",
        .name = "pl041",
        .args = "-machine integratorcp",
        .mrnames = "*pl041*",
        .file = "hw/audio/pl041.c",
        .socket = false,
    },/*{
        .arch = "arm",
        .name = "pflash-cfi02",
        .args = "-machine xilinx-zynq-a9",
        .mrnames = "*zynq.pflash*",
        .file = "hw/block/pflash_cfi02.c",
        .socket = false,
    },*/{
        .arch = "arm",
        .name = "pflash-cfi01",
        .args = "-machine collie",
        .mrnames = "*collie.fl1*,*collie.fl2*",
        .file = "hw/block/pflash_cfi01.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "onenand",
        .args = "-machine n810 -m 128M",
        .mrnames = "*onenand*",
        .file = "hw/block/onenand.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "allwinner-sdhost",
        .args = "-machine cubieboard",
        .mrnames = "*allwinner-sdhost*",
        .file = "hw/sd/allwinner-sdhost.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "bcm2835-sdhost",
        // arm supports raspi0/1/2, aarch64 supports raspi3
        .args = "-machine raspi0",
        .mrnames = "*bcm2835-sdhost*",
        .file = "hw/sd/bcm2835_sdhost.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "omap-mmc",
        .args = "-machine sx1-v1 -m 32M",
        .mrnames = "*omap.mmc*",
        .file = "hw/sd/omap_mmc.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "pl181",
        .args = "-machine integratorcp",
        .mrnames = "*pl181*",
        .file = "hw/sd/pl181.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "pxa2xx-mmci",
        .args = "-machine verdex",
        .mrnames = "*pxa2xx-mmci*",
        .file = "hw/sd/pxa2xx_mmci.c",
        .socket = false,
    },{
        .arch = "arm",
        // ahci -> ich9-ahci (pci) (i386/mips)
        // ahci -> sysbus-ahci (sysbus) (arm)
        // ahci + mmio -> allwinner-ahci (sysbus) (arm)
        // change: change allwinner-ahci to sysbus-ahci/ich9-ahci (TODO)
        // note that problems in sysbus-ahci are also in ich9-ahci
        // note that ahci-idp is not explosed for arm machine!
        .name = "sysbus-ahci",
        .args = "-machine midway",
        .mrnames = "*ahci*,*ahci-idp*",
        .file = "hw/ide/ahci.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "npcm7xx-otp",
        .args = "-machine npcm750-evb",
        .mrnames = "*regs*",
        .file = "hw/nvram/npcm7xx_otp.c",
        .socket = false,
    }, {
        .arch = "arm",
        .name = "nrf51-nvm",
        .args = "-machine microbit",
        "*nrf51_soc.uicr*,*nrf51_soc.flash*",
        .mrnames = "*nrf51_soc.nvmc*,*nrf51_soc.ficr*,"
        "*nrf51_soc.uicr*,*nrf51_soc.flash*",
        .file = "hw/nvram/nrf51_nvm.c",
        .socket = false,
    },
// according to PMM's summary, we will support virt, sbsa-ref,
// xlnx-versal-virt, xlnx-zcu102, highbank and midway first
    /* common in highbank and midway */ {
        .arch = "arm",
        .name = "sp804",
        .args = "-machine midway",
        .mrnames = "*sp804*",
        .file = "hw/timer/arm_timer.c",
        .socket = false,
    }, {
        .arch = "arm",
        .name = "pl011",
        .args = "-machine midway",
        .mrnames = "*pl011*",
        .file = "hw/char/pl011.c",
        .socket = false,
    }, {
        .arch = "arm",
        .name = "highbank-regs",
        .args = "-machine midway",
        .mrnames = "*highbank_regs*",
        .file = "hw/arm/highbank.c",
        .socket = false,
    }, {
        .arch = "arm",
        .name = "pl061",
        .args = "-machine midway",
        .mrnames = "*pl061*",
        .file = "hw/gpio/pl061.c",
        .socket = false,
    }, {
        .arch = "arm",
        .name = "pl031",
        .args = "-machine midway",
        .mrnames = "*pl031*",
        .file = "hw/rtc/pl031.c",
        .socket = false,
    }, {
        .arch = "arm",
        .name = "pl022",
        .args = "-machine midway",
        .mrnames = "*pl022*",
        .file = "hw/ssi/pl022.c",
        .socket = false,
    }, /* xgmac/ahci see above */
    /* only in highbank */ {
        .arch = "arm",
        .name = "a9-scu",
        .args = "-machine highbank",
        .mrnames = "*a9-scu*",
        .file = "hw/misc/a9scu.c",
        .socket = false,
    }, {
        .arch = "arm",
        .name = "arm-gic",
        .args = "-machine highbank",
        .mrnames = "*gic_dist*,*gic_cpu*,*gic_viface*,*gic_vcpu*",
        .file = "hw/intc/arm_gic.c hw/intc/arm_gic_common.c",
        .socket = false,
    }, {
        .arch = "arm",
        .name = "a9-gtimer",
        .args = "-machine highbank",
        .mrnames = "*a9gtimer shared*,*a9gtimer per cpu*",
        .file = "hw/timer/a9gtimer.c",
        .socket = false,
    }, {
        .arch = "arm",
        .name = "arm-mptimer",
        .args = "-machine highbank",
        .mrnames = "*arm_mptimer_timer*,*arm_mptimer_timerblock*",
        .file = "hw/timer/arm_mptimer.c",
        .socket = false,
    }, /* xlnx-zcu102 */
    /* gic/cadence-gem/xlnx-zynqmp-can
     * sysbus-ahci/sdhci/xlnx-dp see above */ {
        .arch = "aarch64",
        .name = "cadence-uart",
        .args = "-machine xlnx-zcu102",
        .mrnames = "*uart*",
        .file = "hw/char/cadence_uart.c",
        .socket = false,
    }, {
        .arch = "aarch64",
        // xilinx-spips + mmio -> xilinx-qspips
        // xilinx-qspips + fifo -> xlnx-zynqmp-qspips
        .name = "xlnx-zynqmp-qspips",
        .args = "-machine xlnx-zcu102",
        .mrnames = "*spi*,*lqspi*",
        .file = "hw/ssi/xilinx_spips.c",
        .socket = false,
    }, {
        .arch = "aarch64",
        .name = "xlnx-dpdma",
        .args = "-machine xlnx-zcu102",
        .mrnames = "*xlnx.dpdma*",
        .file = "hw/dma/xlnx_dpdma.c",
        .socket = false,
    }, {
        .arch = "aarch64",
        .name = "xlnx-zynqmp-ipi",
        .args = "-machine xlnx-zcu102",
        .mrnames = "*xlnx.zynqmp_ipi*",
        .file = "hw/intc/xln-zynqmp-pip.c",
        .socket = false,
    }, {
        .arch = "aarch64",
        .name = "xlnx-zynqmp-rtc",
        .args = "-machine xlnx-zcu102",
        .mrnames = "*xlnx-zynmp.rtc*",
        .file = "hw/rtc/xlnx-zynqmp-rtc.c",
        .socket = false,
    }, {
        .arch = "aarch64",
        .name = "xlnx-zdma",
        .args = "-machine xlnx-zcu102",
        .mrnames = "*xlnx.zdma*",
        .file = "hw/dma/xlnx-zdma.c",
        .socket = false,
    }, {
        .arch = "aarch64",
        .name = "xlnx-csu-dma",
        .args = "-machine xlnx-zcu102",
        .mrnames = "*xlnx.csu_dma*",
        .file = "hw/dma/xlnx_csu_dma.c",
        .socket = false,
    }, /* sbsa-ref */ {
        .arch = "aarch64",
        .name = "arm-gicv3",
        .args = "-machine sbsa-ref",
        .mrnames = "*gicv3_dist*,*gicv3_redist_region*",
        .file = "hw/intc/arm_gicv3.c hw/intc/arm_gicv3_common.c",
        .socket = false,
    }, /* pl011/pl031/e1000e/vga see above */ {
        .arch = "aarch64",
        .name = "wdt-sbsa",
        .args = "-machine sbsa-ref",
        .mrnames = "*sbsa_gwdt.refresh*,*sbsa_gwdt.control*",
        .file = "hw/watchdog/sbsa_gwdt.c",
        .socket = false,
    }, /* virt, pl011/pl031/pl061 see above */ {
        .arch = "aarch64",
        .name = "platform-bus",
        .args = "-machine virt",
        .mrnames = "*platform bus*",
        .file = "hw/core/platform-bus.c",
        .socket = false,
    }
};

static GHashTable *fuzzable_memoryregions;
static GPtrArray *fuzzable_pci_devices;
static QGuestAllocator *qemu_alloc;

bool sockfds_initialized = false;
int sockfds[2];

static int vnc_port;
bool vnc_client_needed = false;
bool vnc_client_initialized = false;

//
// QEMU Dispatcher
//
static uint8_t qemu_readb(uint64_t addr) {
    uint8_t value;
    address_space_read(first_cpu->as, addr, MEMTXATTRS_UNSPECIFIED, &value, 1);
    return value;
}

static uint16_t qemu_readw(uint64_t addr) {
    uint16_t value;
    address_space_read(first_cpu->as, addr, MEMTXATTRS_UNSPECIFIED, &value, 2);
    return value;
}

static uint32_t qemu_readl(uint64_t addr) {
    uint32_t value;
    address_space_read(first_cpu->as, addr, MEMTXATTRS_UNSPECIFIED, &value, 4);
    return value;
}

static uint64_t qemu_readq(uint64_t addr) {
    uint64_t value;
    address_space_read(first_cpu->as, addr, MEMTXATTRS_UNSPECIFIED, &value, 8);
    return value;
}

uint64_t dispatch_mmio_read(Event *event) {
    switch (__disimm_around_event_size(event->size, 8)) {
        case ViDeZZo_Byte: return qemu_readb(event->addr);
        case ViDeZZo_Word: return qemu_readw(event->addr);
        case ViDeZZo_Long: return qemu_readl(event->addr);
        case ViDeZZo_Quad: return qemu_readq(event->addr);
        default: fprintf(stderr, "wrong size of dispatch_mmio_read %d\n", event->size); return 0xffffffffffffffff;
    }
}

static uint8_t qemu_inb(uint16_t addr) {
    return cpu_inb(addr);
}

static uint16_t qemu_inw(uint16_t addr) {
    return cpu_inw(addr);
}

static uint32_t qemu_inl(uint16_t addr) {
    return cpu_inl(addr);
}

uint64_t dispatch_pio_read(Event *event) {
    switch (__disimm_around_event_size(event->size, 4)) {
        case ViDeZZo_Byte: return qemu_inb(event->addr);
        case ViDeZZo_Word: return qemu_inw(event->addr);
        case ViDeZZo_Long: return qemu_inl(event->addr);
        default: fprintf(stderr, "wrong size of dispatch_pio_read %d\n", event->size); return 0xffffffffffffffff;
    }
}

static void qemu_memread(uint64_t addr, void *data, size_t size) {
    address_space_read(first_cpu->as, addr, MEMTXATTRS_UNSPECIFIED, data, size);
}

uint64_t dispatch_mem_read(Event *event) {
    qemu_memread(event->addr, event->data, event->size);
    return 0;
}

static void qemu_writeb(uint64_t addr, uint8_t value) {
    address_space_write(first_cpu->as, addr, MEMTXATTRS_UNSPECIFIED, &value, 1);
}

static void qemu_writew(uint64_t addr, uint16_t value) {
    address_space_write(first_cpu->as, addr, MEMTXATTRS_UNSPECIFIED, &value, 2);
}

static void qemu_writel(uint64_t addr, uint32_t value) {
    address_space_write(first_cpu->as, addr, MEMTXATTRS_UNSPECIFIED, &value, 4);
}

static void qemu_writeq(uint64_t addr, uint64_t value) {
    address_space_write(first_cpu->as, addr, MEMTXATTRS_UNSPECIFIED, &value, 8);
}

static bool xhci = false;
static bool pcnet = false;
static bool e1000e = false;
static bool vmxnet3 = false;
static bool dwc2 = false;
static bool virtio = false;

#define XHCI_CAP_BASE (0xe0004000)
#define XHCI_OPE_BASE (XHCI_CAP_BASE + 0x0040)
#define XHCI_POR_BASE (XHCI_CAP_BASE + 0x0440)
#define XHCI_RUN_BASE (XHCI_CAP_BASE + 0x1000)
#define XHCI_DOO_BASE (XHCI_CAP_BASE + 0x2000)
#define XHCI_DOO_END  (XHCI_DOO_BASE + 0x0040)

uint64_t dispatch_mmio_write(Event *event) {
    unsigned int pid, len;

    if ((!DisableInputProcessing) && xhci && (event->addr >= XHCI_DOO_BASE) && (event->addr < XHCI_DOO_END)) {
        event->addr = XHCI_DOO_BASE + (event->addr - XHCI_DOO_BASE) % 0x40;
        if (event->addr == XHCI_DOO_BASE && (rand() % 100)) {
            event->valu = 0;
        } else {
            uint32_t epid = (rand() - 1) % (5 - 1) + 1;
            uint32_t streamid = (rand() - 1) % (4 - 1) + 1;
            event->valu &= 0xffffffff0000ff00;
            event->valu |= epid;
            event->valu |= (streamid << 16);
        }
    }
    if ((!DisableInputProcessing) && xhci && (event->addr >= XHCI_RUN_BASE) && (event->addr < XHCI_DOO_BASE)) {
        event->addr = (event->addr - XHCI_RUN_BASE) % 0x24 + XHCI_RUN_BASE + 0x001c;
        switch ((event->addr - XHCI_RUN_BASE) % 0x20) {
            case 0x8:
                event->valu = 1;
                break;
            case 0x18:
                event->valu = 0x100000;
                break;
            case 0x1c:
                event->valu = 0;
                break;
        }
    }
    if ((!DisableInputProcessing) && xhci && (event->addr >= XHCI_POR_BASE) && (event->addr < XHCI_RUN_BASE) &&
            ((event->addr - XHCI_POR_BASE) % 0x10 == 0)) {
        // 0: 1, 1: 2, 3: 1, 4: 1, 5: 4, 9: 1, 10: 1
        // 11: 1, 12: 1: 13: 1
        // 14: 2, 16: 1, 17: 1, 18: 1, 19: 1, 20: 1, 21: 1
        // 22: 1, 23: 1, 24: 1, 25: 1, 26: 1, 27: 3, 30: 1, 31: 1
        event->valu = ((rand() % (1 << 1)) << 0)
            | ((rand() % (1 << 2)) << 1)  | ((rand() % (1 << 1)) << 3)
            | ((rand() % (1 << 1)) << 4)  | ((rand() % (1 << 4)) << 5)
            | ((rand() % (1 << 4)) << 5)  | ((rand() % (1 << 1)) << 9)
            | ((rand() % (1 << 1)) << 10) | ((rand() % (1 << 1)) << 11)
            | ((rand() % (1 << 1)) << 12) | ((rand() % (1 << 1)) << 13)
            | ((rand() % (1 << 2)) << 14) | ((rand() % (1 << 1)) << 16)
            | ((rand() % (1 << 1)) << 17) | ((rand() % (1 << 1)) << 18)
            | ((rand() % (1 << 1)) << 19) | ((rand() % (1 << 1)) << 20)
            | ((rand() % (1 << 1)) << 21) | ((rand() % (1 << 1)) << 22)
            | ((rand() % (1 << 1)) << 23) | ((rand() % (1 << 1)) << 24)
            | ((rand() % (1 << 1)) << 25) | ((rand() % (1 << 1)) << 26)
            | ((rand() % (1 << 3)) << 27) | ((rand() % (1 << 1)) << 30)
            | ((rand() % (1 << 1)) << 31);
    }
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
    if ((!DisableInputProcessing) && virtio && event->addr == 0xe0004018) {
        event->valu = 0x100;
    }
    switch (__disimm_around_event_size(event->size, 8)) {
        case ViDeZZo_Byte: qemu_writeb(event->addr, event->valu & 0xFF); break;
        case ViDeZZo_Word: qemu_writew(event->addr, event->valu & 0xFFFF); break;
        case ViDeZZo_Long: qemu_writel(event->addr, event->valu & 0xFFFFFFFF); break;
        case ViDeZZo_Quad: qemu_writeq(event->addr, event->valu); break;
        default: fprintf(stderr, "wrong size of dispatch_mmio_write %d\n", event->size); break;
    }
    return 0;
}

static void qemu_outb(uint16_t addr, uint8_t value) {
    cpu_outb(addr, value);
}

static void qemu_outw(uint16_t addr, uint16_t value) {
    cpu_outw(addr, value);
}

static void qemu_outl(uint16_t addr, uint32_t value) {
    cpu_outl(addr, value);
}

uint64_t dispatch_pio_write(Event *event) {
    if (e1000e && event->addr == 0xc080)
        event->valu %= event->valu % 0xfffff;
    switch (__disimm_around_event_size(event->size, 4)) {
        case ViDeZZo_Byte: qemu_outb(event->addr, event->valu & 0xFF); break;
        case ViDeZZo_Word: qemu_outw(event->addr, event->valu & 0xFFFF); break;
        case ViDeZZo_Long: qemu_outl(event->addr, event->valu & 0xFFFFFFFF); break;
        default: fprintf(stderr, "wrong size of dispatch_pio_write %d\n", event->size); break;
    }
    return 0;
}

static void qemu_memwrite(uint64_t addr, const void *data, size_t size) {
    address_space_write(first_cpu->as, addr, MEMTXATTRS_UNSPECIFIED, data, size);
}

uint64_t dispatch_mem_write(Event *event) {
    qemu_memwrite(event->addr, event->data, event->size);
    return 0;
}

uint64_t dispatch_clock_step(Event *event) {
    QTestState *s = (QTestState *)gfctx_get_object(0);
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

// To avoid overlap between dyn-alloced and QEMU-assumed buffers,
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
    return guest_alloc(qemu_alloc, size);
}

static bool videzzo_free(uint64_t addr) {
    // free the dma accessible buffer in guest memory
    guest_free(qemu_alloc, addr);
    return true;
}

uint64_t dispatch_mem_alloc(Event *event) {
    return videzzo_malloc(event->valu);
}

uint64_t dispatch_mem_free(Event *event) {
    return videzzo_free(event->valu);
}

//
// QEMU specific initialization - Set up interfaces
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
                if (!interface_exists(event_type1, addr, mr->size)) {
                    add_interface(event_type1, addr, mr->size, mr->name, min, max, true);
                    add_interface(event_type2, addr, mr->size, mr->name, min, max, true);
                }
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

static QTestState *fuzz_qts;

// Copied from tests/qtest/fuzz/fuzz.c
#define MAX_EVENT_LOOPS 10
static void flush_events(QTestState *s) {
    int i = MAX_EVENT_LOOPS;
    while (g_main_context_pending(NULL) && i-- > 0) {
        main_loop_wait(false);
    }
}

//
// call into videzzo from QEMU
//
static int videzzo_qemu(uint8_t *Data, size_t Size) {
    QTestState *s = fuzz_qts;
    if (vnc_client_needed && !vnc_client_initialized) {
        init_vnc_client(s, vnc_port);
        vnc_client_initialized = true;
    }
    return videzzo_execute_one_input(Data, Size, s, &flush_events);
}

//
// QEMU specific initialization - Usage
//
static void usage(void) {
    printf("Please specify the following environment variables:\n");
    printf("QEMU_FUZZ_ARGS= the command line arguments passed to qemu\n");
    videzzo_usage();
    exit(0);
}

//
// QEMU specific initialization - Register all targets
//
static QGuestAllocator *get_qemu_alloc(QTestState *qts) {
    QOSGraphNode *node;
    QOSGraphObject *obj;

    // TARGET_NAME=i386    -> i386/pc
    // TARGET_NAME=arm     -> arm/raspi2b
    // TARGET_NAME=aarch64 -> aarch64/xlnx-zcu102
    // TODO: we may want to have customized allocator
    // for each arm and aarch64 virtual devices
    if (strcmp(TARGET_NAME, "i386") == 0) {
        node = qos_graph_get_node("i386/pc");
    } else if (strcmp(TARGET_NAME, "arm") == 0) {
        node = qos_graph_get_node("arm/raspi2b");
    } else if (strcmp(TARGET_NAME, "aarch64") == 0) {
        node = qos_graph_get_node("aarch64/xlnx-zcu102");
    } else if (strcmp(TARGET_NAME, "x86_64") == 0) {
        node = qos_graph_get_node("x86_64/pc");
    } else {
        g_assert(1 == 0);
    }

    g_assert(node->type == QNODE_MACHINE);

    obj = qos_machine_new(node, qts);
    qos_object_queue_destroy(obj);
    return obj->get_driver(obj, "memory");
}

// This is called in LLVMFuzzerTestOneInput
static void videzzo_qemu_pre() {
    QTestState *s = fuzz_qts;
    GHashTableIter iter;
    MemoryRegion *mr;
    QPCIBus *pcibus;
    char **mrnames;

    fuzzable_memoryregions = g_hash_table_new(NULL, NULL);
    fuzzable_pci_devices = g_ptr_array_new();

    mrnames = g_strsplit(getenv("QEMU_FUZZ_MRNAME"), ",", -1);
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
        if (strncmp("*virtio*", mrnames[i], strlen(mrnames[i])) == 0)
            virtio = true;
        locate_fuzzable_objects(qdev_get_machine(), mrnames[i]);
    }

    if (strcmp(TARGET_NAME, "i386") == 0 || strcmp(TARGET_NAME, "x86_64") == 0) {
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

    qemu_alloc = get_qemu_alloc(s);

#ifdef CLANG_COV_DUMP
    llvm_profile_initialize_file(true);
#endif
}

// This is called in LLVMFuzzerInitialize
static const char *fuzz_arch = TARGET_NAME;
static QTestState *qtest_setup(void) {
    qtest_server_set_send_handler(&qtest_client_inproc_recv, &fuzz_qts);
    return qtest_inproc_init(&fuzz_qts, false, fuzz_arch,
            &qtest_server_inproc_recv);
}

// This is called in LLVMFuzzerInitialize
static GString *videzzo_qemu_cmdline(ViDeZZoFuzzTarget *t) {
    GString *cmd_line = g_string_new(TARGET_NAME);
    if (!getenv("QEMU_FUZZ_ARGS")) {
        usage();
    }
    g_string_append_printf(cmd_line, " -display none \
                                      -machine accel=qtest, \
                                      -m 512M %s ", getenv("QEMU_FUZZ_ARGS"));
    return cmd_line;
}

// This is called in LLVMFuzzerInitialize
static GString *videzzo_qemu_predefined_config_cmdline(ViDeZZoFuzzTarget *t) {
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
    setenv("QEMU_FUZZ_ARGS", args_str, 1);
    g_free(args_str);

    setenv("QEMU_FUZZ_MRNAME", config->mrnames, 1);
    return videzzo_qemu_cmdline(t);
}

// This is called in LLVMFuzzerInitialize
static void register_videzzo_qemu_targets(void) {
    videzzo_add_fuzz_target(&(ViDeZZoFuzzTarget){
            .name = "videzzo-fuzz",
            .description = "Fuzz based on any qemu command-line args. ",
            .get_init_cmdline = videzzo_qemu_cmdline,
            .pre_fuzz = videzzo_qemu_pre,
            .fuzz = videzzo_qemu,
    });

    GString *name;
    const ViDeZZoFuzzTargetConfig *config;

    for (int i = 0; i < sizeof(predefined_configs) / sizeof(ViDeZZoFuzzTargetConfig); i++) {
        config = predefined_configs + i;
        // We haven't found a virtual device that is x86_64 only.
        // The reason why we support x86_64 is to show scalability of ViDeZZo.
        if (strcmp(TARGET_NAME, "x86_64") == 0) {
            if (strcmp(config->arch, "i386")) continue;
        } else {
            if (strcmp(TARGET_NAME, config->arch)) continue;
        }
        name = g_string_new("videzzo-fuzz");
        g_string_append_printf(name, "-%s", config->name);
        videzzo_add_fuzz_target(&(ViDeZZoFuzzTarget){
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

int LLVMFuzzerInitialize(int *argc, char ***argv, char ***envp) {
    char *target_name;
    const char *bindir;
    char *datadir;
    GString *cmd_line;
    ViDeZZoFuzzTarget *fuzz_target;

    // step 1: initialize fuzz targets
    qos_graph_init();
    module_call_init(MODULE_INIT_FUZZ_TARGET);
    module_call_init(MODULE_INIT_QOM);
    module_call_init(MODULE_INIT_LIBQOS);

    qemu_init_exec_dir(**argv);
    // step 2: find which fuzz target to run
    int rc = parse_fuzz_target_name(argc, argv, &target_name);
    if (rc == NAME_INBINARY) {
        /*
         * With oss-fuzz, the executable is kept in the root of a directory (we
         * cannot assume the path). All data (including bios binaries) must be
         * in the same dir, or a subdir. Thus, we cannot place the pc-bios so
         * that it would be in exec_dir/../pc-bios.
         * As a workaround, oss-fuzz allows us to use argv[0] to get the
         * location of the executable. Using this we add exec_dir/pc-bios to
         * the datadirs.
         */
        bindir = qemu_get_exec_dir();
        datadir = g_build_filename(bindir, "pc-bios", NULL);
        if (g_file_test(datadir, G_FILE_TEST_IS_DIR)) {
            qemu_add_data_dir(datadir);
        } else {
            g_free(datadir);
        }
    } else if (rc == NAME_INVALID) {
        usage();
    }

    // step 3: get the fuzz target
    fuzz_target = videzzo_get_fuzz_target(target_name);
    save_fuzz_target(fuzz_target);
    if (!fuzz_target) {
        usage();
    }

    fuzz_qts = qtest_setup();

    // step 4: prepare before QEMU init

    // step 5: construct QEMU init cmds and init QEMU
    /* Run QEMU's softmmu main with the fuzz-target dependent arguments */
    cmd_line = fuzz_target->get_init_cmdline(fuzz_target);
    g_string_append_printf(cmd_line, " -qtest /dev/null -qtest-log none");

    /* Split the runcmd into an argv and argc */
    wordexp_t result;
    wordexp(cmd_line->str, &result, 0);
    g_string_free(cmd_line, true);

    qemu_init(result.we_wordc, result.we_wordv, NULL);

    /* re-enable the rcu atfork, which was previously disabled in qemu_init */
    rcu_enable_atfork();

    /*
     * Disable QEMU's signal handlers, since we manually control the main_loop,
     * and don't check for main_loop_should_exit
     */
    signal(SIGINT, SIG_DFL);
    signal(SIGHUP, SIG_DFL);
    signal(SIGTERM, SIG_DFL);

    return 0;
}
