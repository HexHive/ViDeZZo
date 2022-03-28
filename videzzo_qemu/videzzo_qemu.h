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
#include "fuzz.h"
#include "qos_fuzz.h"
#include "fork_fuzz.h"
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
#include <rfb/rfbclient.h>
#include <sys/socket.h>

bool ViDeZZoFuzzer;
static bool qtest_log_enabled;
static void usage(void);

// TODO implement a timeout handler in videzzo
#define DEFAULT_TIMEOUT_US 100000
#define USEC_IN_SEC 1000000000
static useconds_t timeout = DEFAULT_TIMEOUT_US;

static inline void handle_timeout(int sig) {
    if (qtest_log_enabled) {
        fprintf(stderr, "[Timeout]\n");
        fflush(stderr);
    }
    _Exit(0);
}

static GHashTable *fuzzable_memoryregions;
static GPtrArray *fuzzable_pci_devices;
extern QTestState *get_qtest_state(void);

// P.S. "videzzo" is only a mark here.
static QGuestAllocator *videzzo_alloc;

// To avoid overlap between dyn-alloced and QEMU-assumed buffers,
// where dyn-alloced buffers start from 1M,
// we enforce the dynamic alloc memory to be higher than 256M.
#define I386_MEM_LOW  0x10000000
#define I386_MEM_HIGH 0x20000000
uint64_t AroundInvalidAddress(uint64_t physaddr);

static uint64_t (*videzzo_guest_alloc)(size_t) = NULL;
static void (*videzzo_guest_free)(size_t) = NULL;

static uint64_t __wrap_guest_alloc(size_t size) {
    if (videzzo_guest_alloc)
        return videzzo_guest_alloc(size);
    else
        // alloc a dma accessible buffer in guest memory
        return guest_alloc(videzzo_alloc, size);
}

static void __wrap_guest_free(uint64_t addr) {
    if (videzzo_guest_free)
        videzzo_guest_free(addr);
    else
        // free the dma accessible buffer in guest memory
        guest_free(videzzo_alloc, addr);
}

static uint64_t videzzo_malloc(size_t size) {
    return __wrap_guest_alloc(size);
}

static bool videzzo_free(uint64_t addr) {
    // give back the guest memory
    __wrap_guest_free(addr);
    return true;
}

static int sockfds[2];
static bool sockfds_initialized = false;

static void init_sockets(void) {
    int ret = socketpair(PF_UNIX, SOCK_STREAM, 0, sockfds);
    g_assert_cmpint(ret, !=, -1);
    fcntl(sockfds[0], F_SETFL, O_NONBLOCK);
    sockfds_initialized = true;
}

static rfbClient* client;
static bool vnc_client_needed = false;
static bool vnc_client_initialized = false;
static void vnc_client_output(rfbClient* client, int x, int y, int w, int h) {}
static int vnc_port;

/*
 * FindFreeTcpPort tries to find unused TCP port in the range
 * (SERVER_PORT_OFFSET, SERVER_PORT_OFFSET + 99]. Returns 0 on failure.
 */
static int FindFreeTcpPort1(void) {
  int sock, port;
  struct sockaddr_in addr;

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);

  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    rfbClientErr(": FindFreeTcpPort: socket\n");
    return 0;
  }

  for (port = SERVER_PORT_OFFSET + 99; port > SERVER_PORT_OFFSET; port--) {
    addr.sin_port = htons((unsigned short)port);
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
      close(sock);
      return port;
    }
  }

  close(sock);
  return 0;
}

static void init_vnc(void) {
    vnc_port = FindFreeTcpPort1();
    if (!vnc_port) {
        _Exit(1);
    }
}

static int init_vnc_client(QTestState *s) {
    client = rfbGetClient(8, 3, 4);
    if (fork() == 0) {
        client->GotFrameBufferUpdate = vnc_client_output;
        client->serverPort = vnc_port;
        if(!rfbInitClient(client, NULL, NULL)) {
            _Exit(1);
        }
        while (1) {
            if(WaitForMessage(client, 50) < 0)
                break;
            if(!HandleRFBServerMessage(client))
                break;
        }
        rfbClientCleanup(client);
        _Exit(0);
    } else {
        flush_events(s);
    }
    vnc_client_initialized = true;
    return 0;
}

static void vnc_client_receive(void) {
    while (1) {
        if(WaitForMessage(client, 50) < 0)
            break;
        if(!HandleRFBServerMessage(client))
            break;
    }
}

static void uninit_vnc_client(void) {
    rfbClientCleanup(client);
}

typedef struct videzzo_qemu_config {
    const char *arch, *name, *args, *objects, *mrnames, *file;
    gchar* (*argfunc)(void); /* Result must be freeable by g_free() */
    bool socket; /* Need support or not */
    bool display; /* Need support or not */
    bool byte_address; /* Need support or not */
} videzzo_qemu_config;

typedef struct MemoryRegionPortioList {
    MemoryRegion mr;
    void *portio_opaque;
    MemoryRegionPortio ports[];
} MemoryRegionPortioList;

static inline GString *videzzo_qemu_cmdline(FuzzTarget *t)
{
    GString *cmd_line = g_string_new(TARGET_NAME);
    if (!getenv("QEMU_FUZZ_ARGS")) {
        usage();
    }
    g_string_append_printf(cmd_line, " -display none \
                                      -machine accel=qtest, \
                                      -m 512M %s ", getenv("QEMU_FUZZ_ARGS"));
    return cmd_line;
}

static inline GString *videzzo_qemu_predefined_config_cmdline(FuzzTarget *t)
{
    GString *args = g_string_new(NULL);
    const videzzo_qemu_config *config;
    g_assert(t->opaque);
    int port = 0;

    config = t->opaque;
    if (config->socket && !sockfds_initialized) {
        init_sockets();
        port = sockfds[1];
    }
    if (config->display) {
        init_vnc();
        vnc_client_needed = true;
        port = vnc_port - SERVER_PORT_OFFSET;
    }
    if (config->byte_address) {
        setenv("VIDEZZO_BYTE_ALIGNED_ADDRESS", "1", 1);
    }
    setenv("QEMU_AVOID_DOUBLE_FETCH", "1", 1);
    if (config->argfunc) {
        gchar *t = config->argfunc();
        g_string_append_printf(args, t, port);
        g_free(t);
    } else {
        g_assert_nonnull(config->args);
        g_string_append_printf(args, config->args, port);
    }
    gchar *args_str = g_string_free(args, FALSE);
    setenv("QEMU_FUZZ_ARGS", args_str, 1);
    g_free(args_str);

    setenv("QEMU_FUZZ_OBJECTS", config->objects, 1);
    setenv("QEMU_FUZZ_MRNAME", config->mrnames, 1);
    return videzzo_qemu_cmdline(t);
}

static QGuestAllocator *get_videzzo_alloc(QTestState *qts) {
    QOSGraphNode *node;
    QOSGraphObject *obj;

    // TARGET_NAME=i386 -> i386/pc
    // TARGET_NAME=     -> x86_64/pc
    node = qos_graph_get_node("i386/pc");
    g_assert(node->type == QNODE_MACHINE);

    obj = qos_machine_new(node, qts);
    qos_object_queue_destroy(obj);
    return obj->get_driver(obj, "memory");
}

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
        .objects = "*usb* *uhci* *xhci*",
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
        .objects = "*usb* *hci*",
        .mrnames = "*capabilities*,*operational*,*ports*",
        .file = "hw/usb/hcd-ehci.c",
        .socket = false,
    },{
        .arch = "i386",
        .name = "ohci",
        .args = "-machine q35 -nodefaults -device pci-ohci,num-ports=6 "
        COMMON_USB_CMD,
        .objects = "*usb* *ohci*",
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
        .objects = "*uhci*",
        .mrnames = "*uhci*",
        .file = "hw/usb/hcd-uhci.c",
        .socket = false,
    },{
        .arch = "i386",
        .name = "vmxnet3",
        .args = "-machine q35 -nodefaults "
        "-device vmxnet3,netdev=net0 -netdev user,id=net0",
        .objects = "vmxnet3",
        .mrnames = "*vmxnet3-b0*,*vmxnet3-b1*",
        .file = "hw/net/vmxnet3.c",
        .socket = true,
    },{
        .arch = "i386",
        .name = "ne2000",
        .args = "-machine q35 -nodefaults "
        "-device ne2k_pci,netdev=net0 -netdev user,id=net0",
        .objects = "ne2k*",
        .mrnames = "*ne2000*",
        .file = "hw/net/ne2000.c",
        .socket = true,
        .byte_address = true,
    },{
        .arch = "i386",
        .name = "pcnet",
        .args = "-machine q35 -nodefaults "
        "-device pcnet,netdev=net0 -netdev user,id=net0",
        .objects = "pcnet",
        .mrnames = "*pcnet-mmio*,*pcnet-io*",
        .file = "hw/net/pcnet-pci.c",
        .socket = true,
        .byte_address = true,
    },{
        .arch = "i386",
        .name = "rtl8139",
        .args = "-machine q35 -nodefaults "
        "-device rtl8139,netdev=net0 -netdev user,id=net0",
        .objects = "rtl8139",
        .mrnames = "*rtl8139*",
        .file = "hw/net/rtl8139.c",
        .socket = true,
        .byte_address = true,
    },{
        .arch = "i386",
        .name = "i82550",
        .args = "-machine q35 -nodefaults "
        "-device i82550,netdev=net0 -netdev user,id=net0",
        .objects = "*eepro100-mmio*,*eepro100-io*,*eepro100-flash*",
        .mrnames = "*eepro100-mmio*,*eepro100-io*,*eepro100-flash*",
        .file = "hw/net/eepro100.c",
        .socket = true,
        .byte_address = true,
    },{
        .arch = "i386",
        .name = "e1000",
        .args = "-M q35 -nodefaults "
        "-device e1000,netdev=net0 -netdev user,id=net0",
        .objects = "e1000",
        .mrnames = "*e1000-mmio*,*e1000-io*",
        .file = "hw/net/e1000.c",
        .socket = true,
    },{
        .arch = "i386",
        .name = "e1000e",
        .args = "-M q35 -nodefaults "
        "-device e1000e,netdev=net0 -netdev user,id=net0",
        .objects = "e1000e",
        .mrnames = "*e1000e-mmio*,*e1000e-io*",
        .file = "hw/net/e1000e.c",
        .socket = true,
    },{
        .arch = "i386",
        .name = "ac97",
        .args = "-machine q35 -nodefaults "
        "-device ac97,audiodev=snd0 -audiodev none,id=snd0 -nodefaults",
        .objects = "ac97*",
        .mrnames = "*ac97-nam*,*ac97-nabm*",
        .file = "hw/audio/ac97.c",
        .socket = false,
        .byte_address = true,
    },{
        .arch = "i386",
        .name = "cs4231a",
        .args = "-machine q35 -nodefaults "
        "-device cs4231a,audiodev=snd0 -audiodev none,id=snd0 -nodefaults",
        .objects = "cs4231a* i8257*",
        .mrnames = "*cs4231a*,*dma-chan*,*dma-page*,*dma-pageh*,*dma-cont*",
        .file = "hw/audio/cs4231a.c",
        .socket = false,
        .byte_address = true,
    },{
        .arch = "i386",
        .name = "cs4231",
        .args = "-machine q35 -nodefaults "
        "-device cs4231,audiodev=snd0 -audiodev none,id=snd0 -nodefaults",
        .objects = "cs4231a* i8257*",
        .mrnames = "*cs4231*,*dma-chan*,*dma-page*,*dma-pageh*,*dma-cont*",
        .file = "hw/audio/cs4231.c",
        .socket = false,
    },{
        .arch = "i386",
        .name = "es1370",
        .args = "-machine q35 -nodefaults "
        "-device es1370,audiodev=snd0 -audiodev none,id=snd0 -nodefaults",
        .objects = "es1370*",
        .mrnames = "*es1370*",
        .file = "hw/audio/es1370.c",
        .socket = false,
    },{
        .arch = "i386",
        .name = "sb16",
        .args = "-machine q35 -nodefaults "
        "-device sb16,audiodev=snd0 -audiodev none,id=snd0 -nodefaults",
        .objects = "sb16* i8257*",
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
        .objects = "intel-hda",
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
        .objects = "*ati.mmregs*",
        .mrnames = "*ati.mmregs*",
        .file = "hw/display/ati.c",
        .socket = false,
        .display = true,
    },{
        .arch = "i386",
        .name = "cirrus-vga",
        .args = "-machine q35 -nodefaults -device cirrus-vga "
        "-display vnc=localhost:%d -L ../pc-bios/",
        .objects = "cirrus*",
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
        .objects = "fd* floppy* i8257",
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
        .objects = "sd*",
        .mrnames = "*sdhci*",
        .file = "hw/sd/sdhci-pci.c hw/sd/sdhci.c",
        .socket = false,
    },{
        .arch = "i386",
        .name = "ahci-hd",
        .args = "-machine q35 -nodefaults "
        "-drive file=null-co://,if=none,format=raw,id=disk0 "
        "-device ide-hd,drive=disk0",
        .objects = "*ahci*",
        .mrnames = "*ahci*",
        .file = "hw/ide/ahci.c",
        .socket = false,
    },{
        .arch = "i386",
        .name = "ahci-cd",
        .args = "-machine q35 -nodefaults "
        "-drive file=null-co://,if=none,format=raw,id=disk0 "
        "-device ide-cd,drive=disk0",
        .objects = "*ahci*",
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
        .objects = "*lsi-mmio*,*lsi-ram*,*lsi-io*",
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
        .objects = "megasas*",
        .mrnames = "*megasas-mmio*,*megasas-io*,*megasas-queue*",
        .file = "hw/scsi/megasas.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "smc91c111",
        .args = "-machine mainstone",
        .objects = "*smc91c111-mmio*",
        .mrnames = "*smc91c111-mmio*",
        .file = "hw/net/smc91c111.c",
        .socket = true,
    }
};

#endif /* QEMU_VIDEZZO_H */
