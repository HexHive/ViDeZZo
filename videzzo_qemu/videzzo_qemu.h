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
    /* {
        .name = "virtio-net-pci-slirp",
        .args = "-M q35 -nodefaults "
        "-device virtio-net,netdev=net0 -netdev user,id=net0",
        .objects = "virtio*",
        .socket = false,
    },{
        .name = "virtio-blk",
        .args = "-machine q35 -device virtio-blk,drive=disk0 "
        "-drive file=null-co://,id=disk0,if=none,format=raw",
        .objects = "virtio*",
        .socket = false,
    },{
        .name = "virtio-scsi",
        .args = "-machine q35 -device virtio-scsi,num_queues=8 "
        "-device scsi-hd,drive=disk0 "
        "-drive file=null-co://,id=disk0,if=none,format=raw",
        .objects = "scsi* virtio*",
        .socket = false,
    },{
        .name = "virtio-gpu",
        .args = "-machine q35 -nodefaults -device virtio-gpu",
        .objects = "virtio*",
        .socket = false,
    },{
        .name = "virtio-vga",
        .args = "-machine q35 -nodefaults -device virtio-vga",
        .objects = "virtio*",
        .socket = false,
    },{
        .name = "virtio-rng",
        .args = "-machine q35 -nodefaults -device virtio-rng",
        .objects = "virtio*",
        .socket = false,
    },{
        .name = "virtio-balloon",
        .args = "-machine q35 -nodefaults -device virtio-balloon",
        .objects = "virtio*",
        .socket = false,
    },{
        .name = "virtio-serial",
        .args = "-machine q35 -nodefaults -device virtio-serial",
        .objects = "virtio*",
        .socket = false,
    },{
        .name = "virtio-mouse",
        .args = "-machine q35 -nodefaults -device virtio-mouse",
        .objects = "virtio*",
        .socket = false,
    },{
        .name = "virtio-9p",
        .argfunc = generic_fuzzer_virtio_9p_args,
        .objects = "virtio*",
        .socket = false,
    },{
        .name = "virtio-9p-synth",
        .args = "-machine q35 -nodefaults "
        "-device virtio-9p,fsdev=hshare,mount_tag=hshare "
        "-fsdev synth,id=hshare",
        .objects = "virtio*",
        .socket = false,
    },*/{
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
        .name = "kvaser-can",
        .args = "-machine q35 -nodefaults "
        "-object can-bus,id=canbus0 -device kvaser_pci,canbus=canbus0",
        // "-object can-host-socketcan,id=canhost0,if=can0,canbus=canbus0",
        .objects = "*kvaser_pci-s5920*,*kvaser_pci-sja*,*kvaser_pci-xilinx*",
        .mrnames = "*kvaser_pci-s5920*,*kvaser_pci-sja*,*kvaser_pci-xilinx*",
        .socket = true,
    },{
        .arch = "i386",
        .name = "pcm3680-can",
        .args = "-machine q35 -nodefaults "
        "-object can-bus,id=canbus "
        "-device pcm3680_pci,canbus0=canbus,canbus1=canbus",
        // "-object can-host-socketcan,id=canhost0,if=can0,canbus=canbus0",
        .objects = "*pcm3680i_pci-sja1*,*pcm3680i_pci-sja2*",
        .mrnames = "*pcm3680i_pci-sja1*,*pcm3680i_pci-sja2*",
        .socket = true,
    },/*{
        .arch = "i386",
        .name = "mioe3680-can",
        .args = "-machine q35 -nodefaults "
        "-object can-bus,id=canbus "
        "-device mioe3680_pci,canbus0=canbus",
        // "-object can-host-socketcan,id=canhost0,if=can0,canbus=canbus0",
        .objects = "*mioe3680_pci-sja1*,*mioe3680_pci-sja2*",
        .mrnames = "*mioe3680_pci-sja1*,*mioe3680_pci-sja2*",
        .socket = false,
    },*/{
        .arch = "i386",
        .name = "ctu-can",
        .args = "-machine q35 -nodefaults "
        "-object can-bus,id=canbus0-bus "
        "-device ctucan_pci,canbus0=canbus0-bus,canbus1=canbus0-bus",
        // "-object can-host-socketcan,if=can0,canbus=canbus0-bus,id=canbus0-socketcan",
        .objects = "*ctucan_pci-core0*,*ctucan_pci-core1*",
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
        .objects = "*rocker-mmio*",
        .mrnames = "*rocker-mmio*",
        .file = "hw/net/rocker/rocker.c",
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
        .arch = "i386",
        .name = "parallel",
        .args = "-machine q35 -nodefaults "
        "-parallel file:/dev/null",
        .objects = "parallel*",
        .mrnames = "*parallel*",
        .file = "hw/char/parallel.c",
        .socket = false,
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
        .name = "qxl",
        .args = "-machine q35 -nodefaults -device qxl "
        "-display vnc=localhost:%d -L ../pc-bios/",
        .objects = "*qxl-ioports*",
        .mrnames = "*qxl-ioports*",
        .file = "hw/display/qxl.c",
        .socket = false,
        .display = true,
    },{
        .arch = "i386",
        .name = "vmware-svga",
        .args = "-machine q35 -nodefaults -device vmware-svga "
        "-display vnc=localhost:%d -L ../pc-bios/",
        .objects = "*vmsvga-io*",
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
        .objects = "*vga-lowmem*,*vga ioports remapped*,"
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
        .objects = "*vga-lowmem*,*vga ioports remapped*,"
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
        .objects = "*bochs dispi interface*,*qemu extended regs*,*bochs-display-mmio*",
        .mrnames = "*bochs dispi interface*,*qemu extended regs*,*bochs-display-mmio*",
        .file = "hw/display/bochs-display.c",
        .socket = false,
        .display = true,
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
        .name = "nvme",
        .args = "-machine pc -nodefaults "
        "-drive id=nvm,file=null-co://,file.read-zeroes=on,if=none,format=raw "
        "-object memory-backend-file,id=mb,share=on,mem-path=/tmp/nvm-mb,size=4096 "
        "-device nvme,cmb_size_mb=32,serial=deadbeef,drive=nvm,pmrdev=mb",
        .objects = "*nvme*,*nvme-cmb*",
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
        .objects = "sd*",
        .mrnames = "*sdhci*",
        .file = "hw/sd/sdhci-pci.c hw/sd/sdhci.c",
        .socket = false,
    },/*{
        .arch = "i386",
        .name = "ide-hd",
        .args = "-machine pc -nodefaults "
        "-drive file=null-co://,if=none,format=raw,id=disk0 "
        "-device ide-hd,drive=disk0",
        .objects = "*ide*",
        .mrnames = "*ide*",
        .file = "hw/ide/qdev.c",
        .socket = false,
    },{
        .arch = "i386",
        .name = "ide-atapi",
        .args = "-machine pc -nodefaults "
        "-drive file=null-co://,if=none,format=raw,id=disk0 "
        "-device ide-cd,drive=disk0",
        .objects = "*ide*",
        .mrnames = "*ide*",
        .file = "hw/ide/qdev.c",
        .socket = false,
    },*/{
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
    },/*{
        .arch = "i386",
        .name = "piix3-ide",
        // suitable for piix3-ide, piix4-ide and piix3-ide-xen
        .args = "-machine q35 -nodefaults -device piix3-ide",
        .objects = "*piix-bmdma*,*bmdma*",
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
        .objects = "*lsi-mmio*,*lsi-ram*,*lsi-io*",
        .mrnames = "*lsi-mmio*,*lsi-ram*,*lsi-io*",
        .file = "hw/scsi/lsi53c895a.c",
        .socket = false,
        .byte_address = true,
    },{
        .arch = "i386",
        .name = "mptsas1068",
        .args = "-machine q35 -nodefaults "
        "-device mptsas1068,id=scsi0 "
        "-device scsi-hd,drive=drive0,bus=scsi0.0,channel=0,scsi-id=0,lun=0 "
        "-drive file=null-co://,if=none,format=raw,id=drive0 "
        "-device scsi-hd,drive=drive1,bus=scsi0.0,channel=0,scsi-id=1,lun=0 "
        "-drive file=null-co://,if=none,format=raw,id=drive1",
        .objects = "*mptsas-mmio*,*mptsas-io*,*mptsas-diag*",
        .mrnames = "*mptsas-mmio*,*mptsas-io*,*mptsas-diag*",
        .file = "hw/scsi/mptsas.c",
        .socket = false,
    },{
        .arch = "i386",
        .name = "vmw-pvscsi",
        .args = "-machine q35 -nodefaults -device pvscsi",
        .objects = "*pvscsi-io*",
        .mrnames = "*pvscsi-io*",
        .file = "hw/scsi/vmw_pvscsi.c",
        .socket = false,
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
        .arch = "i386",
        .name = "am53c974",
        .args = "-machine q35 -nodefaults "
        "-device am53c974,id=scsi "
        "-device scsi-hd,drive=disk0 "
        "-drive id=disk0,if=none,file=null-co://,format=raw",
        .objects = "*esp* *scsi* *am53c974*",
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
        .objects = "*fwcfg.ctl*,*fwcfg.data*,*fwcfg.dma*,"
        "*fwcfg*",
        .mrnames = "*fwcfg.ctl*,*fwcfg.data*,*fwcfg.dma*,"
        "*fwcfg*",
        .file = "hw/nvram/fw_cfg.c",
        .socket = false,
    },/*{
        .arch = "arm",
        .name = "tusb6010",
        .args = "-machine n810 -m 128M -usb",
        .objects = "*tusb-async* *",
        .mrnames = "*tusb-async*",
        .file = "hw/usb/tusb6010.c",
        .socket = false,
    },*/{
        .arch = "arm",
        .name = "imx-usb-phy",
        .args = "-machine sabrelite",
        .objects = "*imx-usbphy*",
        .mrnames = "*imx-usbphy*",
        .file = "hw/usb/imx-usb-phy.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "chipidea",
        .args = "-machine sabrelite -nodefaults "
        COMMON_USB_CMD_1,
        .objects = "*usb-chipidea.misc*,"
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
        .objects = "*versal.usb2Ctrl_alias*",
        .mrnames = "*versal.usb2Ctrl_alias*",
        .file = "hw/usb/xlnx-versal-usb2-ctrl-regs.c",
        .socket = false,
    },{
        // duplicated
        .arch = "aarch64",
        .name = "dwc3",
        .args = "-machine xlnx-versal-virt -nodefaults "
        COMMON_USB_CMD,
        .objects = "*versal.dwc3_alias*",
        .mrnames = "*versal.dwc3_alias*",
        .file = "hw/usb/hcd-dwc3.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "dwc2",
        // arm supports raspi0/1/2, aarch64 supports raspi3
        .args = "-machine raspi0 -nodefaults "
        COMMON_USB_CMD,
        .objects = "*dwc2-io* *dwc2-fifo*",
        .mrnames = "*dwc2-io*,*dwc2-fifo*",
        .file = "hw/usb/hcd-dwc2.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "xgmac",
        .args = "-machine midway",
        .objects = "*xgmac*",
        .mrnames = "*xgmac*",
        .file = "hw/net/xgmac.c",
        .socket = true,
    },{
        .arch = "arm",
        .name = "stellaris-enet",
        .args = "-machine lm3s6965evb",
        .objects = "*stellaris_enet*",
        .mrnames = "*stellaris_enet*",
        .file = "hw/net/stellaris_enet.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "smc91c111",
        .args = "-machine mainstone",
        .objects = "*smc91c111-mmio*",
        .mrnames = "*smc91c111-mmio*",
        .file = "hw/net/smc91c111.c",
        .socket = true,
    },{
        .arch = "arm",
        .name = "npcm7xx-emc",
        .args = "-machine npcm750-evb",
        .objects = "*npcm7xx-emc*",
        .mrnames = "*npcm7xx-emc*",
        .file = "hw/net/npcm7xx_emc.c",
        .socket = false,
    },/*{
        .arch = "arm",
        .name = "msf2-emac",
        .args= "-machine emcraft-sf2",
        .objects = "*msf2-emac*",
        .mrnames = "*msf2-emac*",
        .file = "hw/net/msf2-emac.c",
        .socket = false,
    },*/{
        .arch = "arm",
        .name = "lan9118",
        .args = "-machine smdkc210",
        .objects = "*lan9118-mmio*",
        .mrnames = "*lan9118-mmio*",
        .file = "hw/net/lan9118.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "imx-fec",
        .args = "-machine sabrelite",
        .objects = "*imx.fec*",
        .mrnames = "*imx.fec*",
        .file = "hw/net/imx_fec.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "ftgmac100",
        .args = "-machine palmetto-bmc",
        .objects = "*ftgmac100*,*aspeed-mmi*",
        .mrnames = "*ftgmac100*,*aspeed-mmi*",
        .file = "hw/net/ftgmac100.c",
        .socket = false,
    },{
        .arch = "aarch64",
        .name = "cadence-gem",
        .args = "-machine xlnx-versal-virt "
        "-net nic,model=cadence_gem,netdev=net0 -netdev user,id=net0",
        .objects = "*enet*",
        .mrnames = "*enet*",
        .file = "hw/net/cadence_gem.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "allwinner-sun8i-emac",
        .args = "-machine orangepi-pc -m 1G",
        .objects = "*allwinner-sun8i-emac*",
        .mrnames = "*allwinner-sun8i-emac*",
        .file = "hw/net/allwinner-sun8i-emac.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "allwinner-emac",
        .args = "-machine cubieboard -nodefaults "
        "-net nic,model=allwinner-emac,netdev=net0 -netdev user,id=net0",
        .objects = "*aw_emac*",
        .mrnames = "*aw_emac*",
        .file = "hw/net/allwinner-emac.c",
        .socket = false,
    },{
        .arch = "aarch64",
        .name = "xlnx-zynqmp-can",
        .args = "-machine xlnx-zcu102",
        .objects = "*xlnx.zynqmp-can*",
        .mrnames = "*xlnx.zynqmp-can*",
        .file = "hw/net/can/xlnx-zynqmp-can.c",
        .socket = false,
    },{
        .arch = "aarch64",
        .name = "xlnx-dp",
        .args = "-machine xlnx-zcu102",
        .objects = "*.core*,*.v_blend*,*.av_buffer_manager*,*.audio*",
        .mrnames = "*.core*,*.v_blend*,*.av_buffer_manager*,*.audio*",
        .file = "hw/display/xlnx_dp.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "exynos4210-fimd",
        .args = "-machine smdkc210",
        .objects = "*exynos4210.fimd*",
        .mrnames = "*exynos4210.fimd*",
        .file = "hw/display/exynos4210_fimd.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "omap-dss",
        .args = "-machine n810 -m 128M",
        .objects = "*omap.diss1*,*omap.disc1*,*omap.rfbi1*,*omap.venc1*,*omap.im3*",
        .mrnames = "*omap.diss1*,*omap.disc1*,*omap.rfbi1*,*omap.venc1*,*omap.im3*",
        .file = "hw/net/omap_dss.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "omap-lcdc",
        .args = "-machine sx1-v1 -m 32M",
        .objects = "*omap.lcdc*",
        .mrnames = "*omap.lcdc*",
        .file = "hw/net/omap_lcdc.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "pl110",
        .args = "-machine integratorcp",
        .objects = "*pl110*",
        .mrnames = "*pl110*",
        .file = "hw/display/pl110.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "pxa2xx-lcd",
        .args = "-machine verdex",
        .objects = "*pxa2xx-lcd-controller*",
        .mrnames = "*pxa2xx-lcd-controller*",
        .file = "hw/display/pxa2xx_lcd.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "tc6393xb",
        .args = "-machine tosa",
        .objects = "*tc6393xb*",
        .mrnames = "*tc6393xb*",
        .file = "hw/display/tc6393xb.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "pl041",
        .args = "-machine integratorcp",
        .objects = "*pl041*",
        .mrnames = "*pl041*",
        .file = "hw/audio/pl041.c",
        .socket = false,
    },/*{
        .arch = "arm",
        .name = "pflash-cfi02",
        .args = "-machine xilinx-zynq-a9",
        .objects = "*zynq.pflash*",
        .mrnames = "*zynq.pflash*",
        .file = "hw/block/pflash_cfi02.c",
        .socket = false,
    },*/{
        .arch = "arm",
        .name = "pflash-cfi01",
        .args = "-machine collie",
        .objects = "*collie.fl1*,*collie.fl2*",
        .mrnames = "*collie.fl1*,*collie.fl2*",
        .file = "hw/block/pflash_cfi01.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "onenand",
        .args = "-machine n810 -m 128M",
        .objects = "*onenand*",
        .mrnames = "*onenand*",
        .file = "hw/block/onenand.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "allwinner-sdhost",
        .args = "-machine cubieboard",
        .objects = "*allwinner-sdhost*",
        .mrnames = "*allwinner-sdhost*",
        .file = "hw/sd/allwinner-sdhost.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "bcm2835-sdhost",
        // arm supports raspi0/1/2, aarch64 supports raspi3
        .args = "-machine raspi0",
        .objects = "*bcm2835-sdhost*",
        .mrnames = "*bcm2835-sdhost*",
        .file = "hw/sd/bcm2835_sdhost.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "omap-mmc",
        .args = "-machine sx1-v1 -m 32M",
        .objects = "*omap.mmc*",
        .mrnames = "*omap.mmc*",
        .file = "hw/sd/omap_mmc.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "pl181",
        .args = "-machine integratorcp",
        .objects = "*pl181*",
        .mrnames = "*pl181*",
        .file = "hw/sd/pl181.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "pxa2xx-mmci",
        .args = "-machine verdex",
        .objects = "*pxa2xx-mmci*",
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
        .objects= "*ahci* *ahci-idp*",
        .mrnames = "*ahci*,*ahci-idp*",
        .file = "hw/ide/ahci.c",
        .socket = false,
    },{
        .arch = "arm",
        .name = "npcm7xx-otp",
        .args = "-machine npcm750-evb",
        .objects = "*npcm7xx-emc*",
        .mrnames = "*regs*",
        .file = "hw/nvram/npcm7xx_otp.c",
        .socket = false,
    }, {
        .arch = "arm",
        .name = "nrf51-nvm",
        .args = "-machine microbit",
        .objects = "*nrf51_soc.nvmc*,*nrf51_soc.ficr*,"
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
        .objects = "*sp804*",
        .mrnames = "*sp804*",
        .file = "hw/timer/arm_timer.c",
        .socket = false,
    }, {
        .arch = "arm",
        .name = "pl011",
        .args = "-machine midway",
        .objects = "*pl011*",
        .mrnames = "*pl011*",
        .file = "hw/char/pl011.c",
        .socket = false,
    }, {
        .arch = "arm",
        .name = "highbank-regs",
        .args = "-machine midway",
        .objects = "*highbank_regs*",
        .mrnames = "*highbank_regs*",
        .file = "hw/arm/highbank.c",
        .socket = false,
    }, {
        .arch = "arm",
        .name = "pl061",
        .args = "-machine midway",
        .objects = "*pl061*",
        .mrnames = "*pl061*",
        .file = "hw/gpio/pl061.c",
        .socket = false,
    }, {
        .arch = "arm",
        .name = "pl031",
        .args = "-machine midway",
        .objects = "*pl031*",
        .mrnames = "*pl031*",
        .file = "hw/rtc/pl031.c",
        .socket = false,
    }, {
        .arch = "arm",
        .name = "pl022",
        .args = "-machine midway",
        .objects = "*pl022*",
        .mrnames = "*pl022*",
        .file = "hw/ssi/pl022.c",
        .socket = false,
    }, /* xgmac/ahci see above */
    /* only in highbank */ {
        .arch = "arm",
        .name = "a9-scu",
        .args = "-machine highbank",
        .objects = "*a9-scu*",
        .mrnames = "*a9-scu*",
        .file = "hw/misc/a9scu.c",
        .socket = false,
    }, {
        .arch = "arm",
        .name = "arm-gic",
        .args = "-machine highbank",
        .objects = "*gic_dist*,*gic_cpu*,*gic_viface*,*gic_vcpu*",
        .mrnames = "*gic_dist*,*gic_cpu*,*gic_viface*,*gic_vcpu*",
        .file = "hw/intc/arm_gic.c hw/intc/arm_gic_common.c",
        .socket = false,
    }, {
        .arch = "arm",
        .name = "a9-gtimer",
        .args = "-machine highbank",
        .objects = "*a9gtimer shared*,*a9gtimer per cpu*",
        .mrnames = "*a9gtimer shared*,*a9gtimer per cpu*",
        .file = "hw/timer/a9gtimer.c",
        .socket = false,
    }, {
        .arch = "arm",
        .name = "arm-mptimer",
        .args = "-machine highbank",
        .objects = "*arm_mptimer_timer*,*arm_mptimer_timerblock*",
        .mrnames = "*arm_mptimer_timer*,*arm_mptimer_timerblock*",
        .file = "hw/timer/arm_mptimer.c",
        .socket = false,
    },
    /* xlnx-zcu102 */
    /* gic/cadence-gem/xlnx-zynqmp-can
     * sysbus-ahci/sdhci/xlnx-dp see above */ {
        .arch = "aarch64",
        .name = "cadence-uart",
        .args = "-machine xlnx-zcu102",
        .objects = "*uart*",
        .mrnames = "*uart*",
        .file = "hw/char/cadence_uart.c",
        .socket = false,
    }, {
        .arch = "aarch64",
        // xilinx-spips + mmio -> xilinx-qspips
        // xilinx-qspips + fifo -> xlnx-zynqmp-qspips
        .name = "xlnx-zynqmp-qspips",
        .args = "-machine xlnx-zcu102",
        .objects = "*spi*,*lqspi*",
        .mrnames = "*spi*,*lqspi*",
        .file = "hw/ssi/xilinx_spips.c",
        .socket = false,
    }, {
        .arch = "aarch64",
        .name = "xlnx-dpdma",
        .args = "-machine xlnx-zcu102",
        .objects = "*xlnx.dpdma*",
        .mrnames = "*xlnx.dpdma*",
        .file = "hw/dma/xlnx_dpdma.c",
        .socket = false,
    }, {
        .arch = "aarch64",
        .name = "xlnx-zynqmp-ipi",
        .args = "-machine xlnx-zcu102",
        .objects = "*xlnx.zynqmp_ipi*",
        .mrnames = "*xlnx.zynqmp_ipi*",
        .file = "hw/intc/xln-zynqmp-pip.c",
        .socket = false,
    }, {
        .arch = "aarch64",
        .name = "xlnx-zynqmp-rtc",
        .args = "-machine xlnx-zcu102",
        .objects = "*xlnx-zynmp.rtc*",
        .mrnames = "*xlnx-zynmp.rtc*",
        .file = "hw/rtc/xlnx-zynqmp-rtc.c",
        .socket = false,
    }, {
        .arch = "aarch64",
        .name = "xlnx-zdma",
        .args = "-machine xlnx-zcu102",
        .objects = "*xlnx.zdma*",
        .mrnames = "*xlnx.zdma*",
        .file = "hw/dma/xlnx-zdma.c",
        .socket = false,
    }, {
        .arch = "aarch64",
        .name = "xlnx-csu-dma",
        .args = "-machine xlnx-zcu102",
        .objects = "*xlnx.csu_dma*",
        .mrnames = "*xlnx.csu_dma*",
        .file = "hw/dma/xlnx_csu_dma.c",
        .socket = false,
    },
    /* sbsa-ref */ {
        .arch = "aarch64",
        .name = "arm-gicv3",
        .args = "-machine sbsa-ref",
        .objects = "*gicv3_dist*,*gicv3_redist_region*",
        .mrnames = "*gicv3_dist*,*gicv3_redist_region*",
        .file = "hw/intc/arm_gicv3.c hw/intc/arm_gicv3_common.c",
        .socket = false,
    }, /* pl011/pl031/e1000e/vga see above */ {
        .arch = "aarch64",
        .name = "wdt-sbsa",
        .args = "-machine sbsa-ref",
        .objects = "*sbsa_gwdt.refresh*,*sbsa_gwdt.control*",
        .mrnames = "*sbsa_gwdt.refresh*,*sbsa_gwdt.control*",
        .file = "hw/watchdog/sbsa_gwdt.c",
        .socket = false,
    },
    /* virt, pl011/pl031/pl061 see above */ {
        .arch = "aarch64",
        .name = "platform-bus",
        .args = "-machine virt",
        .objects = "*platform bus*",
        .mrnames = "*platform bus*",
        .file = "hw/core/platform-bus.c",
        .socket = false,
    }
};

#endif /* QEMU_VIDEZZO_H */
