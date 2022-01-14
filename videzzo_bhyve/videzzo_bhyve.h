/*
 * Type-Aware Virtual-Device Fuzzing bhyve
 *
 * Copyright Red Hat Inc., 2021
 *
 * Authors:
 *  Qiang Liu <cyruscyliu@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef BHYVE_VIDEZZO_H
#define BHYVE_VIDEZZO_H

#include <rfb/rfbclient.h>
#include <sys/socket.h>

static void usage(void);

// P.S. "videzzo" is only a mark here.
static QGuestAllocator *videzzo_alloc;

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

typedef struct videzzo_bhyve_config {
    const char *arch, *name, *args, *objects, *mrnames, *file;
    gchar* (*argfunc)(void); /* Result must be freeable by g_free() */
    bool socket; /* Need support or not */
    bool display; /* Need support or not */
    bool byte_address; /* Need support or not */
} videzzo_bhyve_config;

static inline GString *videzzo_bhyve_cmdline(FuzzTarget *t)
{
    GString *cmd_line = g_string_new(TARGET_NAME);
    if (!getenv("bhyve_FUZZ_ARGS")) {
        usage();
    }
    g_string_append_printf(cmd_line, " -display none \
                                      -machine accel=qtest, \
                                      -m 512M %s ", getenv("bhyve_FUZZ_ARGS"));
    return cmd_line;
}

static inline GString *videzzo_bhyve_predefined_config_cmdline(FuzzTarget *t)
{
    GString *args = g_string_new(NULL);
    const videzzo_bhyve_config *config;
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
    setenv("bhyve_AVOID_DOUBLE_FETCH", "1", 1);
    if (config->argfunc) {
        gchar *t = config->argfunc();
        g_string_append_printf(args, t, port);
        g_free(t);
    } else {
        g_assert_nonnull(config->args);
        g_string_append_printf(args, config->args, port);
    }
    gchar *args_str = g_string_free(args, FALSE);
    setenv("bhyve_FUZZ_ARGS", args_str, 1);
    g_free(args_str);

    setenv("bhyve_FUZZ_OBJECTS", config->objects, 1);
    setenv("bhyve_FUZZ_MRNAME", config->mrnames, 1);
    return videzzo_bhyve_cmdline(t);
}

static void *get_videzzo_alloc(void *object) {
    return NULL;
}

static const videzzo_bhyve_config predefined_configs[] = {
};

#endif /* BHYVE_VIDEZZO_H */
