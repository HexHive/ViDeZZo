/*
 * Type-Aware Virtual Device Fuzzing
 *
 * Copyright Red Hat Inc., 2021
 *
 * Authors: Qiang Liu <cyruscyliu@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 */
#include "videzzo_bhyve.h"
#include "videzzo.h"
#ifdef CLANG_COV_DUMP
#include "clangcovdump.h"
#endif

//
// bhyve Dispatcher
//
uint64_t dispatch_mmio_read(Event *event) {
    return 0;
}

uint64_t dispatch_pio_read(Event *event) {
    return 0;
}

uint64_t dispatch_mem_read(Event *event) {
    return 0;
}

uint64_t dispatch_mmio_write(Event *event) {
    return 0;
}

uint64_t dispatch_pio_write(Event *event) {
    return 0;
}

uint64_t dispatch_mem_write(Event *event) {
    return 0;
}

uint64_t dispatch_clock_step(Event *event) {
    return 0;
}

uint64_t dispatch_socket_write(Event *event) {
    return 0;
}

uint64_t dispatch_mem_alloc(Event *event) {
    return videzzo_malloc(event->valu);
}

uint64_t dispatch_mem_free(Event *event) {
    return videzzo_free(event->valu);
}


//
// bhyve specific initialization - Set up interfaces
//
static void videzzo_bhyve_pre(QTestState *s) {
#ifdef CLANG_COV_DUMP
    llvm_profile_initialize_file(true);
#endif
}

//
// bhyve specific initialization - Show usage
//
// TODO: we should thank add Alex to be one of the authors or whatever titles
static void usage(void) {
    exit(0);
}

//
// call into videzzo from bhyve
//
static void videzzo_bhyve(QTestState *s, uint8_t *Data, size_t Size) {
    if (vnc_client_needed && !vnc_client_initialized) {
        init_vnc_client(s);
    }
    videzzo_execute_one_input(Data, Size, s, &flush_events);
}

//
// call into videzzo from bhyve
//
size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
        size_t MaxSize, unsigned int Seed) {
    return ViDeZZoCustomMutator(Data, Size, MaxSize, Seed);
}

//
// bhyve specific initialization - Register all targets
//
// TODO: move duplicated code to videzzo-core in the future
static void register_videzzo_bhyve_targets(void) {
    GString *name;
    const videzzo_bhyve_config *config;

    for (int i = 0;
         i < sizeof(predefined_configs) / sizeof(videzzo_bhyve_config);
         i++) {
        config = predefined_configs + i;
        if (strcmp(TARGET_NAME, config->arch) != 0)
            continue;
        name = g_string_new("videzzo-fuzz");
        g_string_append_printf(name, "-%s", config->name);
        fuzz_add_target(&(FuzzTarget){
                .name = name->str,
                .description = "Predefined videzzo-fuzz config.",
                .get_init_cmdline = videzzo_bhyve_predefined_config_cmdline,
                .pre_fuzz = videzzo_bhyve_pre,
                .fuzz = videzzo_bhyve,
                .opaque = (void *)config
        });
    }
}

fuzz_target_init(register_videzzo_bhyve_targets);
