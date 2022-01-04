/*
 * Type-Aware Virtual-Device Fuzzing
 *
 * Copyright Qiang Liu <cyruscyliu@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 */

#include "videzzo.h"

void test_input(uint8_t *Data, size_t Size) {
    Input *input = init_input(Data, Size);
    fprintf(stderr, "- deserialize\n");
    input->size = deserialize(input);
    Event *event = input->events;
    for (int i = 0; event != NULL; i++) {
        event_ops[event->type].print_event(event);
        event = event->next;
    }
    free_input(input);
}

void test_reset_data() {
    // let us test reset_data
    fprintf(stderr, "[+] test reset_data ...\n");
    uint8_t *Data = (uint8_t *)calloc(4096, 1);
    size_t Size = reset_data(Data, 4096);
    test_input(Data, Size);
    free(Data);
}

void test_mutators() {
    // let's test mutators!
    fprintf(stderr, "[+] test mutators ...\n");
    uint8_t *Data = (uint8_t *)calloc(4096, 1);
    size_t Size = reset_data(Data, 4096);
    fprintf(stderr, "- ViDeZZoCustomMutator ...\n");
    size_t NewSize;
    NewSize = ViDeZZoCustomMutator(Data, Size, 4096, 0);
    test_input(Data, NewSize);
    free(Data);
}

int main(int argc, char *argv[]) {
    // only some basic testings
    LLVMFuzzerInitialize(&argc, &argv);
    // let print all interfaces 
    fprintf(stderr, "[+] all interfaces ...\n");
    print_interfaces();

    srand(0);
    test_reset_data();
    test_mutators();
}
