/*
 * Type-Aware Virtual-Device Fuzzing
 *
 * Copyright Qiang Liu <cyruscyliu@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 */

#include "videzzo.h"
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>

//
// GroupMutator Feedback
//
bool DisableGroupMutator = 0;

void GroupMutatorMiss(uint8_t id, uint64_t physaddr) {
    static int visited = 0;
    if (visited) {
        visited = 0;
        return;
    }

    if (DisableGroupMutator)
        return;

    // In this handler, the current input will be changed
    // Don't delete any events from the current event to the end
    // All changes will be reissued when this function returns
    group_mutator_handlers[id](gfctx_get_current_input(), gfctx_get_current_event());
    visited = 1;
}

//
// used in vm|fuzzer-specific mutator callback
//
size_t ViDeZZoCustomMutator(uint8_t *Data, size_t Size,
        size_t MaxSize, unsigned int Seed) {
#ifdef VIDEZZO_DEBUG
    fprintf(stderr, "- ViDeZZoCustomMutator, %zu\n", Size);
#endif
    // Copy data to our input manager
    Input *input = init_input(Data, Size);
    if (!input) {
        return reset_data(Data, MaxSize);
    }
    // Deserialize Data to Events
    // If the input is too short to contain longer event, stop early.
    // Note that we don't discard any intact event.
    Size = deserialize(input);
    if (Size == 0) {
        free_input(input);
        return reset_data(Data, MaxSize);
    }
    // set up the RNG
    srand(Seed);
    // Mutate all events
    // TODO: maybe 100 is tunable
    for (int i = 0; i < 100; i++) {
        // weighted: select_weighted_mutators
        size_t aaaaaaa = select_mutators(rand());
#ifdef VIDEZZO_DEBUG
        fprintf(stderr, "- %s\n", CustomMutatorNames[aaaaaaa]);
#endif
        size_t NewSize = CustomMutators[aaaaaaa](input);
        if (NewSize) {
            size_t SerializationSize = serialize(input, Data, MaxSize);
            free_input(input);
#ifdef VIDEZZO_DEBUG
            if (NewSize > MaxSize)
                fprintf(stderr, "- NewSize (overflow), %zu\n", NewSize);
            else
                fprintf(stderr, "- NewSize, %zu\n", NewSize);
#endif
            return SerializationSize;
        }
    }
    free_input(input);
    return reset_data(Data, MaxSize); // Fallback, should not happen frequently.
}

void __videzzo_execute_one_input(Input *input, void *object) {
    Event *event = input->events;
#ifdef VIDEZZO_DEBUG
    fprintf(stderr, "- dispatching events\n");
#endif
    for (int i = 0; event != NULL; i++) {
#ifdef VIDEZZO_DEBUG
        event_ops[event->type].print_event(event);
#endif
        // set up feedback context
        gfctx_set_current_event(i);
        videzzo_dispatch_event(event, object);
        event = get_next_event(event);
    }
    gfctx_set_current_event(0);
}

size_t videzzo_execute_one_input(uint8_t *Data, size_t Size, void *object) {
    // read Data to Input
    Input *input = init_input(Data, Size);
    if (!input)
        return 0;
    // deserialize Data to Events
    input->size = deserialize(input);
    // set up feedback context
    gfctx_set_current_input(input);
    gfctx_set_object(object);
    // if (fork() == 0) {
        __videzzo_execute_one_input(input, object);
    //    _Exit(0);
    // } else {
    //     wait(0);
    // }
    size_t SerializationSize = serialize(input, Data, DEFAULT_INPUT_MAXSIZE);
    gfctx_set_current_input(NULL);
    gfctx_set_object(NULL);
    free_input(input);
    return SerializationSize;
}
