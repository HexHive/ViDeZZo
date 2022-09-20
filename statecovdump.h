/*
 Copyright (c) 2022 Qiang Liu <cyruscyliu@gmail.com>

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#ifndef STATE_COV_DUMP_H
#define STATE_COV_DUMP_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#define StateMachineSize (1 << 8) // 256
#define NodeSize (1 << 6) // 64
#define EdgeSize ((1 << 6) * ((1 << 6) - 1)) // 64 * 63

// A state machine.
typedef struct StateMachine {
    size_t LastNode;
    uint8_t NodeMap[NodeSize];
    uint8_t EdgeMap[EdgeSize];
} StateMachine;

// A state table containing StateMachineSize state machines.
static StateMachine Table[StateMachineSize];
static StateMachine TableAccumulated[StateMachineSize];

// Clear state machines.
void ResetTable() {
    memset(Table, 0, sizeof(Table));
    for (size_t i = 0; i < StateMachineSize; i++) {
        Table[i].LastNode = NodeSize;
    }
}

// Clear accumulated state machines.
void ResetTableAccumulated() {
    memset(TableAccumulated, 0, sizeof(TableAccumulated));
    for (size_t i = 0; i < StateMachineSize; i++) {
        TableAccumulated[i].LastNode = NodeSize;
    }
}

static inline bool GetNodeValue(uint8_t StateMachineId, size_t Node) {
    return Table[StateMachineId].NodeMap[Node];
}

static inline bool GetAccumulatedNodeValue(uint8_t StateMachineId, size_t Node) {
    return TableAccumulated[StateMachineId].NodeMap[Node];
}

static inline bool GetEdgeValue(uint8_t StateMachineId, size_t Edge) {
    return Table[StateMachineId].EdgeMap[Edge];
}

static inline bool GetAccumulatedEdgeValue(uint8_t StateMachineId, size_t Edge) {
    return TableAccumulated[StateMachineId].EdgeMap[Edge];
}

// Return true if the byte is not saturated.
static inline bool UpdateNode(uint8_t StateMachineId, size_t Node) {
    assert(Node < NodeSize);
    // Update NodeMapAccumulated in any case
    if (TableAccumulated[StateMachineId].NodeMap[Node] < 0xFF) {
        TableAccumulated[StateMachineId].NodeMap[Node]++;
    }
    // Update NodeMap
    if (Table[StateMachineId].NodeMap[Node] < 0xFF) {
        Table[StateMachineId].NodeMap[Node]++;
        return true;
    }
    return false;
}

// Return true if the byte is not saturated.
static inline bool UpdateEdge(uint8_t StateMachineId, size_t Node) {
    assert(Node < NodeSize);
    size_t Edge;
    // Update EdgeMap
    // -------------> Node
    // |
    // v LastNode
    // Pos = LastNode * kNodeSize + Node
    if (Table[StateMachineId].LastNode == NodeSize) {
        Table[StateMachineId].LastNode = Node;
    } else {
        Edge = Table[StateMachineId].LastNode * NodeSize + Node;
        // Update EdgeMapAccumulated in any case
        if (TableAccumulated[StateMachineId].EdgeMap[Edge] < 0xFF)  {
            TableAccumulated[StateMachineId].EdgeMap[Edge]++;
        }
        if (Table[StateMachineId].EdgeMap[Edge] < 0xFF)  {
            Table[StateMachineId].EdgeMap[Edge]++;
            Table[StateMachineId].LastNode = Node;
            return true;
        }
    }
    return false;
}

// Return true if the byte is not saturated.
bool UpdateState(uint8_t StateMachineId, size_t Node) {
    bool NodeRet, EdgeRet;
    NodeRet = UpdateNode(StateMachineId, Node);
    EdgeRet = UpdateEdge(StateMachineId, Node);
    return NodeRet && EdgeRet;
}

void PrintAccumulatedStatefulCoverage(bool PrintAllCounters) {
    // Because most state machines are empty,
    // we won't print all of them to be anonying.
    size_t i, j;
    for (i = 0; i < StateMachineSize; i++) {
        // Check here.
        uint32_t acc = 0;
        for (j = 0; j < NodeSize; j++)
            acc += GetAccumulatedNodeValue(i, j);
        if (acc == 0)
            continue;
        // Print then.
        fprintf(stderr, "==StateMachine %d==\n", i);
        fprintf(stderr, "====Node====\n");
        uint8_t v;
        for (j = 0; j < NodeSize; j++) {
            v = GetAccumulatedNodeValue(i, j);
            if (PrintAllCounters)
                v ? fprintf(stderr, "%02x", v) : fprintf(stderr, "--");
            else
                v ? fprintf(stderr, "x"): fprintf(stderr, "-");
        }
        fprintf(stderr, "\n");
        // Go on edges.
        fprintf(stderr, "====Edge====\n");
        for (j = 0; j < EdgeSize; j++) {
            if (j != 0 && j % NodeSize == 0)
                fprintf(stderr, "\n");
            v = GetAccumulatedEdgeValue(i ,j);
            if (PrintAllCounters)
                v ? fprintf(stderr, "%02x", v) : fprintf(stderr, "--");
            else
                v ? fprintf(stderr, "x"): fprintf(stderr, "-");
        }
        fprintf(stderr, "\n");
    }
}

int DumpStateToFile(const char *pathname) {
    uint8_t *Data = (uint8_t *)TableAccumulated;
    size_t Size = sizeof(TableAccumulated);

    FILE *f = fopen(pathname, "wb");
    if (f == NULL) {
        printf("[-] %s failed to open. Exit.\n", pathname);
        exit(1);
    }
    size_t ret = fwrite(Data, 1, Size, f);

    fclose(f);
    return ret;
}

#endif /* STATE_COV_DUMP_H */
