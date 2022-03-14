#!/bin/bash

pushd qemu
mkdir build-cov-6
pushd build-cov-6
CLANG_COV_DUMP=1 \
CC=clang CXX=clang++ ../configure \
    --enable-videzzo --enable-fuzzing --enable-debug \
    --disable-werror --disable-sanitizers \
    --extra-cflags="-DCLANG_COV_DUMP -DVIDEZZO_LESS_CRASHES -fprofile-instr-generate -fcoverage-mapping" \
    --target-list="i386-softmmu arm-softmmu"
ninja qemu-fuzz-i386 qemu-system-i386 qemu-fuzz-arm qemu-system-arm
popd
popd
