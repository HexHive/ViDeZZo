#!/bin/bash

pushd qemu
mkdir out-cov
pushd out-cov
CLANG_COV_DUMP=1 \
CC=clang CXX=clang++ ../configure \
    --enable-videzzo --enable-fuzzing --enable-debug \
    --disable-werror --disable-sanitizers --enable-spice \
    --extra-cflags="-DCLANG_COV_DUMP -DVIDEZZO_LESS_CRASHES -fprofile-instr-generate -fcoverage-mapping" \
    --target-list="i386-softmmu x86_64-softmmu arm-softmmu aarch64-softmmu"
ninja qemu-videzzo-i386 qemu-videzzo-x86_64 qemu-videzzo-arm qemu-videzzo-aarch64
popd
popd
