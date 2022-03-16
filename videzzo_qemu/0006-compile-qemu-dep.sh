#!/bin/bash

pushd qemu
mkdir build-dep-6
pushd build-dep-6
CC=clang CXX=clang++ ../configure \
    --enable-videzzo --enable-fuzzing \
    --disable-werror --enable-sanitizers \
    --target-list="i386-softmmu arm-softmmu"
ninja qemu-fuzz-i386 qemu-fuzz-arm
popd
popd
