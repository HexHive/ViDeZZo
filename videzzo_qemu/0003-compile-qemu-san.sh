#!/bin/bash

pushd qemu
mkdir out-san
pushd out-san
CC=clang CXX=clang++ ../configure \
    --enable-videzzo --enable-fuzzing --enable-debug \
    --disable-werror --enable-sanitizers --enable-spice \
    --enable-slirp \
    --target-list="i386-softmmu x86_64-softmmu arm-softmmu aarch64-softmmu"
ninja qemu-videzzo-i386 qemu-videzzo-x86_64 qemu-videzzo-arm qemu-videzzo-aarch64
popd
popd
