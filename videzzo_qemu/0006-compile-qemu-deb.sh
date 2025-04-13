#!/bin/bash

pushd qemu
mkdir out-deb
pushd out-deb
CC=clang CXX=clang++ ../configure \
    --enable-videzzo --enable-fuzzing --enable-debug \
    --disable-werror --enable-asan --enable-ubsan --enable-spice \
    --enable-slirp --disable-gtk --disable-sdl \
    --target-list="i386-softmmu x86_64-softmmu arm-softmmu aarch64-softmmu"
ninja qemu-videzzo-i386 qemu-videzzo-x86_64 qemu-videzzo-arm qemu-videzzo-aarch64
popd
popd
