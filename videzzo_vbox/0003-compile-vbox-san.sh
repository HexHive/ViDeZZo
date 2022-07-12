#!/bin/bash

pushd vbox
mkdir -p out-san
./configure --disable-hardening --disable-docs \
    --disable-java --disable-qt -d --out-base-dir=out-san
pushd out-san && source ./env.sh && popd
kmk VBOX_FUZZ=1 KBUILD_TYPE=debug VBOX_GCC_TOOL=CLANG \
    PATH_OUT_BASE=$PWD/out-san \
    TOOL_CLANG_CFLAGS="-fsanitize=fuzzer-no-link -fPIE" \
    TOOL_CLANG_CXXFLAGS="-fsanitize=fuzzer-no-link -fPIE" \
    TOOL_CLANG_LDFLAGS="-fsanitize=fuzzer-no-link,address,undefined" \
    VBOX_FUZZ_LDFLAGS="-fsanitize=fuzzer,address,undefined"

# 1. compile kernel drivers
pushd out-san/linux.amd64/debug/bin/
pushd src
sudo make && sudo make install
# 2. install kernel drivers
sudo rmmod vboxnetadp vboxnetflt vboxdrv
sudo insmod vboxdrv.ko
sudo insmod vboxnetflt.ko
sudo insmod vboxnetadp.ko
popd
popd
popd
