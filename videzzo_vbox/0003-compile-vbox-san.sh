#!/bin/bash

pushd vbox
mkdir -p out-san
./configure --disable-hardening --disable-docs \
    --disable-java --disable-qt -d --out-base-dir=out-san
pushd out-san && source ./env.sh && popd
ANNOTATION="-videzzo-instrumentation=$PWD/videzzo_vbox_types.yaml -flegacy-pass-manager"
EXPORT_SYMBOL_LIST="$PWD/export_symbol_list.txt"
EXPORT_SYMBOL="-Wl,--export-dynamic -Wl,--export-dynamic-symbol-list=$EXPORT_SYMBOL_LIST"
kmk VBOX_FUZZ=1 KBUILD_TYPE=debug VBOX_GCC_TOOL=CLANG \
    VBOX_WITH_GCC_SANITIZER=1 \
    IPRT_WITH_GCC_SANITIZER=1 \
    PATH_OUT_BASE=$PWD/out-san \
    TOOL_CLANG_CFLAGS="-fsanitize=fuzzer-no-link -fPIE ${ANNOTATION}" \
    TOOL_CLANG_CXXFLAGS="-fsanitize=fuzzer-no-link -fPIE ${ANNOTATION}" \
    TOOL_CLANG_LDFLAGS="-fsanitize=fuzzer-no-link ${EXPORT_SYMBOL}" \
    VBOX_FUZZ_LDFLAGS="-fsanitize=fuzzer"

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
