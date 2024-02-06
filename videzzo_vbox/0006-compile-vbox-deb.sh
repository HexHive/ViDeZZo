#!/bin/bash

pushd vbox
mkdir -p out-deb
./configure --disable-hardening --disable-docs \
    --disable-java --disable-qt -d --out-base-dir=out-deb
pushd out-deb && source ./env.sh && popd
ANNOTATION="-videzzo-instrumentation=$PWD/videzzo_vbox_types.yaml -flegacy-pass-manager"
EXPORT_SYMBOL_LIST="$PWD/export_symbol_list.txt"
EXPORT_SYMBOL="-Wl,--export-dynamic -Wl,--export-dynamic-symbol-list=$EXPORT_SYMBOL_LIST"
LINKER_SCRIPT="-Wl,-T,$PWD/src/VBox/Frontends/VBoxManage/videzzo_fork.ld"
kmk VBOX_FUZZ=1 KBUILD_TYPE=debug VBOX_GCC_TOOL=CLANG \
    PATH_OUT_BASE=$PWD/out-deb \
    TOOL_CLANG_CFLAGS="-fsanitize=fuzzer-no-link -fPIE -DRT_NO_STRICT ${ANNOTATION}" \
    TOOL_CLANG_CXXFLAGS="-fsanitize=fuzzer-no-link -fPIE -DRT_NO_STRICT ${ANNOTATION}" \
    TOOL_CLANG_LDFLAGS="-fsanitize=fuzzer-no-link ${EXPORT_SYMBOL} ${LINKER_SCRIPT}" \
    VBOXDD_SANITIZER=1 \
    VBOX_FUZZ_LDFLAGS="-fsanitize=fuzzer,address,undefined"

# 1. compile kernel drivers
pushd out-deb/linux.amd64/debug/bin/
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
