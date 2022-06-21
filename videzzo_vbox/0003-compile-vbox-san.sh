#!/bin/bash

pushd vbox
mkdir -p out-san
./configure --disable-hardening --disable-docs \
    --disable-java --disable-qt -d --out-base-dir=out-san
source ./env.sh
kmk VBOX_FUZZ=1 KBUILD_TYPE=debug VBOX_GCC_TOOL=CLANG \
    PATH_OUT_BASE=$PWD/out-san \
    TOOL_CLANG_CFLAGS="-fsanitize=fuzzer-no-link -fPIE" \
    TOOL_CLANG_CXXFLAGS="-fsanitize=fuzzer-no-link -fPIE" \
    TOOL_CLANG_LDFLAGS="-fsanitize=fuzzer-no-link,address,undefined" \
    VBOX_FUZZ_LDFLAGS="-fsanitize=fuzzer,address,undefined"
popd
