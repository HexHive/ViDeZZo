#!/bin/bash

pushd vbox
mkdir -p out-cov
./configure --disable-hardening --disable-docs \
    --disable-java --disable-qt -d --out-base-dir=out-cov
source ./env.sh
kmk VBOX_FUZZ=1 KBUILD_TYPE=debug VBOX_GCC_TOOL=CLANG \
    PATH_OUT_BASE=$PWD/out-cov \
    TOOL_CLANG_CFLAGS="-DCLANG_COV_DUMP -DVIDEZZO_LESS_CRASHES -fprofile-instr-generate -fcoverage-mapping -fPIE" \
    TOOL_CLANG_CXXFLAGS="-DCLANG_COV_DUMP -DVIDEZZO_LESS_CRASHES -fprofile-instr-generate -fcoverage-mapping -fPIE"
popd
