#!/bin/bash

# usage: bash -x 04-quick-cov.sh qemu|vbox i386|x86_64|arm|aarch64 ac97 60
vmm=$1
arch=$2
target=$3
timeout=$4

# stage 1
pushd videzzo_${vmm}/out-cov
if [ "$vmm" = "vbox" ]; then
    export VBOX_LOG_DEST="nofile stdout"
    export VBOX_LOG="+gui.e.l.f"
fi

# stage 2
rm -rf clangcovdump.profraw*
bin=./${vmm}-videzzo-${arch}-target-videzzo-fuzz-${target}
$bin -max_total_time=${timeout}

# stage 3
llvm-profdata merge -output=clangcovdump.profraw $(ls clangcovdump.profraw-* | tail -n 1)
llvm-cov show -format=html -output-dir=./coverage-reports/${target} -instr-profile clangcovdump.profraw $bin
rm -f default.profraw
echo "please check $PWD/coverage-reports/${target}"
popd
