#!/bin/bash

# usage: bash -x 01-quick-san.sh qemu|vbox i386|x86_64|arm|aarch64 ac97 60
vmm=$1
arch=$2
target=$3
timeout=$4

# stage 1
pushd videzzo_${vmm}/out-san
if [ "$vmm" = "vbox" ]; then
    export VBOX_LOG_DEST="nofile stdout"
    export VBOX_LOG="+gui.e.l.f"
fi

# stage 2
export ASAN_OPTIONS=detect_leaks=0:halt_on_error=0
bin=./${vmm}-videzzo-${arch}-target-videzzo-fuzz-${target}
$bin -max_total_time=${timeout} -timeout=60

popd
