#!/bin/bash

usage="01-quick-san.sh qemu|vbox i386|x86_64|arm|aarch64 target timeout_in_second"
vmm=$1
arch=$2
target=$3
timeout=$4

if [ -z $vmm ]; then
    echo "VMM is migging"
    echo $usage
    exit 1
fi

if [ -z $arch ]; then
    echo "architecture is migging"
    echo $usage
    exit 1
fi

if [ -z $target ]; then
    echo "target is missing"
    echo $usage
    exit 1
fi

if [ -z $timeout ]; then
    echo "timeout in second is missing"
    echo $usage
    exit 1
fi

# stage 1
pushd videzzo_${vmm}/out-san
if [ "$vmm" = "vbox" ]; then
    export VBOX_LOG_DEST="nofile stdout"
    export VBOX_LOG="+gui.e.l.f"
fi

# stage 2
export ASAN_OPTIONS=detect_leaks=0
bin=./${vmm}-videzzo-${arch}-target-videzzo-fuzz-${target}
$bin -max_total_time=${timeout} -timeout=60

popd
