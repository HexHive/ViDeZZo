#!/bin/bash

usage="04-quick-cov.sh qemu|vbox i386|x86_64|arm|aarch64 target timeout_in_second [fork]"
vmm=$1
arch=$2
target=$3
timeout=$4
fork=$5

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

if [ -z $fork ]; then
    echo 'VIDEZZO_FORK is unset'
else
    echo 'VIDEZZO_FORK is set'
    export VIDEZZO_FORK=1
fi

# stage 1
pushd videzzo_${vmm}/out-cov
if [ "$vmm" = "vbox" ]; then
    export VBOX_LOG_DEST="nofile stdout"
    export VBOX_LOG="+gui.e.l.f"
fi

# stage 2
rm -rf clangcovdump.profraw*
bin=./${vmm}-videzzo-${arch}-target-videzzo-fuzz-${target}
$bin -max_total_time=${timeout} -timeout=60

# stage 3
llvm-profdata merge -output=clangcovdump.profraw $(ls clangcovdump.profraw-* | tail -n 1)
if [ "$vmm" = "vbox" ]; then
    llvm-cov show -format=html -output-dir=./coverage-reports/${target} -instr-profile clangcovdump.profraw \
        ./VBoxDD.so
else
    llvm-cov show -format=html -output-dir=./coverage-reports/${target} -instr-profile clangcovdump.profraw $bin
fi
rm default.profraw
echo "please check $PWD/coverage-reports/${target}"
popd
