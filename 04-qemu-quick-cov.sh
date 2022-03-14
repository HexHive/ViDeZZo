#!/bin/bash

# usage: bash -x 04-qemu-quick-cov.sh i386 ac97
arch=$1
target=$2

# stage 1
pushd videzzo_qemu/out-cov

# stage 2
rm -rf clangcovdump.profraw*
bin=./qemu-fuzz-${arch}-target-videzzo-fuzz-${target}
$bin -max_total_time=300

# stage 3
llvm-profdata merge -output=clangcovdump.profraw $(ls clangcovdump.profraw-* | tail -n 1)
llvm-cov show -format=html -output-dir=./coverage-reports/${target} -instr-profile clangcovdump.profraw $bin
echo "please check $PWD/coverage-reports/${target}"
popd
