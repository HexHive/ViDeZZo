#!/bin/bash

# This script is derived from QEMU/scripts/oss-fuzz/build.sh

# let's assume we've compiled QEMU
# so we have qemu/out-[san|cov]/qemu-videzzo-[i386|arm]
CONTROL=$1 # san or cov
DEST_DIR=$PWD/out-$1
mkdir $DEST_DIR

pushd qemu/out-$CONTROL
cp -r ../pc-bios $DEST_DIR/pc-bios
archs=(i386 x86_64 arm aarch64)
for arch in ${archs[@]}; do
    targets=$(./qemu-videzzo-$arch | awk '$1 ~ /\*/  {print $2}')
    for target in $(echo "$targets" | head -n -1); do
        if [ "$target" != "videzzo-fuzz" ]; then
            echo Generate "$DEST_DIR/qemu-videzzo-$arch-target-$target"
            ln -f ./qemu-videzzo-$arch "$DEST_DIR/qemu-videzzo-$arch-target-$target"
        fi
    done
done
popd

pushd $DEST_DIR
# zip -r ../qemu-address-$(date '+%Y%m%d%H%M%S').zip *
popd
