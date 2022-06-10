#!/bin/bash

# This script is derived from QEMU/scripts/oss-fuzz/build.sh

# let's assume we've compiled VirtualBox
# so we have qemu/build-[san|cov]-6/qemu-videzzo-[i386|arm]
CONTROL=$1 # san or cov
DEST_DIR=$PWD/out-$1
mkdir -p $DEST_DIR

pushd vbox/out-san/linux.amd64/debug/bin/
targets=$(./VBoxViDeZZo | awk '$1 ~ /\*/  {print $2}')
for target in $(echo "$targets" | head -n -1); do
    if [ "$target" != "videzzo-fuzz" ]; then
        echo Generate "$DEST_DIR/vbox-videzzo-i386-target-$target"
        ln -f ./VBoxViDeZZo "$DEST_DIR/vbox-videzzo-i386-target-$target"
    fi
done
popd
pushd $DEST_DIR
# zip -r ../vbox-address-$(date '+%Y%m%d%H%M%S').zip *
popd