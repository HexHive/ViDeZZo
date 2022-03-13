#!/bin/bash

# This script is derived from QEMU/scripts/oss-fuzz/build.sh

# let's assume we've compiled QEMU
# so we have qemu/build-[san|cov]-6/qemu-fuzz-[i386|arm]
CONTROL=$1 # san or cov
DEST_DIR=$PWD/out-$1
rm -rf $DEST_DIR && mkdir $DEST_DIR

pushd qemu/build-$CONTROL-6
cp -r ../pc-bios $DEST_DIR/pc-bios
archs=(i386 arm)
for arch in ${archs[@]}; do
    targets=$(./qemu-fuzz-$arch | awk '$1 ~ /\*/  {print $2}')
    for target in $(echo "$targets" | head -n -1); do
        if [ "$target" != "videzzo-fuzz" ]; then
            echo Generate "$DEST_DIR/qemu-fuzz-$arch-target-$target"
            ln -f ./qemu-fuzz-$arch "$DEST_DIR/qemu-fuzz-$arch-target-$target"
        fi
    done
done
popd

pushd $DEST_DIR
rm qemu-fuzz-arm-target-videzzo-fuzz-a9-gtimer
rm qemu-fuzz-arm-target-videzzo-fuzz-a9-scu
rm qemu-fuzz-arm-target-videzzo-fuzz-allwinner-emac
rm qemu-fuzz-arm-target-videzzo-fuzz-allwinner-sdhost
rm qemu-fuzz-arm-target-videzzo-fuzz-allwinner-sun8i-emac
rm qemu-fuzz-arm-target-videzzo-fuzz-arm-gic
rm qemu-fuzz-arm-target-videzzo-fuzz-arm-mptimer
rm qemu-fuzz-arm-target-videzzo-fuzz-bcm2835-sdhost
rm qemu-fuzz-arm-target-videzzo-fuzz-chipidea
rm qemu-fuzz-arm-target-videzzo-fuzz-dwc2
rm qemu-fuzz-arm-target-videzzo-fuzz-exynos4210-fimd
rm qemu-fuzz-arm-target-videzzo-fuzz-ftgmac100
rm qemu-fuzz-arm-target-videzzo-fuzz-highbank-regs
rm qemu-fuzz-arm-target-videzzo-fuzz-imx-fec
rm qemu-fuzz-arm-target-videzzo-fuzz-imx-usb-phy
rm qemu-fuzz-arm-target-videzzo-fuzz-lan9118
rm qemu-fuzz-arm-target-videzzo-fuzz-npcm7xx-emc
rm qemu-fuzz-arm-target-videzzo-fuzz-npcm7xx-otp
rm qemu-fuzz-arm-target-videzzo-fuzz-nrf51-nvm
rm qemu-fuzz-arm-target-videzzo-fuzz-omap-dss
rm qemu-fuzz-arm-target-videzzo-fuzz-omap-lcdc
rm qemu-fuzz-arm-target-videzzo-fuzz-omap-mmc
rm qemu-fuzz-arm-target-videzzo-fuzz-onenand
rm qemu-fuzz-arm-target-videzzo-fuzz-pflash-cfi01
rm qemu-fuzz-arm-target-videzzo-fuzz-pl011
rm qemu-fuzz-arm-target-videzzo-fuzz-pl022
rm qemu-fuzz-arm-target-videzzo-fuzz-pl031
rm qemu-fuzz-arm-target-videzzo-fuzz-pl041
rm qemu-fuzz-arm-target-videzzo-fuzz-pl061
rm qemu-fuzz-arm-target-videzzo-fuzz-pl110
rm qemu-fuzz-arm-target-videzzo-fuzz-pl181
rm qemu-fuzz-arm-target-videzzo-fuzz-pxa2xx-lcd
rm qemu-fuzz-arm-target-videzzo-fuzz-pxa2xx-mmci
rm qemu-fuzz-arm-target-videzzo-fuzz-sp804
rm qemu-fuzz-arm-target-videzzo-fuzz-stellaris-enet
rm qemu-fuzz-arm-target-videzzo-fuzz-sysbus-ahci
rm qemu-fuzz-arm-target-videzzo-fuzz-tc6393xb
rm qemu-fuzz-arm-target-videzzo-fuzz-xgmac
rm qemu-fuzz-i386-target-videzzo-fuzz-am53c974
rm qemu-fuzz-i386-target-videzzo-fuzz-bochs-display
rm qemu-fuzz-i386-target-videzzo-fuzz-cs4231
rm qemu-fuzz-i386-target-videzzo-fuzz-ctu-can
rm qemu-fuzz-i386-target-videzzo-fuzz-e1000
rm qemu-fuzz-i386-target-videzzo-fuzz-ehci
rm qemu-fuzz-i386-target-videzzo-fuzz-fw-cfg
rm qemu-fuzz-i386-target-videzzo-fuzz-kvaser-can
rm qemu-fuzz-i386-target-videzzo-fuzz-lsi53c895a
rm qemu-fuzz-i386-target-videzzo-fuzz-mptsas1068
rm qemu-fuzz-i386-target-videzzo-fuzz-nvme
rm qemu-fuzz-i386-target-videzzo-fuzz-megasas
rm qemu-fuzz-i386-target-videzzo-fuzz-ohci
rm qemu-fuzz-i386-target-videzzo-fuzz-parallel
rm qemu-fuzz-i386-target-videzzo-fuzz-pcm3680-can
rm qemu-fuzz-i386-target-videzzo-fuzz-qxl
rm qemu-fuzz-i386-target-videzzo-fuzz-rocker
rm qemu-fuzz-i386-target-videzzo-fuzz-secondary-vga
rm qemu-fuzz-i386-target-videzzo-fuzz-std-vga
rm qemu-fuzz-i386-target-videzzo-fuzz-uhci
rm qemu-fuzz-i386-target-videzzo-fuzz-vmw-pvscsi
rm qemu-fuzz-i386-target-videzzo-fuzz-vmware-svga
rm qemu-fuzz-i386-target-videzzo-fuzz-vmxnet3
rm qemu-fuzz-i386-target-videzzo-fuzz-xhci
# zip -r ../qemu-address-$(date '+%Y%m%d%H%M%S').zip *
popd
