#
# Type-Aware Virtual-Device Fuzzing
#
# Copyright Qiang Liu <cyruscyliu@gmail.com>
#
# This work is licensed under the terms of the GNU GPL, version 2 or later.
#
#
CFLAGS ?=

patch:
	cp 0001-Update-QEMU-to-support-ViDeZZo-as-a-library.patch qemu/
	cd qemu && git am < 0001-Update-QEMU-to-support-ViDeZZo-as-a-library.patch && cd $(OLDPWD)

compile:
	bash -x 0002-copy-to-qemu.sh
	bash -x 0003-compile-qemu.sh

.PHONY: qemu

qemu:
	sudo apt-get install -y make autoconf automake libtool ninja-build libglib2.0-dev \
		libfdt-dev libpixman-1-dev zlib1g-dev patchelf wget libattr1 libattr1-dev \
		libcap-ng-dev pkg-config libvncserver-dev
	if [ ! -d "qemu" ]; then git clone https://github.com/qemu/qemu.git --depth 1; make patch; fi
	make compile

update:
	cd qemu && git pull && cd $(OLDPWD)
	make compile

clean:
	# do nothing
