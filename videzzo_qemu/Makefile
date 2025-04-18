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
	cp 0001-fix-assertion-in-hw-usb-core.c.patch qemu/
	cp 0001-Revert-util-cutils-Remove-unused-qemu_get_exec_dir.patch qemu/
	cd qemu && patch -p 1 < 0001-Update-QEMU-to-support-ViDeZZo-as-a-library.patch && \
		patch -p 1 < 0001-fix-assertion-in-hw-usb-core.c.patch && \
		patch -p 1 < 0001-Revert-util-cutils-Remove-unused-qemu_get_exec_dir.patch && \
		./configure && make update-buildoptions && \
		cd $(OLDPWD)

compile:
	bash -x 0002-copy-to-qemu.sh
	bash -x 0003-compile-qemu-san.sh

compile-coverage:
	bash -x 0002-copy-to-qemu.sh
	bash -x 0005-compile-qemu-cov.sh

compile-debug:
	bash -x 0002-copy-to-qemu.sh
	bash -x 0006-compile-qemu-deb.sh

.PHONY: qemu

qemu-dep:
	if [ ! -d "qemu" ]; then \
		sudo apt-get install -y make autoconf automake libtool ninja-build libglib2.0-dev \
			libfdt-dev libpixman-1-dev zlib1g-dev patchelf wget libattr1 libattr1-dev \
			libcap-ng-dev pkg-config libvncserver-dev && \
		git clone https://github.com/qemu/qemu.git --depth 1; make patch; fi

qemu: qemu-dep
	make compile

qemu-coverage: qemu-dep
	make compile-coverage

qemu-debug: qemu-dep
	make compile-debug

update:
	cd qemu && git pull && cd $(OLDPWD)
	make compile

clusterfuzz:
	bash -x 0004-zip-qemu-targets.sh san

clusterfuzz-coverage:
	bash -x 0004-zip-qemu-targets.sh cov

clusterfuzz-debug:
	bash -x 0004-zip-qemu-targets.sh deb

distclean:
	rm -f *_*.h *.yaml
	rm -rf out-*
	rm -rf qemu
