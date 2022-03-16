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
	bash -x 0003-compile-qemu-san.sh

compile-coverage:
	bash -x 0002-copy-to-qemu.sh
	bash -x 0005-compile-qemu-cov.sh

compile-deployment:
	bash -x 0002-copy-to-qemu.sh
	bash -x 0006-compile-qemu-dep.sh

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

qemu-deployment: qemu-dep
	make compile-deployment

update:
	cd qemu && git pull && cd $(OLDPWD)
	make compile

clusterfuzz:
	bash -x 0004-zip-qemu-targets.sh san

clusterfuzz-coverage:
	bash -x 0004-zip-qemu-targets.sh cov

clusterfuzz-deployment:
	bash -x 0004-zip-qemu-targets.sh dep

clean:
	# do nothing
