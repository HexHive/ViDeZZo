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
	echo "nothing to patch"
	cp 0001-Update-VBOX-to-support-ViDeZZo-as-a-library.patch vbox
	cd vbox && patch -p 1 < 0001-Update-VBOX-to-support-ViDeZZo-as-a-library.patch && \
		cd $(OLDPWD)

compile:
	bash -x 0002-copy-to-vbox.sh
	bash -x 0003-compile-vbox-san.sh

compile-coverage:
	bash -x 0002-copy-to-vbox.sh
	bash -x 0005-compile-vbox-cov.sh

compile-debug:
	bash -x 0002-copy-to-vbox.sh
	bash -x 0006-compile-vbox-deb.sh

.PHONY: vbox

vbox-dep:
	bash -x 0007-update-gcc-for-kernel-modules.sh
	# this will pull vbox and kbuild
	# svn might fail due to network issues
	# please run `svn cleanup && svn update` to finish
	if [ ! -d "vbox" ]; then \
		wget https://download.virtualbox.org/virtualbox/7.0.20/VirtualBox-7.0.20.tar.bz2 -O vbox.tar.bz2; \
		mkdir vbox && tar -xf vbox.tar.bz2 -C vbox --strip-components=1; make patch; fi
vbox: vbox-dep
	make compile

vbox-coverage: vbox-dep
	make compile-coverage

vbox-debug: vbox-dep
	make compile-debug

update:
	cd vbox && svn update && cd $(OLDPWD)
	make compile

clusterfuzz:
	bash -x 0004-zip-vbox-targets.sh san

clusterfuzz-coverage:
	bash -x 0004-zip-vbox-targets.sh cov

clusterfuzz-debug:
	bash -x 0004-zip-vbox-targets.sh deb

distclean:
	rm -f *_*.h *.yaml
	rm -rf out-*
	rm -rf vbox
