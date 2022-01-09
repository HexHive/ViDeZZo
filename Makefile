#
# Type-Aware Virtual-Device Fuzzing
#
# Copyright Qiang Liu <cyruscyliu@gmail.com>
#
# This work is licensed under the terms of the GNU GPL, version 2 or later.
#

CFLAGS ?= -g -fsanitize=address,undefined -fPIE -fno-omit-frame-pointer -fno-optimize-sibling-calls

videzzo-core:
	python3 videzzo_types_gen.py ${HYPERVISOR}
	clang ${CFLAGS} -o videzzo.o -c videzzo.c
	clang ${CFLAGS} -o videzzo_types.i -E videzzo_types.c
	clang ${CFLAGS} -o videzzo_types.o -c videzzo_types.c
	ar rcs libvidezzo.a videzzo.o videzzo_types.o

videzzo-vmm:
	HYPERVISOR=vmm make videzzo-core
	clang -fsanitize=fuzzer ${CFLAGS} -o vmm       videzzo_vmm.c libvidezzo.a

videzzo-vmm-debug:
	CFLAGS="${CFLAGS} -DVIDEZZO_DEBUG" HYPERVISOR=vmm make videzzo-core
	clang -fsanitize=fuzzer ${CFLAGS} -o vmm-debug videzzo_vmm.c libvidezzo.a

vmm: videzzo-vmm videzzo-vmm-debug

.PHONY: videzzo-qemu videzzo-virtualbox videzzo-bhyve

videzzo-qemu:
	HYPERVISOR=qemu make videzzo-core
	make -C videzzo_qemu

videzzo-qemu-debug:
	HYPERVISOR=qemu make videzzo-core
	CFLAGS="-DVIDEZZO_DEBUG" make -C videzzo_qemu

qemu: videzzo-qemu

videzzo-virtualbox:
	HYPERVISOR=virtualbox make videzzo-core
	make -C videzzo_virtualbox

videzzo-virtualbox-debug:
	HYPERVISOR=virtualbox make videzzo-core
	CFLAGS="-DVIDEZZO_DEBUG" make -C videzzo_virtualbox

virtualbox: videzzo-virtualbox

videzzo-bhyve:
	HYPERVISOR=bhyve make videzzo-core
	make -C videzzo_bhyve

videzzo-bhyve-debug:
	HYPERVISOR=bhyve make videzzo-core
	CFLAGS="-DVIDEZZO_DEBUG" make -C videzzo_bhyve

bhyve: videzzo-bhyve

clean:
	rm -rf *.o *.a *.i

distclean: clean
	make -C videzzo_qemu clean
	make -C videzzo_virtualbox clean
	make -C videzzo_bhyve clean
