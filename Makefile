#
# Type-Aware Virtual-Device Fuzzing
#
# Copyright Qiang Liu <cyruscyliu@gmail.com>
#
# This work is licensed under the terms of the GNU GPL, version 2 or later.
#

CFLAGS ?= -g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-optimize-sibling-calls -fno-pie

videzzo-core:
	python3 videzzo_gen_types.py ${HYPERVISOR}
	clang ${CFLAGS} -o videzzo.o -c videzzo.c
	clang ${CFLAGS} -o videzzo_types.i -E videzzo_types.c
	clang ${CFLAGS} -o videzzo_types.o -c videzzo_types.c
	ar rcs videzzo_core.a videzzo.o videzzo_types.o

videzzo-vmm:
	HYPERVISOR=vmm make videzzo-core
	clang -fsanitize=fuzzer ${CFLAGS} -o vmm videzzo_vmm.c videzzo_core.a

videzzo-vmm-debug:
	HYPERVISOR=vmm make videzzo-core
	clang -fsanitize=fuzzer ${CFALGS} -DVIDEZZO_DEBUG -o vmm-debug videzzo_vmm.c videzzo_core.a

.PHONY: videzzo-qemu videzzo-virtualbox videzzo-bhyve

videzzo-qemu:
	HYPERVISOR=qemu make videzzo-core
	make -C videzzo_qemu

videzzo-qemu-debug: videzzo-core
	HYPERVISOR=qemu make videzzo-core
	CFLAGS="-DVIDEZZO_DEBUG" make -C videzzo_qemu

videzzo-virtualbox: videzzo-core
	HYPERVISOR=virtualbox make videzzo-core
	make -C videzzo_virtualbox

videzzo-virtualbox-debug: videzzo-core
	HYPERVISOR=virtualbox make videzzo-core
	CFLAGS="-DVIDEZZO_DEBUG" make -C videzzo_virtualbox

videzzo-bhyve: videzzo-core
	HYPERVISOR=bhyve make videzzo-core
	make -C videzzo_bhyve

videzzo-bhyve-debug: videzzo-core
	HYPERVISOR=bhyve make videzzo-core
	CFLAGS="-DVIDEZZO_DEBUG" make -C videzzo_bhyve

clean:
	rm -rf *.o *.a

distclean: clean
	make -C videzzo_qemu clean
	make -C videzzo_virtualbox clean
	make -C videzzo_bhyve clean
