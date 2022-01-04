#
# Type-Aware Virtual-Device Fuzzing
#
# Copyright Qiang Liu <cyruscyliu@gmail.com>
#
# This work is licensed under the terms of the GNU GPL, version 2 or later.
#

CFLAGS ?= "-fno-omit-frame-pointer -fno-optimize-sibling-calls -fno-pie"

videzzo-core:
	clang -g -fsanitize=address,undefined -o videzzo.o -c videzzo.c
	clang -g -fsanitize=address,undefined -o videzzo_lib.o -c videzzo_lib.c

videzzo-test:
	clang -g -fsanitize=address,undefined ${CFALGS} \
		-o test test.c videzzo_vmm.c videzzo.c videzzo_lib.c # videzzo_types.c

videzzo-vmm:
	clang -g -fsanitize=fuzzer,address,undefined ${CFALGS} \
		-o vmm videzzo_vmm.c videzzo.c videzzo_lib.c # videzzo_types.c

videzzo-vmm-debug:
	clang -g -fsanitize=fuzzer,address,undefined ${CFALGS} -DVIDEZZO_DEBUG \
		-o vmm-debug videzzo_vmm.c videzzo.c videzzo_lib.c # videzzo_types.c

.PHONY: videzzo-qemu videzzo-virtualbox videzzo-bhyve

videzzo-qemu: videzzo-core
	ar rcs videzzo_core.a videzzo.o videzzo_lib.o
	VIDEZZO_CORE=$PWD/videzz_core.a make -C videzzo_qemu

videzzo-qemu-debug: videzzo-core
	CFLAGS="-DVIDEZZO_DEBUG" make -C videzzo_qemu

videzzo-virtualbox: videzzo-core
	make -C videzzo_virtualbox

videzzo-virtualbox-debug: videzzo-core
	CFLAGS="-DVIDEZZO_DEBUG" make -C videzzo_virtualbox

videzzo-bhyve: videzzo-core
	make -C videzzo_bhyve

videzzo-bhyve-debug: videzzo-core
	CFLAGS="-DVIDEZZO_DEBUG" make -C videzzo_bhyve

clean:
	rm test
