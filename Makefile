#
# Type-Aware Virtual-Device Fuzzing
#
# Copyright Qiang Liu <cyruscyliu@gmail.com>
#
# This work is licensed under the terms of the GNU GPL, version 2 or later.
#

CFLAGS ?= "-fno-omit-frame-pointer -fno-optimize-sibling-calls -fno-pie"
VIDEZZO_CORE=videzzo.c videzzo_lib.c # videzzo_types.c

videzzo-test:
	clang -g -fsanitize=address,undefined ${CFALGS} \
		-o test test.c videzzo_vmm.c ${VIDEZZO_CORE}

videzzo-vmm:
	clang -g -fsanitize=fuzzer,address,undefined ${CFALGS} \
		-o vmm videzzo_vmm.c ${VIDEZZO_CORE}

videzzo-vmm-debug:
	clang -g -fsanitize=fuzzer,address,undefined ${CFALGS} -DVIDEZZO_DEBUG \
		-o vmm-debug videzzo_vmm.c ${VIDEZZO_CORE}

.PHONY: videzzo-qemu videzzo-virtualbox videzzo-bhyve

videzzo-qemu:
	make -C videzzo_qemu

videzzo-qemu-debug:
	CFLAGS="-DVIDEZZO_DEBUG" make -C videzzo_qemu

videzzo-virtualbox:
	make -C videzzo_virtualbox

videzzo-virtualbox-debug:
	CFLAGS="-DVIDEZZO_DEBUG" make -C videzzo_virtualbox

videzzo-bhyve:
	make -C videzzo_bhyve

videzzo-bhyve-debug:
	CFLAGS="-DVIDEZZO_DEBUG" make -C videzzo_bhyve

clean:
	rm test
