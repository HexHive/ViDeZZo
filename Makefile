#
# Type-Aware Virtual-Device Fuzzing
#
# Copyright Qiang Liu <cyruscyliu@gmail.com>
#
# This work is licensed under the terms of the GNU GPL, version 2 or later.
#

SANITIZERS = -fsanitize=address,undefined
CFLAGS ?= -g -fPIE -fno-omit-frame-pointer -fno-optimize-sibling-calls

videzzo-merge:
	clang ${CFLAGS} -o videzzo-merge merge.c videzzo.c

videzzo-poc-gen:
	clang ${CFLAGS} -o videzzo-poc-gen poc-gen.c videzzo.c

tools: videzzo-merge videzzo-poc-gen

videzzo-core:
	python3 videzzo_types_gen.py ${HYPERVISOR}
	clang ${CFLAGS} -o videzzo.o -c videzzo.c
	clang ${CFLAGS} -o videzzo_types.i -E videzzo_types.c
	clang ${CFLAGS} -o videzzo_types.o -c videzzo_types.c
	ar rcs libvidezzo.a videzzo.o videzzo_types.o

videzzo-vmm:
	CFLAGS="${CFLAGS} ${SANITIZERS}"                 HYPERVISOR=vmm make videzzo-core
	clang -fsanitize=fuzzer ${CFLAGS} ${SANITIZERS} \
		-videzzo-instrumentation=./videzzo_vmm_types.yaml -flegacy-pass-manager \
		-o vmm       videzzo_vmm.c libvidezzo.a

videzzo-vmm-debug:
	CFLAGS="${CFLAGS} ${SANITIZERS} -DVIDEZZO_DEBUG" HYPERVISOR=vmm make videzzo-core
	clang -fsanitize=fuzzer ${CFLAGS} ${SANITIZERS} -DVIDEZZO_DEBUG  \
		-videzzo-instrumentation=./videzzo_vmm_types.yaml -flegacy-pass-manager \
		-o vmm-debug videzzo_vmm.c libvidezzo.a

vmm: videzzo-vmm videzzo-vmm-debug

videzzo-qemu:
	CFLAGS="${CFLAGS} ${SANITIZERS}"                 HYPERVISOR=qemu make videzzo-core
	make -C videzzo_qemu qemu clusterfuzz

videzzo-qemu-coverage:
	CFLAGS="${CFLAGS}"                               HYPERVISOR=qemu make videzzo-core
	make -C videzzo_qemu qemu-coverage clusterfuzz-coverage

videzzo-qemu-debug:
	CFLAGS="${CFLAGS} ${SANITIZERS} -DVIDEZZO_DEBUG" HYPERVISOR=qemu make videzzo-core
	make -C videzzo_qemu qemu-debug clusterfuzz-debug

qemu: videzzo-qemu

qemu-coverage: videzzo-qemu-coverage

qemu-debug: videzzo-qemu-debug

clean:
	rm -rf *.o *.a *.i videzzo-merge

distclean: clean
	make -C videzzo_qemu clean
	make -C videzzo_virtualbox clean
	make -C videzzo_bhyve clean
