#
# Type-Aware Virtual-Device Fuzzing
#
# Copyright Qiang Liu <cyruscyliu@gmail.com>
#
# This work is licensed under the terms of the GNU GPL, version 2 or later.
#

SANITIZERS = -fsanitize=address,undefined
CFLAGS ?= -g -fPIE -fno-omit-frame-pointer -fno-optimize-sibling-calls \
		  -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include

videzzo-tool:
	CFLAGS="${CFLAGS}" make -C videzzo_tool all

tool: videzzo-tool

videzzo-core:
	python3 videzzo_types_gen.py ${HYPERVISOR}
	clang ${CFLAGS} -o videzzo.o -c videzzo.c
	clang ${CFLAGS} -o videzzo_types.i -E videzzo_types.c
	clang ${CFLAGS} -o videzzo_types.o -c videzzo_types.c
	ar rcs libvidezzo.a videzzo.o videzzo_types.o

videzzo-qemu:
	CFLAGS="${CFLAGS} ${SANITIZERS}"                 HYPERVISOR=qemu make videzzo-core
	make -C videzzo_qemu qemu clusterfuzz

videzzo-vbox:
	CFLAGS="${CFLAGS} ${SANITIZERS}"                 HYPERVISOR=vbox make videzzo-core
	make -C videzzo_vbox vbox clusterfuzz

videzzo-qemu-coverage:
	CFLAGS="${CFLAGS}"                               HYPERVISOR=qemu make videzzo-core
	make -C videzzo_qemu qemu-coverage clusterfuzz-coverage

videzzo-vbox-coverage:
	CFLAGS="${CFLAGS}"                               HYPERVISOR=vbox make videzzo-core
	make -C videzzo_vbox vbox-coverage clusterfuzz-coverage

videzzo-qemu-debug:
	CFLAGS="${CFLAGS} ${SANITIZERS} -DVIDEZZO_DEBUG" HYPERVISOR=qemu make videzzo-core
	make -C videzzo_qemu qemu-debug clusterfuzz-debug

videzzo-vbox-debug:
	CFLAGS="${CFLAGS} ${SANITIZERS} -DVIDEZZO_DEBUG" HYPERVISOR=vbox make videzzo-core
	make -C videzzo_vbox vbox-debug clusterfuzz-debug

qemu: videzzo-qemu

vbox: videzzo-vbox

qemu-coverage: videzzo-qemu-coverage

vbox-coverage: videzzo-vbox-coverage

qemu-debug: videzzo-qemu-debug

vbox-debug: videzzo-vbox-debug

clean:
	rm -rf *.o *.a *.i videzzo-merge

distclean: clean
	make -C videzzo_qemu clean
	make -C videzzo_vbox clean
	make -C videzzo_tool clean
