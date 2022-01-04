#
# Type-Aware Virtual-Device Fuzzing
# 
# Copyright Qiang Liu <cyruscyliu@gmail.com>
#  
# This work is licensed under the terms of the GNU GPL, version 2 or later.
# 
CFLAGS ?= "-fno-omit-frame-pointer -fno-optimize-sibling-calls -fno-pie"

videzzo-test:
	clang -g -fsanitize=address,undefined ${CFALGS} \
		-o test test.c videzzo_vmm.c videzzo.c videzzo_lib.c videzzo_types.c

test: videzzo-test
	./test

videzzo-vmm:
	clang -g -fsanitize=fuzzer,address,undefined ${CFALGS} \
		-o vmm videzzo_vmm.c videzzo.c videzzo_lib.c videzzo_types.c

videzzo-vmm-debug:
	clang -g -fsanitize=fuzzer,address,undefined ${CFALGS} -DVIDEZZO_DEBUG \
		-o vmm-debug videzzo_vmm.c videzzo.c videzzo_lib.c videzzo_types.c

run: videzzo-vmm
	./vmm

debug: videzzo-vmm-debug
	./vmm-debug

clean:
	rm test
