#
# Dependency-Aware Virtual-Device Fuzzing
#
# Copyright Qiang Liu <cyruscyliu@gmail.com>
#
# This work is licensed under the terms of the GNU GPL, version 2 or later.
#

videzzo-merge:
	clang ${CFLAGS} -I.. -o videzzo-merge merge.c ../videzzo.c -lvncclient -lgmodule-2.0 -lglib-2.0 -lpthread -lrt

videzzo-poc-gen:
	clang ${CFLAGS} -I.. -o videzzo-poc-gen poc-gen.c ../videzzo.c -lvncclient -lgmodule-2.0 -lglib-2.0 -lpthread -lrt

all: videzzo-merge videzzo-poc-gen

clean:
	rm -f videzzo-merge videzzo-poc-gen
