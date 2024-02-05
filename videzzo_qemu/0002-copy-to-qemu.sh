#!/bin/bash

target=qemu/tests/qtest/videzzo
cp ../clangcovdump.h $target/
cp ../videzzo.h $target/
cp ../videzzo_fork.c $target
cp ../videzzo_fork.h $target
cp ../videzzo_fork.ld $target
cp ../libvidezzo.a.qemu $target/libvidezzo.a
cp videzzo_qemu.c $target/
cp videzzo_qemu_types.yaml qemu/
