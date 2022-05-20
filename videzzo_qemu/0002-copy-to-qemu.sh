#!/bin/bash

target=qemu/tests/qtest/fuzz
cp ../clangcovdump.h $target/
cp ../videzzo.h $target/
cp ../libvidezzo.a $target/
cp videzzo_qemu.c $target/
cp videzzo_qemu_types.yaml qemu/
