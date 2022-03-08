#!/bin/bash

target=qemu/tests/qtest/fuzz
cp ../videzzo.h $target/
cp ../libvidezzo.a $target/
cp videzzo_qemu.c $target/
cp videzzo_qemu.h $target/
cp videzzo_qemu_types.yaml qemu/
