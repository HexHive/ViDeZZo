#!/bin/bash

target=vbox/src/VBox/Frontends/VBoxViDeZZo
cp ../clangcovdump.h $target/
cp ../videzzo.h $target/
cp ../libvidezzo.a $target/
cp Makefile.kmk $target/
cp VBoxViDeZZo.cpp $target/
cp VBoxViDeZZoHardened.cpp $target/
cp videzzo_vbox_types.yaml $target/
