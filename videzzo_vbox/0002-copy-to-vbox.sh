#!/bin/bash

target=vbox/src/VBox
cp ../clangcovdump.h $target/Devices/build
cp ../videzzo.h $target/Frontends/VBoxManage
cp ../libvidezzo.a $target/Frontends/VBoxManage
cp VBoxViDeZZo.cpp $target/Frontends/VBoxManage
cp VBoxMalloc.h $target/Frontends/VBoxManage
cp CLANG.kmk vbox/kBuild/tools
cp videzzo_vbox_types.yaml vbox
cp export_symbol_list.txt vbox
