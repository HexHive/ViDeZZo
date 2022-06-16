#!/bin/bash

target=vbox/src/VBox/Frontends/VBoxManage
cp ../clangcovdump.h $target/
cp ../videzzo.h $target/
cp ../libvidezzo.a $target/
cp VBoxViDeZZo.cpp $target/
cp CLANG.kmk vbox/kBuild/tools
