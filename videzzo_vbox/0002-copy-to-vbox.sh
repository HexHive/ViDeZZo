#!/bin/bash

target=vbox/src/VBox/Frontends/VBoxViDeZZo
test -d $target || mkdir $target
cp ../clangcovdump.h $target/
cp ../videzzo.h $target/
cp ../libvidezzo.a $target/
cp Makefile.kmk $target/
cp VBoxViDeZZo.cpp $target/
cp CLANG.kmk vbox/kBuild/tools
