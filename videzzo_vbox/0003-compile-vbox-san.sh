#!/bin/bash

pushd vbox
CC=clang CXX=clang++ ./configure --disable-hardening --disable-docs
source ./env.sh
kmk ?
popd
