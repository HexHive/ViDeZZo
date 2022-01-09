# ViDeZZo: Virtual Device Fuzzing Framework

ViDeZZo is a virtual device fuzzing framwork. Now, it supports QEMU, VirtualBox,
and BHyve.

## Install

1. Download our customized LLVM toolchains.
```
git clone git@github.com:cyruscyliu/virtfuzz-llvm-project.git llvm-project --depth=1
pushd llvm-project && mkdir build-custom && pushd build-custom
cmake -G Ninja -DLLVM_USE_LINKER=gold -DLLVM_ENABLE_PROJECTS="clang;compiler-rt" -DLLVM_TARGETS_TO_BUILD=X86 -DLLVM_OPTIMIZED_TABLEGEN=ON ../llvm/
ninja clang compiler-rt llvm-symbolizer llvm-profdata llvm-cov
popd && popd
export PATH=$PWD/llvm-project/build-custom/bin:$PATH
```
2. Make sure Python3 (any) is working well.
3. Update binutils.
```
wget https://ftp.gnu.org/gnu/binutils/binutils-2.35.tar.gz
tar xzvf binutils-2.35.tar.gz; cd binutils-2.35; ./configure; make -j8; sudo make install;
sudo rm /usr/bin/objcopy; sudo ln -s /usr/local/bin/objcopy /usr/bin/objcopy
```
4. clone this project
```
git clone git@github.com:cyruscyliu/videzzo.git
```

## Contribution

If any questions and ideas, please do not hesitate to raise an issse.
