# ViDeZZo: Virtual Device Fuzzing Framework

ViDeZZo is a virtual device fuzzing framwork. Now, it supports QEMU, VirtualBox,
and BHyve.

## Usage

1. Download our customized LLVM toolchains.
```
git clone git@github.com:cyruscyliu/virtfuzz-llvm-project.git llvm-project --depth=1
pushd llvm-project && mkdir build-custom && pushd build-custom
cmake -G Ninja -DLLVM_USE_LINKER=gold -DLLVM_ENABLE_PROJECTS="clang;compiler-rt" -DLLVM_TARGETS_TO_BUILD=X86 -DLLVM_OPTIMIZED_TABLEGEN=ON ../llvm/
ninja clang compiler-rt llvm-symbolizer llvm-profdata llvm-cov
popd && popd
```

## Contribution

If any questions and ideas, please do not hesitate to raise an issse.
