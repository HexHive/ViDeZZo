# ViDeZZo: Virtual Device Fuzzing Framework

ViDeZZo is a virtual device fuzzing framwork. Now, it supports the latest QEMU.

## Install

We tested ViDeZZo on Ubuntu 18.04.

1. Clone this project.
```
git clone git@github.com:cyruscyliu/videzzo.git
```
2. Export our customized LLVM toolchains.
```
pip install gdown

mkdir llvm-project
pushd llvm-project
gdown https://drive.google.com/uc?id=1n8eESb7lR27zINPOLmOLLrcUQoZTninr # will download our toolchain
tar xf llvm-project-13.tar.gz
popd
export PATH=$PWD/llvm-project/bin:$PATH
```
3. Make sure Python3 (any) is working well.
4. Update binutils.
```
wget https://ftp.gnu.org/gnu/binutils/binutils-2.35.tar.gz
tar xzvf binutils-2.35.tar.gz; cd binutils-2.35; ./configure; make -j8; sudo make install;
sudo rm /usr/bin/objcopy; sudo ln -s /usr/local/bin/objcopy /usr/bin/objcopy
```

## Contribution

If any questions and ideas, please do not hesitate to raise an issse or a pull request.
