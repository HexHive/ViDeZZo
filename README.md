# ViDeZZo: Virtual Device Fuzzing Framework

ViDeZZo is a virtual device fuzzing framwork. Now, it supports the latest QEMU.

## Install

We tested ViDeZZo on Ubuntu 18.04.

1. Clone this project.
```
git clone git@github.com:cyruscyliu/videzzo.git
```
2. Make sure gcc/g++ are both there
```
sudo apt-get install -y gcc g++ 
```
3. Export our customized LLVM toolchains.
```
pip install gdown

mkdir llvm-project
pushd llvm-project
gdown https://drive.google.com/uc?id=1n8eESb7lR27zINPOLmOLLrcUQoZTninr # will download our toolchain
tar xf llvm-project-13.tar.gz
popd
export PATH=$PWD/llvm-project/bin:$PATH

```
4. Make sure Python3 (any) is working well.
```
python3 -m pip install picire
```
5. Update binutils.
```
wget https://ftp.gnu.org/gnu/binutils/binutils-2.35.tar.gz
tar xzvf binutils-2.35.tar.gz; cd binutils-2.35; ./configure; make -j8; sudo make install; cd $OLDPWD
sudo rm /usr/bin/objcopy; sudo ln -s /usr/local/bin/objcopy /usr/bin/objcopy
```
6. Compile QEMU
```
make qemu
```

## Reprocuder

Fuzzing is fast in mining vulnerabilities. However, as ViDeZZo introduces
types-aware mutators that inevitably introduces overhead, we avoid using fork()
in ViDeZZo to make the fuzzer faster. Due to accumulated states, some crashes
are not reproducible. We first solve this problem via delta debugging.

1. Please assign the corpus when running a fuzzer
2. Run `02-dd.sh -t ABS_PATH_TO_BINARY -c ABS_PATH_TO_CRASHING_SEED -s
   ABS_PATH_TO_CORPUS`. Importantly, please add * after the curpus path because
   there are actual two corpus directories.
3. Wait and follow the instructions shown after the delta debugging.

## Contribution

If any questions and ideas, please do not hesitate to raise an issse or a pull request.
