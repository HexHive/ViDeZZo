# ViDeZZo: Dependency-aware Virtual Device Fuzzing Framework

!!! For better communication, please join our [discord](https://discord.gg/9tuPhCtr) server. !!!

ViDeZZo is a virtual device fuzzing framework considering both intra- and
inter-message dependencies to balance fuzzing scalability and efficiency.
The [research paper](https://nebelwelt.net/files/23Oakland4.pdf) was accepted by IEEE S&P 2023.

Currently, ViDeZZo supports libFuzzer in combination with ASAN and UBSAN.

Currently, ViDeZZo supports QEMU (6.1.50 and above) and VirtualBox (C++)
covering Audio, Storage, Network, USB, and Graphics virtual devices, and
covering i386, x86_64, ARM, and AArch64 builds.

A develop plan is as follows.
+ group mutators are not thread safe in vbox, and reproduction doesn't work either
+ consider all pitfalls and maybe reimplement the grammar interpreter

Part of virtual device code is not covered by ViDeZZo due to the lack of VM
snapshot/migration and device plug in/out. Nevertheless, we do not have a plan
to support them.

The usage of ViDeZZo is as follows.

## Quick start

Step 1: build and enter the docker container

``` bash
sudo docker build -t videzzo:latest .
sudo docker run --rm -it -v $PWD:/root/videzzo videzzo:latest /bin/bash
```

More adjustment is necessary for VirtualBox as VirtualBox would install its
kernel modules into the host system.

```
sudo docker run --rm -it \
    -v /usr/src:/usr/src \
    -v /dev:/dev \
    -v /lib/modules:/lib/modules \
    --privileged \
    -v $PWD:/root/videzzo videzzo:latest \
    /bin/bash
```

We recommend running ViDeZZo in a docker container.

We also tested ViDeZZo on a native Ubuntu 20.04 host, espicailly for VirtualBox.
Note that, testing VirtualBox virtual devices requires `sudo` or a root user.

Step 2: build and test QEMU and VirtualBox (artifact evaluation)

``` bash
cd videzzo
make qemu qemu-coverage
make vbox vbox-coverage
```

`make qemu` compiles the latest QEMU with ASAN and UBSAN and `make qemu-coverage`
compiles the latest QEMU with source code coverage profiling. For the fuzzing
only, go to `videzzo_qemu/out-san` and run binary there.  Use `-detect_leaks=0`
as we do not prefer small leakages.  For the coverage collection, go to
`videzzo_qemu/out-cov` and run binary there. This also applies to VirtualBox.

We develop scripts to make life easy. Let's say we want to fuzz QEMU ac97 for 60
second in pure fuzzing mode and coverage collection mode.

``` bash
bash -x videzzo_tool/01-quick-san.sh qemu i386 ac97 60
bash -x videzzo_tool/04-quick-cov.sh qemu i386 ac97 60
```

## Advanced usage - Crash-Resistant Mode

ViDeZZo has supported a built-in fork server that allows no stop if there is any
crash. Enable it with VIDEZZO_FORK=1. Or use the scripts as follows. However,
the performance deteriorates very much.

``` bash
bash -x videzzo_tool/01-quick-san.sh qemu i386 ac97 60 fork
bash -x videzzo_tool/04-quick-cov.sh qemu i386 ac97 60 fork
```

LibFuzzer `-jobs` and `-workers` should be working automatically.

``` bash
LIBFUZZER_ARGS="-jobs=2 -workers=2" \
bash -x videzzo_tool/01-quick-san.sh qemu i386 ac97 60 fork
```

fuzz-<JOB>.log should be found in `out-san`.

## Advanced usage - Fuzzing process

In practice, we fuzz QEMU and VirtualBox virtual devices as follows.

1. Maintain ViDeZZo (ViDeZZo's Maintainer)

+ Task: Fix any bugs in ViDeZZo, adjust fuzzing policies, tune performance, and
add new features to ViDeZZo, e.g., add new virtual device target.

+ How to tune performance: I usually use
[FlameGraph](https://github.com/brendangregg/FlameGraph) to highlight which
functions take in much time.

+ How to add a new virtual device target: follow `predefined_configs` in both
[videzzo_qemu.c](./videzzo_qemu/videzzo_qemu.c) and
[VBoxViDeZZo.cpp](./videzzo_vbox/VBoxViDeZZo.cpp); follow this
[manual](./docs/IntraMessageDependenciesManuals.md) and update
[videzzo_types_gen_vmm.py](./videzzo_types_gen_vmm.py).

2. Deploy ViDeZZo Locally (Security Analyst)

+ 2.1 build: `cd videzzo && make qemu vbox`.

+ 2.2 deploy: if we want to fuzz all QEMU virtual devices for 24 hours for the
first time, we can run `./videzzo_tool/05-deploy.sh -t 86400 -v qemu 0`. See
[05-deply.sh](./videzzo_tool/05-deploy.sh) for more information.

3. Triage bugs (Security Analyst)

+ 3.1 collect historical seeds: run the crashed fuzz target with
`DEFAULT_INPUT_MAXSIZE=10000000`, `-max_len=10000000`, where `10000000` is a
large value decided by the running status to make sure every event is dumped,
and enable `CORPUS`. For example, `DEFAULT_INPUT_MAXSIZE=10000000
./qemu-videzzo-i386-target-videzzo-fuzz-ohci -max_len=10000000 -detect_leaks=0
ohci`. To capture UBSAN bugs, please `export
UBSAN_OPTIONS=halt_on_error=1:symbolize=1:print_stacktrace=1`.

+ 3.2 delta-debug and gen a PoC: run `02-dd.sh -t ABS_PATH_TO_BINARY -s
ABS_PATH_TO_CORPUS -c ABS_PATH_TO_CRASHING_SEED`. To capture UBSAN bugs, please
add `-e "runtime error"`.

+ 3.3 minimize this PoC: run `06-minimize.sh -t ABS_PATH_TO_BINARY -c
ABS_PATH_TO_CRASHING_POC`. To capture UBSAN bugs, please add `-e "runtime
error"`.

+ 3.4 you may want to dump this poc and change it: run
`DEFAULT_INPUT_MAXSIZE=10000000 ./videzzo_tool/videzzo-poc-gen -i binary -o text
-O path/to/text path/to/poc` to deserialize a PoC to a plan text file.  Modify
the text file and then serialize it: `DEFAULT_INPUT_MAXSIZE=10000000
./videzzo_tool/videzzo-poc-gen -i text -o binary -O path/to/poc path/to/binary`.

+ 3.5 analyze the minimized PoC: Evaluate security impacts of crashes, report,
discuss, and submit your patches. Apply for CVE and advertise if it is possible.
See [this](https://github.com/HexHive/virtfuzz-bugs) project for more
information.

## Q&A about the toolchain

With the command line in Step 1, the toolchain (clang-13) is automatically
downloaded into the docker image. You can also [build the toolchain
yourself](https://github.com/cyruscyliu/videzzo-llvm-project). In this way, you
need to adjust the command lines a little bit.

```
sudo docker build --target base -t videzzo:latest .
sudo docker run --rm \
    -v $PWD/videzzo-llvm-project:/root/llvm-project \
    -e PATH=$PATH:/root/llvm-project/build-custom/bin \
    -v $PWD/videzzo:/root/videzzo \
    -v /usr/src:/usr/src \
    -v /dev:/dev \
    -v /lib/modules:/lib/modules \
    --privileged \
    -it videzzo:latest /bin/bash
```

## Contribution

If any questions and ideas, please do not hesitate to raise an issue. A pull
request is also welcome!
