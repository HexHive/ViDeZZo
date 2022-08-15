# ViDeZZo: Dependency-aware Virtual Device Fuzzing Framework

ViDeZZo is a virtual device fuzzing framework considering both intra- and
inter-message dependencies to balance fuzzing scalability and efficiency. More
technical details go in to our paper.

Currently, ViDeZZo supports libFuzzer in combination with ASAN and UBSAN.

Currently, ViDeZZo supports QEMU (C) and VirtualBox (C++) covering Audio,
Storage, Network, USB, and Graphics virtual devices, and covering i386, x86_64,
ARM, and AArch64 builds.

The usage of ViDeZZo is as follows.

## Quick start

Step 1: build and enter the docker container

``` bash
sudo docker build -t videzzo:latest .
sudo docker run --rm -it -v $PWD:/root/videzzo videzzo:latest /bin/bash
```

We recommend running ViDeZZo in a docker container.

We also tested ViDeZZo on a native Ubuntu 20.04 host.

For artifact evaluation, it's not necessary to download the tool chain. `sudo
docker build --target base -t videzzo:latest .` is enough.

Step 2: build and test QEMU and VirtualBox

``` bash
cd videzzo
make qemu vbox
```

To test a virtual device, go to `videzzo_qemu/out-san` or
`videzzo_vbox/out-san`, and then run binary there. Usually, we enable ASAN and
UBSAN. Use `-detect_leaks=0` as we do not prefer small leakages.

Note that, testing VirtualBox virtual devices requires `sudo` or a root user.

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
ohci`

+ 3.2 delta-debug and gen a PoC: run `02-dd.sh -t ABS_PATH_TO_BINARY -s
ABS_PATH_TO_CORPUS -c ABS_PATH_TO_CRASHING_SEED`. Note that UBSAN bugs need to
enable "halt_on_error" and the check of "runtime error".

+ 3.3 minimize this PoC: run `06-minimize.sh -t ABS_PATH_TO_BINARY -c
ABS_PATH_TO_CRASHING_POC`. Note that UBSAN bugs need to enable "halt_on_error"
and the check of "runtime error".

+ 3.4 analyze this minimized PoC: Evaluate security impacts of crashes, fix bugs
and verify, submit patches and discuss in communities. Apply for CVE and
advertise if it is necessary. See
[this](https://github.com/HexHive/virtfuzz-bugs) project for more information.

+ 3.5 modify this PoC to exploit the primitive capability: run
`DEFAULT_INPUT_MAXSIZE=10000000 ./videzzo_tool/videzzo-poc-gen -i binary -o text
-O path/to/text path/to/poc` to deserialize a PoC to a plan text file.  Modify
the text file and then serialize it: `DEFAULT_INPUT_MAXSIZE=10000000
./videzzo_tool/videzzo-poc-gen -i text -o binary -O path/to/poc path/to/binary`.

## Advanced usage: Source code coverage profiling

With source code coverage profiling, we know what we can or cannot improve. To
enable the profiling, `make qemu-cov` or `make vbox-cov`, and then run binary in
`videzzo_qemu/out-cov` or `videzzo_vbox/out-cov`. Next, pick up any uncover code
and update the ViDeZZo to support it.

Part of code is not covered by ViDeZZo due to the following reasons. Currently,
we do not have a plan to support them.

+ VM Snapshot
+ Device plug in/out

## Contribution

If any questions and ideas, please do not hesitate to raise an issue or a pull
request.
