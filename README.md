# ViDeZZo: Dependency-aware Virtual Device Fuzzing Framework

ViDeZZo is a virtual device fuzzing framework considering both intra- and
inter-message dependencies to balance fuzzing scalability and efficiency.

Currently, ViDeZZo supports libFuzzer in combination with ASAN and UBSAN.

Currently, ViDeZZo supports QEMU (C) and VirtualBox (C++) covering Audio,
Storage, Network, USB, and Graphics virtual devices, and covering i386, x86_64,
ARM, and AArch64 builds.

More technical details go in to our paper. The usage of ViDeZZo is as follows.

## Docker container

We recommend running ViDeZZo in a docker container. We also tested ViDeZZo on a
native Ubuntu 20.04 host.

```
sudo docker build -t videzzo:latest .
sudo docker build --target base -t videzzo:latest . # for artifact evaluation only
sudo docker run --rm -it -v $PWD:/root/videzzo videzzo:latest /bin/bash
```

## Fuzzing process

In practice, we fuzz QEMU and VirtualBox virtual devices as follows.

1. Maintain ViDeZZo (ViDeZZo's Maintainer)

>Fix any bugs in ViDeZZo, adjust fuzzing policies, tune performance, and new
features to ViDeZZo, e.g., add new virtual device target.

+ Add a new virtual device target: follow `predefined_configs` in both
[videzzo_qemu.c](./videzzo_qemu/videzzo_qemu.c) and
[VBoxViDeZZo.cpp](./videzzo_vbox/VBoxViDeZZo.cpp); follow this
[manual](./docs/IntraMessageDependenciesManuals.md) and update
[videzzo_types_gen_vmm.py](./videzzo_types_gen_vmm.py).

2. Deploy ViDeZZo Locally (Automation Script)

>Build both QEMU and VirtualBox targets, and fuzz all virtual devices on a
machine. Usually, we enable ASAN and UBSAN. Considering the number of resources,
virtual devices, and hours we have, we deploy the fuzzing campaign
automatically. Use `-detect_leaks=0` as we do not prefer small leakages.

+ Build: `cd videzzo`, and then `make qemu` or `make vbox`.

+ Test: To test a virtual device, go to `videzzo_qemu/out-san` or
`videzzo_vbox/out-san`, and then run binary there. Note that, to test VBox
virtual device, start with `sudo`.

3. Triage bugs (Security Analyst)

>Evaluate security impacts of crashes, fix bugs and verify, submit patches and
discuss in communities. Apply for CVE and advertise if it is necessary.

+ Collect historical seeds: run the crashed fuzz target with `CORPUS`,
`DEFAULT_INPUT_MAXSIZE=10000000`, and `-max_len=10000000`, where `10000000` is a
large value decided by the running status to make sure every event is dumped.

``` bash
DEFAULT_INPUT_MAXSIZE=10000000 \
./qemu-videzzo-i386-target-videzzo-fuzz-ohci -max_len=10000000 -detect_leaks=0 ohci
```

+ Delta-debug and gen a PoC: run `02-dd.sh -t ABS_PATH_TO_BINARY -s
ABS_PATH_TO_CORPUS -c ABS_PATH_TO_CRASHING_SEED`. Note that UBSAN bugs need to
enable "halt_on_error" and the check of "runtime error".

## Source code coverage profiling

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
