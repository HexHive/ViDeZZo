# ViDeZZo: Dependency-aware Virtual Device Fuzzing Framework

ViDeZZo is a virtual device fuzzing framwork considering both intra- and
inter-message dependencies. 

Now, it supports the latest QEMU and VirtualBox, which is tested on Ubuntu
20.04.

## Prepare a Docker container

Please build the docker image and run the container,

```
sudo docker build -t videzzo:latest .
sudo docker run --rm -it -v $PWD:/root/videzzo videzzo:latest /bin/bash
```

## Test QEMU and VirtualBox

Before testing, please `cd videzzo`, and then `make qemu` or `make vbox`.

To test a virtual device, please go to `videzzo_qemu/out-san` or
`videzzo_vbox/out-san`, and then run binary there. Note that, to test VBox
virtual device, please `sudo`.

To enable source code coverage profile, please `make qemu-cov` or `make
vbox-cov`, and then run binary in `videzzo_qemu/out-cov` or
`videzzo_vbox/out-cov`.

## Add a new virtual device

Please follow `predefined_configs` in both
[videzzo_qemu.c](./videzzo_qemu/videzzo_qemu.c) and
[VBoxViDeZZo.cpp](./videzzo_vbox/VBoxViDeZZo.cpp).

## Update intra-message annotation

Please follow this [manual](./docs/IntraMessageDependenciesManuals.md) and
update [videzzo_types_gen_vmm.py](./videzzo_types_gen_vmm.py).

## Collect source code coverage profile

Please run [04-quick-cov.sh](./04-quick-cov.sh).

## Crash and Reproduce

Please run [01-quick-bug.py](./01-quick-bug.py).

As we don't use fork() in ViDeZZo, ViDeZZo is faster. However, due to
accumulated states, some crashes are not reproducible. We first solve this
problem via delta debugging.

1. Please use corpus `CORPUS` when running a fuzzer
2. Run `02-dd.sh -t ABS_PATH_TO_BINARY -c ABS_PATH_TO_CRASHING_SEED -s
   ABS_PATH_TO_CORPUS`.
3. Wait and follow the instructions shown after the delta debugging.

## Contribution

If any questions and ideas, please do not hesitate to raise an issse or a pull
request.
