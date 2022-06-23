# ViDeZZo: Virtual Device Fuzzing Framework

ViDeZZo is a virtual device fuzzing framwork. Now, it supports the latest QEMU
and VirtualBox.

Tested on Ubuntu 20.04.

## Build and Run

Please build the docker image and run the container,

```
sudo docker build -t videzzo:latest .
sudo docker run --rm -it -v $PWD:/root/videzzo videzzo:latest /bin/bash
```

or follow the Docker to install all necessary packages.

+ VMM (a generic VMM for tests)

VMM is a generic VMM with limited functionality to test ViDeZZo. To build it,
`make vmm` is enough. To launch it, please run `./vmm` or `./vmm-debug` for more
debug information.

+ QEMU

To build it, please `cd videzzo && make qemu`. To run it, please go to
`videzzo_qemu/out-san` and run binary there. If to check virtual device
messages, please run `make qemu-debug`.

+ VirtualBox

To build it, please `cd videzzo && make vbox`. To run it, please go to
`videzzo_vbox/out-san` and run binary with `sudo` there. If to check virtual
device messages, please run `make vbox-debug`.

## Reprocuder

As we don't use fork() in ViDeZZo, ViDeZZo is faster. However, due to
accumulated states, some crashes are not reproducible. We first solve this
problem via delta debugging.

1. Please use corpus `CORPUS` when running a fuzzer
2. Run `02-dd.sh -t ABS_PATH_TO_BINARY -c ABS_PATH_TO_CRASHING_SEED -s
   ABS_PATH_TO_CORPUS`.
3. Wait and follow the instructions shown after the delta debugging.

## Contribution

If any questions and ideas, please do not hesitate to raise an issse or a pull request.
