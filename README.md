# ViDeZZo: Virtual Device Fuzzing Framework

ViDeZZo is a virtual device fuzzing framwork. Now, it supports the latest QEMU.

## Build and Run

[Optional] Please build the docker image and run the container.

```
sudo docker build -t videzzo:latest .
sudo docker run --rm -it -v $PWD:/root/videzzo videzzo:latest /bin/bash
```

+ VMM (a generic VMM for tests)

VMM is a generic VMM with limited functionality to test ViDeZZo. To build it,
`make vmm` is enough. To launch it, please run `./vmm` or `./vmm-debug` for more
debug information.

+ QEMU

To build it, please `cd videzzo && make qemu`. To run it, please go to
`videzzo_qemu/out` and run binary there. If to check virtual device messages,
please run `make qemu-debug`.

## Reprocuder

As ViDeZZo introduces types-aware mutators that inevitably introduces overhead,
we avoid using fork() in ViDeZZo to make the fuzzer faster. Due to accumulated
states, some crashes are not reproducible. We first solve this problem via delta
debugging.

1. Please use corpus when running a fuzzer
2. Run `02-dd.sh -t ABS_PATH_TO_BINARY -c ABS_PATH_TO_CRASHING_SEED -s
   ABS_PATH_TO_CORPUS`. Importantly, please add * after the curpus path because
   there are actual two corpus directories.
3. Wait and follow the instructions shown after the delta debugging.

## Contribution

If any questions and ideas, please do not hesitate to raise an issse or a pull request.
