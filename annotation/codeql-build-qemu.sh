./configure \
    --disable-werror --enable-debug \
    --target-list="i386-softmmu arm-softmmu aarch64-softmmu"
make -j$(nproc)
