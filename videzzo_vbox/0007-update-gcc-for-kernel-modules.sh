#!/bin/bash

# Step 1: Get GCC version used to build the kernel
kernel_gcc_version=$(cat /proc/version | grep -oP 'linux-gnu-gcc-\d+' | cut -d- -f4)

# Step 2: Get current GCC version
current_gcc_version=$(gcc -dumpversion | cut -d. -f1,2)

echo "Kernel GCC version: $kernel_gcc_version"
echo "Current GCC version: $current_gcc_version"

# Step 3: Compare versions
if [ "$kernel_gcc_version" != "$current_gcc_version" ]; then
    echo "GCC version mismatch detected."

    # Step 4: Find matching gcc alternative (assumes it's registered)
    match_path=$(update-alternatives --list gcc | grep "$kernel_gcc_version")

    if [ -n "$match_path" ]; then
        echo "Switching to GCC $kernel_gcc_version at $match_path..."
        echo sudo update-alternatives --set gcc "$match_path"
        echo "GCC version updated. New version: $(gcc -dumpversion)"
    else
        echo "No matching GCC version $kernel_gcc_version found in alternatives."
        sudo apt-get install -y gcc-$kernel_gcc_version g++-$kernel_gcc_version \
            gcc-$kernel_gcc_version-multilib g++-$kernel_gcc_version-multilib
        match_path=$(which gcc-$kernel_gcc_version)
        sudo update-alternatives --install /usr/bin/gcc gcc $match_path 120
        match_path=$(which g++-$kernel_gcc_version)
        sudo update-alternatives --install /usr/bin/g++ g++ $match_path 120
        echo "GCC version updated. New version: $(gcc -dumpversion)"
    fi
else
    echo "GCC version matches the kernel build. No action needed."
fi

