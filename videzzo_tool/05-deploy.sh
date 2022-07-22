#!/usr/bin/bash

function usage() {
cat << HEREDOC
 Usage: $0 [-b blocklist.txt] [-t timeout] [-v qemu|vbox|all] revision

 positional arguments:
   revision          revision (int) of current fuzzing compaign

 optional arguments:
   -b, blocklist.txt absolute pathname of the blocked fuzz target
   -t, timeout       number of seconds we want to run, 86400 by default
   -v, qemu|vbox|all virtual machine manager we want to fuzz, all by default
   -h                show this help message and exit

HEREDOC
   exit 1
}

blocklist=$(pwd)/videzzo_tool/blocklist.txt
timeout=86400
vmm='all'

while getopts ":b:t:v:" o; do
case "${o}" in
 b)
   blocklist=${OPTARG}
   ;;
 t)
   timeout=${OPTARG}
   ;;
 v)
   vmm=${OPTARG}
   ((vmm == 'vbox' || vmm == 'qemu' || vmm == 'all')) || usage
   ;;
 *)
   usage
   ;;
esac
done

revision=${@:$OPTIND:1}

if [ -z ${revision} ]; then
    usage
fi

echo "[+] === We are going to deploy ViDeZZo. ==="

if [ ! -f "$(pwd)/videzzo.c" ]; then
    echo "[+] We are not in the root directory. Exit."
    exit 1
fi

if [ ${vmm} = "all" ]; then
    echo [-] make qemu
    echo [-] make vbox
elif [ ${vmm} = "qemu" ]; then
    echo [-] make qemu
elif [ ${vmm} = "vbox" ]; then
    echo [-] make vbox
fi

echo "[+] Load blocklist.txt ..."
__blocklist=()

while IFS= read -r pattern; do
    if [ -z "${pattern}" ]; then
        continue
    elif [ "${pattern:0:1}" = "#" ]; then
        continue
    else
        echo "   - ${pattern}"
        __blocklist+=("${pattern}")
    fi
done < ${blocklist}

function is_blocked() {
    filename=$1
    echo "   - ${filename}"
    for pattern in ${__blocklist[@]}; do
        case ${filename} in
            ${pattern}) echo "   ~ ${pattern} matched"; return 1 ;;
        esac
    done
    return 0
}

number_of_qemu_fuzz_target=0
number_of_vbox_fuzz_target=0
number_of_fuzz_target=0

qemu_fuzz_target=()
vbox_fuzz_target=()

function count_qemu() {
    dir=videzzo_qemu/out-san
    for target in ${dir}/*; do
        fuzz_target=$(basename ${target})
        is_blocked ${fuzz_target}
        if [ $? == 0 ]; then
            number_of_qemu_fuzz_target=$((number_of_qemu_fuzz_target+1))
            qemu_fuzz_target+=("${fuzz_target}")
        fi
    done
}

function count_vbox() {
    dir=videzzo_vbox/out-san
    for target in ${dir}/*; do
        fuzz_target=$(basename ${target})
        is_blocked ${fuzz_target}
        if [ $? == 0 ]; then
            number_of_vbox_fuzz_target=$((number_of_vbox_fuzz_target+1))
            vbox_fuzz_target+=("${fuzz_target}")
        fi
    done
}

echo "[+] Traverse fuzz targets"

if [ ${vmm} = "all" ]; then
    count_qemu
    count_vbox
elif [ ${vmm} = "qemu" ]; then
    count_qemu
elif [ ${vmm} = "vbox" ]; then
    count_vbox
fi

number_of_fuzz_target=$(expr ${number_of_qemu_fuzz_target} + ${number_of_vbox_fuzz_target})

echo "[+] Detect resources"

processors=$(expr $(nproc) - 2)
echo "   - ${processors} processors"                                                 # 10
echo "   - ${timeout} seconds"                                                       # 3600
echo "   - ${number_of_qemu_fuzz_target} qemu targets"
echo "   - ${number_of_vbox_fuzz_target} vbox targets"
echo "   - ${number_of_fuzz_target} in total"                                        # 108

echo "[+] Calculate average timeout for each fuzz target"
__batches=$(expr \( ${number_of_fuzz_target} + ${processors} - 1 \) / ${processors}) # 11
echo "   - ${__batches} batches"
__timeout=$(expr \( ${timeout} + ${__batches} - 1 \) / ${__batches})                 # 360
echo "   - ${__timeout} seconds"

gen_cmds=/tmp/videzzo_deploy_cmds.sh

function gen_qemu_cmds() {
    batch=${revision}
    dir=videzzo_qemu/out-san
    for fuzz_target in ${qemu_fuzz_target[@]}; do
        cmd="cd ${dir}; export ASAN_OPTIONS=detect_leaks=0; cpulimit -l 100 -- ./${fuzz_target} -fork=1 -ignore-crashes=1 -max_total_time=${__timeout} >${fuzz_target}-${batch}.log 2>&1; cd \$OLDPWD"
        echo ${cmd} >> ${gen_cmds}
    done
}

function gen_vbox_cmds() {
    batch=${revision}
    dir=videzzo_vbox/out-san
    for fuzz_target in ${vbox_fuzz_target[@]}; do
        cmd="cd ${dir}; export ASAN_OPTIONS=detect_leaks=0; cpulimit -l 100 -- ./${fuzz_target} -fork=1 -ignore-crashes=1 -max_total_time=${__timeout} >${fuzz_target}-${batch}.log 2>&1; cd \$OLDPWD"
        echo ${cmd} >> ${gen_cmds}
    done
}

echo "[+] Generate deploy commands"
rm -f ${gen_cmds}

if [ ${vmm} = "all" ]; then
    gen_qemu_cmds
    gen_vbox_cmds
elif [ ${vmm} = "qemu" ]; then
    gen_qemu_cmds
elif [ ${vmm} = "vbox" ]; then
    gen_vbox_cmds
fi

echo "[+] Will run ${gen_cmds}"
parallel -j${processors} --bar < ${gen_cmds}
