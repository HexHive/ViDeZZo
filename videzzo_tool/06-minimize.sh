#!/bin/bash

function usage() {
  cat << HEREDOC
Usage: $0 -t TARGET_PATH -c CRASH_PATH

positional arguments:
  -t, TARGET_PATH  absolute pathname of the fuzz target
  -a, ARG_LIST     argument list for the fuzz target, e.g., "-L pathname/to/pc-bios"
  -c, CRASH_PATH   absolute pathname of the crashing test case

optional arguments:
  -h, --help               show this help message and exit

HEREDOC
  exit 1
}

while getopts ":t:a:c:s:" o; do
  case "${o}" in
    t)
      target=${OPTARG}
      ;;
    a)
      arglist=${OPTARG}
      ;;
    c)
      crash=${OPTARG}
      ;;
    *)
      usage
      ;;
  esac
done

if [[ -z $target ]]; then
    echo "[-] -t is missing"
    exit 1
fi

if [[ -z $crash ]]; then
    echo "[-] -c is missing"
    exit 1
fi

arglist="$arglist -max_len=10000000"

echo "[-] target = $target"
echo "[-] crash  = $crash"

# step 1: create a private directory
ws=$(mktemp -d)
echo [-] working in $ws

poc_gen=$(realpath $(dirname $0)/videzzo-poc-gen)

# step 2: create a tester script
echo "#!/bin/bash" > $ws/picire_tester.sh
echo "export ASAN_OPTIONS=detect_leaks=0" >> $ws/picire_tester.sh
echo "export DEFAULT_INPUT_MAXSIZE=10000000" >> $ws/picire_tester.sh
echo "$poc_gen -i text -o binary -O $ws/poc-bin \$1" >> $ws/picire_tester.sh
echo "$target $ws/poc-bin $arglist 2>&1 | grep -q -e \"ERROR\";" >> $ws/picire_tester.sh
chmod +x $ws/picire_tester.sh
echo [-] created $ws/picire_tester.sh
echo "#!/bin/bash" > $ws/picire_reproduce.sh
echo "export ASAN_OPTIONS=detect_leaks=0" >> $ws/picire_reproduce.sh
echo "export DEFAULT_INPUT_MAXSIZE=10000000" >> $ws/picire_reproduce.sh
echo "$poc_gen -i text -o binary -O $ws/poc-bin \$1" >> $ws/picire_reproduce.sh
echo "$target $ws/poc-bin $arglist" >> $ws/picire_reproduce.sh
chmod +x $ws/picire_reproduce.sh
echo [-] created $ws/picire_reproduce.sh
echo "#!/bin/bash" > $ws/picire_latest.sh
echo "export ASAN_OPTIONS=detect_leaks=0" >> $ws/picire_latest.sh
echo "export DEFAULT_INPUT_MAXSIZE=10000000" >> $ws/picire_latest.sh
echo "$poc_gen -i text -o binary -O $ws/poc-bin \$1" >> $ws/picire_latest.sh
echo "$target $ws/poc-bin $arglist" >> $ws/picire_latest.sh
chmod +x $ws/picire_latest.sh
echo [-] created $ws/picire_latest.sh

# step 3: create an input
DEFAULT_INPUT_MAXSIZE=10000000 $poc_gen -i binary -o text -O $ws/picire_inputs $crash
echo [-] created $ws/picire_inputs

# step 4: let's start dd
echo [-] starting delta debugging!
time picire --input=$ws/picire_inputs --test=$ws/picire_tester.sh \
	--parallel --subset-iterator=skip --complement-iterator=backward

echo [-] save output to $ws/picire_inputs.*/picire_inputs
echo [-] run $ws/picire_reproduce.sh $ws/picire_inputs.*/picire_inputs
echo [-] modify and run $ws/picire_latest.sh $ws/picire_inputs.*/picire_inputs
