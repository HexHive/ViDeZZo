#!/usr/bin/python3
"""
This script put the crashing seed and dependent seed together for videzzo-merge.
"""
import os
import sys
import uuid


usage="[-] Usage: {} CRASHING_SEED DEPENDENT_SEEDS_LIST".format(sys.argv[0])
if len(sys.argv) != 3:
    print(usage)
    exit(1)

# load files
crashing_seed = os.path.realpath(sys.argv[1])

dependent_seeds = []
dependent_seeds_list = sys.argv[2]
with open(dependent_seeds_list) as f:
    for line in f:
        dependent_seeds.append(os.path.realpath(line.strip()))

# generate videzzo-merge's cmd
print("{}/videzzo-merge -o {} {} {}".format(os.path.dirname(os.path.abspath(__file__)), uuid.uuid1(), ' '.join(dependent_seeds), crashing_seed))
