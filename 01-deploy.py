#!/bin/bash
import os
import sys

out = sys.argv[1]
targets = []
for target in os.listdir(out):
    if target == 'pc-bios':
        continue
    elif target.endswith('.log'):
        continue
    targets.append(target)
    print('{} found ...'.format(target))

cmds = []
for target in targets:
    cmd = 'bash -x 02-run.sh {0} {1}'.format(out, target)
    cmds.append(cmd)

for i in range(0, len(cmds) // 3 + 1):
    for j in range(0, 3):
        os.system(cmds[i + j])

print('done')
