#!/bin/bash
import os
import sys
import multiprocessing

def worker(out, target, index):
    os.system('mkdir -p /media/hdd0/qiliu/videzzo-corpus/{}-{}'.format(target, index))
    os.system('cd {0}; cpulimit -l 100 -- ./{1} -max_total_time=86400 /media/hdd0/qiliu/videzzo-corpus/{1}-{2} >{1}-{2}.log 2>&1; cd $OLDPWD'.format(out, target, index))

if __name__ == '__main__':
    out = sys.argv[1]
    index = sys.argv[2]
    targets = []
    for target in os.listdir(out):
        if target == 'pc-bios':
            continue
        elif target.endswith('.log'):
            continue
        elif target.startswith('crash') or target.startswith('slow') or target.startswith('leak') or target.startswith('oom') or target.endswith('sh'):
            continue
        targets.append(target)

    with multiprocessing.Pool(processes=30) as Pool:
        for target in targets:
            res = Pool.apply_async(worker, (out, target, index))
            print(res.get())

    print('done')
