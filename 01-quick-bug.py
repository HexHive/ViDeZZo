#!/usr/bin/python3
import os
import sys
import multiprocessing

def worker(out, target, index):
    os.system('cd {0}; cpulimit -l 100 -- ./{1} -max_total_time=60 >{1}-{2}.log 2>&1; cd $OLDPWD'.format(out, target, index))
    print('[+] {}-{}-{} starts!'.format(out, target, index))

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print('usage: python3 {} path/to/out-san index nproc'.format(sys.argv[0]))
        exit(1)

    out = sys.argv[1]
    index = sys.argv[2]
    nproc = int(sys.argv[3])

    targets = []
    for target in os.listdir(out):
        if target == 'pc-bios':
            continue
        elif target.endswith('.log'):
            continue
        elif target.startswith('vbox_vm_'):
            continue
        elif os.path.basename(target) in [
                "VBoxManage", "VBoxHeadless", "VBoxViDeZZo",
                "VBoxSVC", "VBoxXPCOMIPCD", "VBoxVMM.so",
                "VBoxRT.so", "VBoxXPCOM.so", "VBoxDDU.so",
                "VBoxDDR0.debug", "VBoxDDR0.r0", "VBoxDD2.so",
                "VBoxDD.so", "VMMR0.debug", "VMMR0.r0", "components"]:
            continue
        elif target.startswith('crash') \
                or target.startswith('slow') \
                or target.startswith('leak') \
                or target.startswith('oom') \
                or target.endswith('sh'):
            continue
        targets.append(target)

    with multiprocessing.Pool(processes=nproc) as pool:
        for target in targets:
            res = pool.apply_async(worker, (out, target, index))
        pool.close()
        pool.join()

    print('[-] done')
