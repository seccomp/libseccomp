#!/usr/bin/env python3

#
# Seccomp Library program to update the syscalls.csv file
#
# Copyright (c) 2025 Oracle and/or its affiliates.  All rights reserved.
# Author: Tom Hromatka <tom.hromatka@oracle.com>
#

#
# This library is free software; you can redistribute it and/or modify it
# under the terms of version 2.1 of the GNU Lesser General Public License as
# published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
# for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this library; if not, see <http://www.gnu.org/licenses>.
#

import subprocess
import datetime
import argparse
import sys
import os

arch_list = [
    'i386', 'x86_64', 'x32', 'arm', 'arm64', 'loongarch64', 'm68k',
    'mipso32', 'mips64', 'mips64n32', 'parisc', 'parisc64', 'powerpc',
    'powerpc64', 'riscv64', 's390', 's390x', 'sh'
]

ignore_syscall_list = [
    'arc_gettls', 'arc_settls', 'arc_usr_cmpxchg', 'bfin_spinlock',
    'cache_sync', 'clone2', 'cmpxchg_badaddr', 'dipc', 'dma_memcpy',
    'exec_with_loader', 'execv', 'file_getattr', 'file_setattr',
    'flush_cache', 'fp_udfiex_crtl', 'getdomainname', 'getdtablesize',
    'gethostname', 'getunwind', 'getxgid', 'getxpid', 'getxuid',
    'kern_features', 'llseek', 'madvise1', 'memory_ordering', 'metag_get_tls',
    'metag_set_fpu_flags', 'metag_set_tls', 'metag_setglobalbit',
    'mq_getsetaddr', 'old_adjtimex', 'old_getpagesize', 'oldumount',
    'or1k_atomic', 'osf_fstat', 'osf_fstatfs', 'osf_fstatfs64',
    'osf_getdirentries', 'osf_getdomainname', 'osf_getitimer',
    'osf_getrusage', 'osf_getsysinfo', 'osf_gettimeofday', 'osf_lstat',
    'osf_mount', 'osf_proplist_syscall', 'osf_select',
    'osf_set_program_attributes', 'osf_setitimer', 'osf_setsysinfo',
    'osf_settimeofday', 'osf_shmat', 'osf_sigprocmask', 'osf_sigstack',
    'osf_stat', 'osf_statfs', 'osf_statfs64', 'osf_swapon', 'osf_syscall',
    'osf_sysinfo', 'osf_usleep_thread', 'osf_utimes', 'osf_utsname',
    'osf_wait4', 'perfctr', 'perfmonctl', 'pread', 'pwrite',
    'sched_get_affinity', 'sched_set_affinity', 'sethae', 'setpgrp',
    'shmatcall', 'sram_alloc', 'sram_free', 'streams1', 'streams2',
    'sys_epoll_create', 'sys_epoll_ctl', 'sys_epoll_wait', 'tas', 'udftrap',
    'utrap_install'
]

def parse_args():
    parser = argparse.ArgumentParser('Script to update the syscalls.csv kernel versions',
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-d', '--datapath', required=True, type=str, default=None,
                        help="Path to the directory where arch-build-kver-tables.py "
                        'output the version tables')
    parser.add_argument('-k', '--kernelpath', required=True, type=str, default=None,
                        help="Path to the kernel source directory")
    parser.add_argument('-c', '--csv', required=False, type=str,
                        default='src/syscalls.csv',
                        help='Path to the the syscalls csv file')
    parser.add_argument('-V', '--versions', required=True, type=str, default=None,
                        help="Comma-separated list of kernel versions to update, e.g "
                        "6.17,6.18")
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show verbose warnings')
    parser.add_argument('-a', '--add', action='store_true',
                        help='Add newly discovered syscalls to the csv')

    args = parser.parse_args()
    args.versions = args.versions.split(',')

    return args

def run(command, verbose=False, shell=False, timeout=None):
    if shell:
        if isinstance(command, str):
            # nothing to do.  command is already formatted as a string
            pass
        elif isinstance(command, list):
            command = ' '.join(command)
        else:
            raise ValueError('Unsupported command type')

    subproc = subprocess.Popen(command, shell=shell,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)

    if timeout:
        try:
            out, err = subproc.communicate(timeout=timeout)
            ret = subproc.returncode

            out = out.strip().decode('UTF-8')
            err = err.strip().decode('UTF-8')
        except TimeoutExpired as timeout:
            if timeout.stdout:
                out = timeout.stdout.strip().decode('UTF-8')
            else:
                out = ''
            if timeout.stderr:
                    err = timeout.stderr.strip().decode('UTF-8')
            else:
                err = ''

            if len(err):
                ret = -1
            else:
                ret = 0
    else:
        out, err = subproc.communicate()
        ret = subproc.returncode

        out = out.strip().decode('UTF-8')
        err = err.strip().decode('UTF-8')

    if verbose:
        if not shell:
            command = ' '.join(command)
        print('run:\n\tcmd = {}\n\tret = {}\n\tstdout = {}\n\tstderr = {}\n'.format(
              command, ret, out, err))

    return ret, out, err

def get_kernel_ver(args):
    makefile = os.path.join(args.kernelpath, 'Makefile')

    with open(makefile, 'r') as mkf:
        for line in mkf:

            if line.startswith('VERSION'):
                maj = int(line.split('=')[1].strip())
            elif line.startswith('PATCHLEVEL'):
                mnr = int(line.split('=')[1].strip())
            elif line.startswith('SUBLEVEL'):
                sub = int(line.split('=')[1].strip())
            elif line.startswith('EXTRAVERSION'):
                xtr = line.split('=')[1].strip()

    return maj, mnr, sub, xtr

def build_header(args, columns):
    maj, mnr, sub, xtr = get_kernel_ver(args)
    date = datetime.datetime.now().strftime("%Y-%m-%d")
    header = '#syscall (v{}.{}.{}{} {})'.format(maj, mnr, sub, xtr, date)

    for col in columns:
        header = header + ',{}'.format(col)

    return header

def parse_syscalls_csv(args):
    column_order = list()
    syscalls = dict()

    with open(args.csv, 'r') as csvf:
        for line_idx, line in enumerate(csvf):
            if line_idx == 0:
                for col_idx, col_name in enumerate(line.split(',')):
                    if col_idx == 0:
                        continue
                    else:
                        column_order.append(col_name.strip())
            else:
                for col_idx, col_value in enumerate(line.split(',')):
                    if col_idx == 0:
                        syscall_name = col_value
                        syscalls[syscall_name] = list()
                    else:
                        syscalls[syscall_name].append(col_value.strip())

    return column_order, syscalls

def insert_new_syscall(syscalls, syscall_name, column_cnt):
    inserted = False

    for syscall in syscalls:
        if syscall_name < syscall:
            idx = list(syscalls.keys()).index(syscall)
            syscalls_list = list(syscalls.items())
            syscalls_list.insert(idx, (syscall_name, ['PNR'] * column_cnt))
            syscalls = dict(syscalls_list)
            inserted = True
            break

    if not inserted:
        syscalls[syscall_name] = ['PNR'] * column_cnt

    return syscalls

def update_syscalls_dict(args, columns, syscalls, kver):
    for col_idx, column in enumerate(columns):
        if 'kver' in column:
            # Only operate on the columns with syscall numbers.  The
            # kernel version columns always immediately follow the syscall
            # number columns
            continue

        if column == 'x86':
            arch = 'i386'
        elif column == 'aarch64':
            arch = 'arm64'
        elif column == 'mips':
            arch = 'mipso32'
        elif column == 'ppc':
            arch = 'powerpc'
        elif column == 'ppc64':
            arch = 'powerpc64'
        else:
            arch = column

        table_path = os.path.join(args.datapath, 'tables-{}'.format(kver),
                                  'syscalls-{}'.format(arch))

        with open(table_path, 'r') as tblf:
            for line in tblf:
                if line.startswith('HPUX_'):
                    continue

                if len(line.split()) == 1:
                    syscall_name = line.strip()
                    if syscall_name.startswith('HPUX'):
                        continue
                    if syscall_name in ignore_syscall_list:
                        continue

                    if syscall_name not in syscalls:
                        if args.verbose:
                            print('syscall {} is not in csv'.format(
                                  syscall_name))

                    if args.verbose:
                        print('syscall {} is undefined in {} for kernel v{}'.
                              format(line.strip(), column, kver))

                    if syscall_name in syscalls and \
                       not syscalls[syscall_name][col_idx] == 'PNR':
                        # This syscall had a syscall number in an earlier
                        # table, but this table doesn't have one.  Don't
                        # remove the previous number
                        continue

                    if args.add:
                        if not syscall_name in syscalls:
                            # This is a new syscall for this kernel version
                            syscalls = insert_new_syscall(syscalls,
                                           syscall_name, len(columns))

                        syscalls[syscall_name][col_idx] = 'PNR'
                        syscalls[syscall_name][col_idx + 1] = 'SCMP_KV_UNDEF'
                else:
                    syscall_name = line.split()[0].strip()
                    syscall_num = int(line.split()[1].strip())

                    if arch == 'mipso32':
                        syscall_num -= 4000
                    elif arch == 'mips64':
                        syscall_num -= 5000
                    elif arch == 'mips64n32':
                        syscall_num -= 6000
                    elif arch == 'x32' and syscall_num >= 0x40000000:
                        syscall_num = syscall_num - 0x40000000

                    if syscall_name in ignore_syscall_list:
                        continue

                    if syscall_name not in syscalls:
                        if args.verbose:
                            print('syscall {} is not in csv'.format(
                                  syscall_name))

                        if args.add:
                            syscalls = insert_new_syscall(syscalls,
                                           syscall_name, len(columns))
                        else:
                            continue

                    if syscalls[syscall_name][col_idx] == 'PNR':
                        if args.verbose:
                            print('adding syscall {} to {} in kernel v{}'.
                                  format(syscall_name, column, kver))

                        syscalls[syscall_name][col_idx] = str(syscall_num)
                        maj = kver.split('.')[0]
                        mnr = kver.split('.')[1]
                        syscalls[syscall_name][col_idx + 1] = \
                            'SCMP_KV_{}_{}'.format(maj, mnr)

    return syscalls

def write_csv(args, columns, syscalls):
    with open(args.csv, 'w') as csvf:
        csvf.write(build_header(args, columns))
        csvf.write('\n')

        for syscall in syscalls:
            csvf.write('{},'.format(syscall))
            csvf.write(','.join(syscalls[syscall]))
            csvf.write('\n')

def main(args):
    for kver in args.versions:
        print('Updating {} version table for kernel {}'.format(args.csv, kver))

        checkout_cmd = 'cd {};git checkout v{}'.format(args.kernelpath, kver)
        ret, out, err = run(checkout_cmd, shell=True)
        if ret != 0:
            raise KeyError('Failed to checkout v{}: {}'.format(kver, ret))

        columns, syscalls = parse_syscalls_csv(args)
        syscalls = update_syscalls_dict(args, columns, syscalls, kver)
        write_csv(args, columns, syscalls)

if __name__ == '__main__':
    if sys.version_info < (3, 7):
        # Guaranteed dictionary ordering was added in python 3.7
        print("This script requires Python 3.7 or higher.")
        sys.exit(1)

    args = parse_args()
    main(args)
