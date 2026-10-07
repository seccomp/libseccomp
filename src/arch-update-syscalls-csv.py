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

import argparse
import os

def parse_args():
    parser = argparse.ArgumentParser('Script to update the syscalls.csv kernel versions',
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-d', '--datapath', required=True, type=str, default=None,
                        help="Path to the directory where arch-build-kver-tables.py "
                        'output the version tables')
    parser.add_argument('-c', '--csv', required=False, type=str,
                        default='src/syscalls.csv',
                        help='Path to the the syscalls csv file')
    parser.add_argument('-V', '--versions', required=True, type=str, default=None,
                        help="Comma-separated list of kernel versions to update, e.g "
                        "6.17,6.18")
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show verbose warnings')

    args = parser.parse_args()
    # the first kernel version a syscall is found in is used, so the
    # versions must be processed in ascending order
    args.versions = sorted(args.versions.split(','),
                           key=lambda v: tuple(int(i) for i in v.split('.')))

    return args

def table_arch(column):
    if column == 'x86':
        return 'i386'
    elif column == 'aarch64':
        return 'arm64'
    elif column == 'mips':
        return 'mipso32'
    elif column == 'ppc':
        return 'powerpc'
    elif column == 'ppc64':
        return 'powerpc64'
    return column

def parse_syscalls_csv(args):
    with open(args.csv, 'r') as csvf:
        lines = csvf.read().splitlines()

    header = lines[0]
    columns = header.split(',')
    syscalls = dict()
    for line in lines[1:]:
        fields = line.split(',')
        syscalls[fields[0]] = fields

    return header, columns, syscalls

def update_syscalls_dict(args, columns, syscalls, kver):
    kver_name = 'SCMP_KV_{}_{}'.format(*kver.split('.'))
    kver_path = os.path.join(args.datapath, 'tables-{}'.format(kver))
    if not os.path.isdir(kver_path):
        raise RuntimeError('No tables for kernel v{} in {}'.format(
                           kver, args.datapath))

    for col_idx, column in enumerate(columns):
        if col_idx == 0 or column.endswith('_kver'):
            # Only operate on the columns with syscall numbers.  The
            # kernel version columns always immediately follow the syscall
            # number columns
            continue

        table_path = os.path.join(kver_path,
                                  'syscalls-{}'.format(table_arch(column)))
        if not os.path.exists(table_path):
            # This architecture is not present in this kernel version
            continue

        with open(table_path, 'r') as tblf:
            for line in tblf:
                fields = line.split()
                if len(fields) != 2 or fields[0] not in syscalls:
                    # Not a syscall with a number, or not one in the csv
                    continue

                syscall = syscalls[fields[0]]
                if syscall[col_idx] == 'PNR' or \
                   syscall[col_idx + 1] != 'SCMP_KV_UNDEF':
                    # The syscall numbers are maintained by
                    # arch-syscall-validate, so do not add any, and keep
                    # the kernel versions which are already set
                    continue

                if args.verbose:
                    print('setting {} kernel version in {} to v{}'.format(
                          fields[0], column, kver))
                syscall[col_idx + 1] = kver_name

def print_undef(columns, syscalls):
    for col_idx, column in enumerate(columns):
        if col_idx == 0 or column.endswith('_kver'):
            continue

        undef = [s for s in syscalls if syscalls[s][col_idx] != 'PNR' and
                 syscalls[s][col_idx + 1] == 'SCMP_KV_UNDEF']
        if undef:
            print('{}: no kernel version for {} syscalls'.format(column,
                  len(undef)))

def write_csv(args, header, syscalls):
    with open(args.csv, 'w') as csvf:
        csvf.write(header)
        csvf.write('\n')

        for syscall in syscalls:
            csvf.write(','.join(syscalls[syscall]))
            csvf.write('\n')

def main(args):
    header, columns, syscalls = parse_syscalls_csv(args)

    for kver in args.versions:
        print('Updating {} kernel versions for kernel {}'.format(args.csv,
              kver))
        update_syscalls_dict(args, columns, syscalls, kver)

    write_csv(args, header, syscalls)
    print_undef(columns, syscalls)

if __name__ == '__main__':
    args = parse_args()
    main(args)
