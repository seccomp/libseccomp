#!/usr/bin/env python

#
# Seccomp Library program to determine the largest syscall number
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

DEFAULT_CSV='syscalls.csv'

def parse_args():
    parser = argparse.ArgumentParser('Script to get the max syscall number for an architecture',
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-a', '--arch', required=True, type=str, default=None,
                        help='Architecture')
    parser.add_argument('-c', '--csv', required=False, type=str,
                        default=DEFAULT_CSV, help='syscalls.csv path')

    args = parser.parse_args()

    return args

def get_max_syscall_num(arch, csv):
    max_syscall_num = 0
    col = None

    with open(csv) as csvf:
        for line_num, line in enumerate(csvf):
            if line_num == 0:
                fields = line.split(',')

                for field_num, field in enumerate(fields):
                    if field == arch:
                        col = field_num
                        break

            else:
                syscall_str = line.split(',')[col]

                syscall_num = 0
                try:
                    syscall_num = int(syscall_str)
                except ValueError:
                    continue

                if syscall_num > 983000:
                    # skip arm syscalls with a really large base number
                    continue

                if syscall_num > max_syscall_num:
                    max_syscall_num = syscall_num

    return max_syscall_num

def main(args):
    num = get_max_syscall_num(args.arch, args.csv)

    print(num)

if __name__ == '__main__':
    args = parse_args()
    main(args)
