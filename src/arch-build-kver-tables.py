#!/usr/bin/env python3
#
# Seccomp Library program to build the kernel version tables
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

#######################################################
#### WARNING - to generate proper headers for x32, you
####           must install the glibc 32-bit headers
####
####           apt install libc6-dev-x32
####
#######################################################

from subprocess import TimeoutExpired
import subprocess
import argparse
import os

kernel_versions = ['3.0', '3.1', '3.2', '3.3', '3.4', '3.5', '3.6', '3.7',
                   '3.8', '3.9', '3.10', '3.11', '3.12', '3.13', '3.14',
                   '3.15', '3.16', '3.17', '3.18', '3.19', '4.0', '4.1',
                   '4.2', '4.3', '4.4', '4.5', '4.6', '4.7', '4.8', '4.9',
                   '4.10', '4.11', '4.12', '4.13', '4.14', '4.15', '4.16',
                   '4.17', '4.18', '4.19', '4.20', '5.0', '5.1', '5.2',
                   '5.3', '5.4', '5.5', '5.6', '5.7', '5.8', '5.9', '5.10',
                   '5.11', '5.12', '5.13', '5.14', '5.15', '5.16', '5.17',
                   '5.18', '5.19', '6.0', '6.1', '6.2', '6.3', '6.4', '6.5',
                   '6.6', '6.7', '6.8', '6.9', '6.10', '6.11', '6.12',
                   '6.13', '6.14', '6.15', '6.16']

def parse_args():
    parser = argparse.ArgumentParser('Script to populate the syscalls.csv kernel versions',
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-d', '--datapath', required=True, type=str, default=None,
                        help="Path to the local copy of @hrw's syscalls-table tool")
    parser.add_argument('-k', '--kernelpath', required=True, type=str, default=None,
                        help="Path to the kernel source directory")
    parser.add_argument('-V', '--versions', required=False, type=str, default=None,
                        help="Comma-separated list of kernel versions to build, e.g "
                        "3.0,6.1,6.10.  If not specified all known kernel version "
                        "tables are built")
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show verbose warnings')

    args = parser.parse_args()

    if not args.versions:
        args.versions = kernel_versions
    else:
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

def main(args):
    for kver in args.versions:
        print('Building version table for kernel {}'.format(kver))

        checkout_cmd = 'cd {};git checkout v{}'.format(args.kernelpath, kver)
        ret, out, err = run(checkout_cmd, shell=True)
        if ret != 0:
            raise KeyError('Failed to checkout v{}: {}'.format(kver, ret))

        update_cmd = 'cd {};bash scripts/update-tables.sh {}'.format(
                     args.datapath, args.kernelpath)
        ret, out, err = run(update_cmd, shell=True)
        if ret != 0:
            raise RuntimeError('Failed to update tables: {}'.format(ret))

        src_path = os.path.join(args.datapath, 'data/tables')
        dest_path = os.path.join(os.getcwd(), 'tables-{}'.format(kver))
        cp_cmd = 'cp -r {} {}'.format(src_path, dest_path)
        ret, out, err = run(cp_cmd, shell=True)
        if ret != 0:
            raise RuntimeError('Table copy failed: {}'.format(ret))

if __name__ == '__main__':
    args = parse_args()
    main(args)
