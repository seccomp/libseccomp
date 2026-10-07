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

# See doc/admin/SYSCALL_KVER_TABLES.md for the requirements and usage.

from subprocess import TimeoutExpired
import subprocess
import argparse
import shutil
import os
import re

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
                   '6.13', '6.14', '6.15', '6.16', '6.17', '6.18',
                   '6.19', '7.0', '7.1', '7.2']

# kernel architecture directories used by libseccomp
kernel_arches = ['arm', 'arm64', 'loongarch', 'm68k', 'mips', 'parisc',
                 'powerpc', 'riscv', 's390', 'sh', 'x86']

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

        # NOTE: this relies on the update-tables.sh fixes from syscalls-table
        #       commits c58bc160537f, e5b5b182d2c9 and b019db68a150

        # update-tables.sh keeps the old table if it fails to generate a
        # new one
        failed = re.findall(r'Failed to compile list-syscalls for (\S+)', out)
        if failed:
            raise RuntimeError('Failed to build the {} tables for kernel '
                               'v{}'.format(', '.join(failed), kver))

        # update-tables.sh skips the architectures whose headers can not be
        # installed.  This is fine for the architectures not used by
        # libseccomp (e.g. the cris headers can not be installed in Linux
        # v3.x).
        failed = re.findall(r'Failed to install headers for (\S+)', out)
        if [arch for arch in failed if arch in kernel_arches]:
            raise RuntimeError('Failed to install the {} headers for kernel '
                               'v{}'.format(', '.join(failed), kver))
        if ret != 0 and not failed:
            raise RuntimeError('Failed to update tables: {}'.format(ret))

        # update-tables.sh only regenerates the tables for the architectures
        # present in this kernel version.  The other tables in data/tables
        # are leftovers (e.g. from a newer kernel version), so only copy the
        # tables that were generated for this kernel.
        arch_path = os.path.join(args.datapath,
                                 'data/architectures-present-in-kernel.text')
        with open(arch_path, 'r') as archf:
            arches = [arch.strip() for arch in archf if arch.strip()]

        src_path = os.path.join(args.datapath, 'data/tables')
        dest_path = os.path.join(os.getcwd(), 'tables-{}'.format(kver))
        shutil.rmtree(dest_path, ignore_errors=True)
        os.makedirs(dest_path)
        for arch in arches:
            shutil.copy(os.path.join(src_path, 'syscalls-{}'.format(arch)),
                        dest_path)

if __name__ == '__main__':
    args = parse_args()
    main(args)
