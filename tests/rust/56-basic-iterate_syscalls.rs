// SPDX-License-Identifier: LGPL-2.1-only
//
// Copyright 2024 Sony Group Corporation
//
// Seccomp Library test program
//

use anyhow::Result;
use libseccomp::error::SeccompError;
use libseccomp::*;
use std::process::exit;

const ARCH_LIST: [ScmpArch; 20] = [
    ScmpArch::Native,
    ScmpArch::X86,
    ScmpArch::X8664,
    ScmpArch::X32,
    ScmpArch::Arm,
    ScmpArch::Aarch64,
    ScmpArch::Mips,
    ScmpArch::Mips64,
    ScmpArch::Mips64N32,
    ScmpArch::Mipsel,
    ScmpArch::Mipsel64,
    ScmpArch::Mipsel64N32,
    ScmpArch::Ppc,
    ScmpArch::Ppc64,
    ScmpArch::Ppc64Le,
    ScmpArch::S390,
    ScmpArch::S390X,
    ScmpArch::Parisc,
    ScmpArch::Parisc64,
    ScmpArch::Riscv64,
];

fn test_arch(arch: ScmpArch, init: i32) -> i32 {
    for iter in init..(init + 1000) {
        let name: Result<String, SeccompError> = ScmpSyscall::from(iter).get_name_by_arch(arch);
        if name.is_err() {
            continue;
        }

        let n: ScmpSyscall = ScmpSyscall::from_name_by_arch(&name.unwrap(), arch).unwrap();
        if n != iter {
            return 1;
        }
    }

    0
}

fn main() -> Result<()> {
    for arch in ARCH_LIST {
        let init: i32 = match arch {
            ScmpArch::X32 => 0x40000000,
            ScmpArch::Mips => 4000,
            ScmpArch::Mips64 => 5000,
            ScmpArch::Mips64N32 => 6000,
            _ => 0,
        };
        if test_arch(arch, init) < 0 {
            exit(1)
        };
    }

    exit(0)
}
