// SPDX-License-Identifier: LGPL-2.1-only
//
// Copyright 2024 Sony Group Corporation
//
// Seccomp Library test program
//

use anyhow::Result;
use libseccomp::*;

const ARCH_LIST: [ScmpArch; 23] = [
    ScmpArch::Native,
    ScmpArch::X86,
    ScmpArch::X8664,
    ScmpArch::X32,
    ScmpArch::Arm,
    ScmpArch::Aarch64,
    ScmpArch::Loongarch64,
    ScmpArch::M68k,
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
    ScmpArch::Sh,
];

fn main() -> Result<()> {
    assert_eq!(ScmpSyscall::from_name("open")?, ScmpSyscall::new("open"));
    assert_eq!(ScmpSyscall::from_name("read")?, ScmpSyscall::new("read"));
    assert!(ScmpSyscall::from_name("INVALID").is_err());
    assert_eq!(
        ScmpSyscall::from_name_by_arch_rewrite("openat", ScmpArch::Native)?,
        ScmpSyscall::new("openat")
    );

    for arch in ARCH_LIST {
        assert!(ScmpSyscall::from_name("INVALID").is_err());
        assert!(ScmpSyscall::from(-1).get_name_by_arch(arch).is_err());

        let nr_open = ScmpSyscall::from_name_by_arch("open", arch)?;
        let nr_read = ScmpSyscall::from_name_by_arch("read", arch)?;
        let nr_socket = ScmpSyscall::from_name_by_arch_rewrite("socket", arch)?;
        let nr_shmctl = ScmpSyscall::from_name_by_arch_rewrite("shmctl", arch)?;

        let mut name = nr_open.get_name_by_arch(arch)?;
        assert_eq!(name, "open");
        name = nr_read.get_name_by_arch(arch)?;
        assert_eq!(name, "read");
        name = nr_socket.get_name_by_arch(arch)?;
        assert!(name == "socket" || name == "socketcall");
        name = nr_shmctl.get_name_by_arch(arch)?;
        assert!(name == "shmctl" || name == "ipc");

        // socket pseudo-syscalls
        if ScmpSyscall::from_name_by_arch("socketcall", arch)? > 0.into() {
            for sys in -120..-100 {
                ScmpSyscall::from(sys).get_name_by_arch(arch)?;
            }
        }

        // ipc pseudo-syscalls
        if ScmpSyscall::from_name_by_arch("ipc", arch)? > 0.into() {
            for sys in -204..-200 {
                ScmpSyscall::from(sys).get_name_by_arch(arch)?;
            }
            for sys in -214..-210 {
                ScmpSyscall::from(sys).get_name_by_arch(arch)?;
            }
            for sys in -224..-220 {
                ScmpSyscall::from(sys).get_name_by_arch(arch)?;
            }
        }
    }
    Ok(())
}
