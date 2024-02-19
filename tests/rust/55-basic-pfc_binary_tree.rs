// SPDX-License-Identifier: LGPL-2.1-only
//
// Copyright 2024 Sony Group Corporation
//
// Seccomp Library test program
//

use anyhow::Result;
use libseccomp::*;
use utils::*;

const ARG_COUNT_MAX: usize = 2;

struct SyscallErrno {
    syscall: ScmpSyscall,
    error: i32,
    arg_cnt: i32,
    // To make the test more interesting, arguments are added to several
    // syscalls.  To keep the test simple, the arguments always use == operator
    args: [i32; ARG_COUNT_MAX],
}

const TABLE: &[SyscallErrno] = &[
    SyscallErrno::new(ScmpSyscall::new("read"), 0, 2, [100, 101]),
    SyscallErrno::new(ScmpSyscall::new("write"), 1, 1, [102, 0]),
    SyscallErrno::new(ScmpSyscall::new("open"), 2, 0, [0, 0]),
    SyscallErrno::new(ScmpSyscall::new("close"), 3, 2, [0, 0]),
    SyscallErrno::new(ScmpSyscall::new("stat"), 4, 0, [0, 0]),
    SyscallErrno::new(ScmpSyscall::new("fstat"), 5, 1, [103, 0]),
    SyscallErrno::new(ScmpSyscall::new("lstat"), 6, 0, [0, 0]),
    SyscallErrno::new(ScmpSyscall::new("poll"), 7, 1, [0, 0]),
    SyscallErrno::new(ScmpSyscall::new("lseek"), 8, 1, [104, 0]),
    SyscallErrno::new(ScmpSyscall::new("mmap"), 9, 0, [0, 0]),
    SyscallErrno::new(ScmpSyscall::new("mprotect"), 10, 1, [105, 0]),
    SyscallErrno::new(ScmpSyscall::new("munmap"), 11, 0, [0, 0]),
    SyscallErrno::new(ScmpSyscall::new("brk"), 12, 0, [0, 0]),
    SyscallErrno::new(ScmpSyscall::new("rt_sigaction"), 13, 0, [0, 0]),
    SyscallErrno::new(ScmpSyscall::new("rt_sigprocmask"), 14, 0, [0, 0]),
    SyscallErrno::new(ScmpSyscall::new("rt_sigreturn"), 15, 0, [0, 0]),
    SyscallErrno::new(ScmpSyscall::new("ioctl"), 16, 0, [0, 0]),
    SyscallErrno::new(ScmpSyscall::new("pread64"), 17, 1, [106, 0]),
    SyscallErrno::new(ScmpSyscall::new("pwrite64"), 18, 2, [107, 108]),
];

impl SyscallErrno {
    pub const fn new(
        syscall: ScmpSyscall,
        error: i32,
        arg_cnt: i32,
        args: [i32; ARG_COUNT_MAX],
    ) -> Self {
        Self {
            syscall,
            error,
            arg_cnt,
            args,
        }
    }
}

fn main() -> Result<()> {
    let opts = util_getopt();
    let mut ctx = ScmpFilterContext::new(ScmpAction::Allow)?;

    ctx.remove_arch(ScmpArch::Native)?;

    ctx.add_arch(ScmpArch::Aarch64)?;
    ctx.add_arch(ScmpArch::Ppc64Le)?;
    ctx.add_arch(ScmpArch::X8664)?;

    ctx.set_ctl_optimize(2)?;

    for tb in TABLE {
        match tb.arg_cnt {
            2 => ctx.add_rule_conditional(
                ScmpAction::Errno(tb.error),
                tb.syscall,
                &[
                    scmp_cmp!($arg0 == tb.args[0] as u64),
                    scmp_cmp!($arg1 == tb.args[1] as u64),
                ],
            )?,
            1 => ctx.add_rule_conditional(
                ScmpAction::Errno(tb.error),
                tb.syscall,
                &[scmp_cmp!($arg0 == tb.args[0] as u64)],
            )?,
            _ => ctx.add_rule(ScmpAction::Errno(tb.error), tb.syscall)?,
        };
    }

    util_filter_output(&opts, &ctx)
}
