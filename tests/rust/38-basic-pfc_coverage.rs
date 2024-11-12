// SPDX-License-Identifier: LGPL-2.1-only
//
// Copyright 2024 Sony Group Corporation
//
// Seccomp Library test program
//

use anyhow::Result;
use libseccomp::*;
use std::io::stdout;
use utils::*;

fn main() -> Result<()> {
    let opts = util_getopt();
    set_api(3)?;
    let mut ctx = ScmpFilterContext::new(ScmpAction::Allow)?;

    ctx.remove_arch(ScmpArch::Native)?;

    ctx.add_arch(ScmpArch::X8664)?;
    ctx.add_arch(ScmpArch::X86)?;
    ctx.add_arch(ScmpArch::X32)?;
    ctx.add_arch(ScmpArch::Arm)?;
    ctx.add_arch(ScmpArch::Aarch64)?;
    ctx.add_arch(ScmpArch::Mipsel)?;
    ctx.add_arch(ScmpArch::Mipsel64)?;
    ctx.add_arch(ScmpArch::Mipsel64N32)?;
    ctx.add_arch(ScmpArch::Ppc64Le)?;
    ctx.add_arch(ScmpArch::Riscv64)?;

    // NOTE: the syscalls and their arguments have been picked to achieve
    //       the highest possible code coverage, this is not a useful
    //       real world filter configuration
    ctx.add_rule(ScmpAction::KillThread, ScmpSyscall::from_name("open")?)?;
    ctx.add_rule_conditional(
        ScmpAction::KillThread,
        ScmpSyscall::from_name("read")?,
        &[
            scmp_cmp!($arg0 == 0),
            scmp_cmp!($arg1 >= 1),
            scmp_cmp!($arg2 > 2),
            scmp_cmp!($arg3 & 0x0f == 3),
        ],
    )?;
    ctx.add_rule_conditional(
        ScmpAction::Trap,
        ScmpSyscall::from_name("write")?,
        &[
            scmp_cmp!($arg0 != 0),
            scmp_cmp!($arg1 <= 1),
            scmp_cmp!($arg2 < 2),
        ],
    )?;
    ctx.add_rule(ScmpAction::Errno(1), ScmpSyscall::from_name("close")?)?;
    ctx.add_rule(ScmpAction::Trace(1), ScmpSyscall::from_name("exit")?)?;
    ctx.add_rule(ScmpAction::KillThread, ScmpSyscall::from_name("fstat")?)?;
    ctx.add_rule(ScmpAction::Log, ScmpSyscall::from_name("exit_group")?)?;

    // verify the prioritized, but no-rule, syscall
    ctx.set_syscall_priority(ScmpSyscall::from_name("poll")?, 255)?;

    ctx.export_pfc(stdout())?;

    util_filter_output(&opts, &ctx)
}
