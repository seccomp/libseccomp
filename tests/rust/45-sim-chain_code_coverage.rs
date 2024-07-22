// SPDX-License-Identifier: LGPL-2.1-only
//
// Copyright 2024 Sony Group Corporation
//
// Seccomp Library test program
//

use anyhow::Result;
use libseccomp::*;
use utils::*;

fn main() -> Result<()> {
    let opts = util_getopt();

    let mut ctx = ScmpFilterContext::new(ScmpAction::KillThread)?;

    // the syscall and argument numbers are all fake to make the test simpler
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1008),
        &[scmp_cmp!($arg0 >= 1)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1008),
        &[scmp_cmp!($arg1 >= 2)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1008),
        &[scmp_cmp!($arg0 > 3)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1008),
        &[scmp_cmp!($arg2 & 0xf == 4)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1008),
        &[scmp_cmp!($arg2 & 0xff == 5)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1008),
        &[scmp_cmp!($arg2 & 0xff == 6)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1008),
        &[
            scmp_cmp!($arg0 == 7),
            scmp_cmp!($arg1 == 8),
            scmp_cmp!($arg2 == 9),
            scmp_cmp!($arg3 == 10),
            scmp_cmp!($arg4 == 11),
            scmp_cmp!($arg5 & 0xffff == 12),
        ],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1008),
        &[
            scmp_cmp!($arg0 == 7),
            scmp_cmp!($arg1 == 8),
            scmp_cmp!($arg2 == 9),
            scmp_cmp!($arg3 == 10),
            scmp_cmp!($arg4 == 11),
            scmp_cmp!($arg5 & 0xffff == 13),
        ],
    )?;

    util_filter_output(&opts, &ctx)
}
