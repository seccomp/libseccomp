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
    let args: [(ScmpAction, i32, ScmpArgCompare); 3] = [
        (ScmpAction::Allow, 2000, scmp_cmp!($arg0 == u64::MAX)),
        (
            ScmpAction::Allow,
            2032,
            scmp_cmp!($arg0 == u64::from(u32::MAX)),
        ),
        (ScmpAction::Allow, 2064, scmp_cmp!($arg0 == u64::MAX)),
    ];
    let opts = util_getopt();
    let mut ctx = ScmpFilterContext::new(ScmpAction::KillThread)?;

    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1000),
        &[scmp_cmp!($arg0 == u64::MAX)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1064),
        &[scmp_cmp!($arg0 == u64::MAX)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1032),
        &[scmp_cmp!($arg0 == u64::from(u32::MAX))],
    )?;

    for (action, syscall, cmp) in args {
        ctx.add_rule_conditional_exact(action, syscall, &[cmp])?;
    }

    util_filter_output(&opts, &ctx)
}
