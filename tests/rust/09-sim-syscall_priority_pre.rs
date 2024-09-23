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

    // The syscall and argument numbers are all fake to make the test
    // simpler.
    ctx.set_syscall_priority(1000, 3)?;
    ctx.set_syscall_priority(1001, 2)?;
    ctx.set_syscall_priority(1002, 1)?;

    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1000),
        &[scmp_cmp!($arg0 == 0), scmp_cmp!($arg1 == 1)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1001),
        &[scmp_cmp!($arg0 == 0)],
    )?;
    ctx.add_rule_exact(ScmpAction::Allow, ScmpSyscall::from(1002))?;

    util_filter_output(&opts, &ctx)
}
