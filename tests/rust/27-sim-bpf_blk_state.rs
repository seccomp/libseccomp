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
    let mut ctx = ScmpFilterContext::new(ScmpAction::Allow)?;

    ctx.add_rule_conditional_exact(
        ScmpAction::KillThread,
        ScmpSyscall::from(1000),
        &[scmp_cmp!($arg0 == 3)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::KillThread,
        ScmpSyscall::from(1000),
        &[scmp_cmp!($arg0 == 4)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::KillThread,
        ScmpSyscall::from(1000),
        &[scmp_cmp!($arg0 == 5)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::KillThread,
        ScmpSyscall::from(1000),
        &[scmp_cmp!($arg0 == 6)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::KillThread,
        ScmpSyscall::from(1000),
        &[scmp_cmp!($arg0 == 7)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::KillThread,
        ScmpSyscall::from(1000),
        &[scmp_cmp!($arg0 == 8)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::KillThread,
        ScmpSyscall::from(1000),
        &[scmp_cmp!($arg0 == 9)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::KillThread,
        ScmpSyscall::from(1000),
        &[scmp_cmp!($arg0 == 11)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::KillThread,
        ScmpSyscall::from(1000),
        &[scmp_cmp!($arg0 == 12)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::KillThread,
        ScmpSyscall::from(1000),
        &[scmp_cmp!($arg0 == 13)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::KillThread,
        ScmpSyscall::from(1000),
        &[scmp_cmp!($arg0 == 14)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::KillThread,
        ScmpSyscall::from(1000),
        &[scmp_cmp!($arg0 == 15)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::KillThread,
        ScmpSyscall::from(1000),
        &[scmp_cmp!($arg0 >= 16)],
    )?;

    util_filter_output(&opts, &ctx)
}
