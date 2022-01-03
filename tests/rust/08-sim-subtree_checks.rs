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
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1000),
        &[scmp_cmp!($arg0 == 0), scmp_cmp!($arg1 == 1)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1000),
        &[scmp_cmp!($arg1 == 1)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1001),
        &[scmp_cmp!($arg1 == 1)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1001),
        &[scmp_cmp!($arg0 == 0), scmp_cmp!($arg1 == 1)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1002),
        &[
            scmp_cmp!($arg0 == 0),
            scmp_cmp!($arg1 == 1),
            scmp_cmp!($arg2 == 2),
            scmp_cmp!($arg3 == 3),
        ],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1002),
        &[scmp_cmp!($arg1 == 1), scmp_cmp!($arg2 == 2)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1003),
        &[scmp_cmp!($arg1 == 1), scmp_cmp!($arg2 == 2)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1003),
        &[
            scmp_cmp!($arg0 == 0),
            scmp_cmp!($arg1 == 1),
            scmp_cmp!($arg2 == 2),
            scmp_cmp!($arg3 == 3),
        ],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1004),
        &[
            scmp_cmp!($arg0 == 0),
            scmp_cmp!($arg1 == 1),
            scmp_cmp!($arg2 == 2),
            scmp_cmp!($arg3 == 3),
        ],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1004),
        &[scmp_cmp!($arg0 == 0), scmp_cmp!($arg1 == 11)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1004),
        &[
            scmp_cmp!($arg0 == 0),
            scmp_cmp!($arg1 == 1),
            scmp_cmp!($arg2 == 2),
            scmp_cmp!($arg3 == 33),
        ],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1004),
        &[scmp_cmp!($arg1 == 1), scmp_cmp!($arg2 == 2)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1005),
        &[scmp_cmp!($arg1 == 1), scmp_cmp!($arg2 == 2)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1005),
        &[
            scmp_cmp!($arg0 == 0),
            scmp_cmp!($arg1 == 1),
            scmp_cmp!($arg2 == 2),
            scmp_cmp!($arg3 == 3),
        ],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1005),
        &[scmp_cmp!($arg0 == 0), scmp_cmp!($arg1 == 11)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1005),
        &[
            scmp_cmp!($arg0 == 0),
            scmp_cmp!($arg1 == 1),
            scmp_cmp!($arg2 == 2),
            scmp_cmp!($arg3 == 33),
        ],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1006),
        &[scmp_cmp!($arg1 != 1), scmp_cmp!($arg2 == 0)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1006),
        &[scmp_cmp!($arg1 == 1), scmp_cmp!($arg2 == 2)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1006),
        &[scmp_cmp!($arg1 != 1)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Trap,
        ScmpSyscall::from(1007),
        &[scmp_cmp!($arg2 == 2), scmp_cmp!($arg3 == 3)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1007),
        &[scmp_cmp!($arg2 == 2), scmp_cmp!($arg3 != 3)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1007),
        &[scmp_cmp!($arg3 != 3)],
    )?;

    util_filter_output(&opts, &ctx)
}
