// SPDX-License-Identifier: LGPL-2.1-only
//
// Copyright 2024 Sony Group Corporation
//
// Seccomp Library test program
//

use anyhow::Result;
use libseccomp::error::SeccompErrno;
use libseccomp::*;
use utils::*;

fn main() -> Result<()> {
    let opts = util_getopt();
    let mut ctx = ScmpFilterContext::new(ScmpAction::KillThread)?;

    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1001),
        &[scmp_cmp!($arg0 == 1), scmp_cmp!($arg1 == 2)],
    )?;
    ctx.add_rule_exact(ScmpAction::Allow, ScmpSyscall::from(1001))?;

    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1002),
        &[scmp_cmp!($arg0 == 1)],
    )?;
    let e = ctx
        .add_rule_conditional_exact(
            ScmpAction::Trap,
            ScmpSyscall::from(1002),
            &[scmp_cmp!($arg0 == 1)],
        )
        .unwrap_err();
    assert_eq!(e.errno().unwrap(), SeccompErrno::EEXIST);

    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1003),
        &[scmp_cmp!($arg0 != 1)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Trap,
        ScmpSyscall::from(1003),
        &[scmp_cmp!($arg0 == 1)],
    )?;

    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1004),
        &[scmp_cmp!($arg0 == 1)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Trap,
        ScmpSyscall::from(1004),
        &[scmp_cmp!($arg0 != 1)],
    )?;

    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1005),
        &[scmp_cmp!($arg0 == 1)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1005),
        &[scmp_cmp!($arg0 != 1)],
    )?;

    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1006),
        &[scmp_cmp!($arg0 == 1), scmp_cmp!($arg1 == 2)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1006),
        &[scmp_cmp!($arg0 == 1)],
    )?;

    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1007),
        &[scmp_cmp!($arg0 == 1)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1007),
        &[scmp_cmp!($arg0 == 1), scmp_cmp!($arg1 == 2)],
    )?;

    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1008),
        &[scmp_cmp!($arg0 != 1), scmp_cmp!($arg1 != 2)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1008),
        &[
            scmp_cmp!($arg0 != 1),
            scmp_cmp!($arg1 != 2),
            scmp_cmp!($arg2 != 3),
        ],
    )?;

    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1009),
        &[scmp_cmp!($arg0 == 1), scmp_cmp!($arg1 != 2)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1009),
        &[scmp_cmp!($arg0 != 1)],
    )?;

    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1010),
        &[scmp_cmp!($arg0 != 1), scmp_cmp!($arg1 == 2)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1010),
        &[scmp_cmp!($arg0 == 1)],
    )?;

    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1011),
        &[scmp_cmp!($arg0 == 1)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1011),
        &[scmp_cmp!($arg0 != 1), scmp_cmp!($arg2 == 1)],
    )?;

    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1012),
        &[scmp_cmp!($arg0 & 0x0000 == 1)],
    )?;

    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1013),
        &[scmp_cmp!($arg0 != 1), scmp_cmp!($arg1 != 2)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1013),
        &[scmp_cmp!($arg0 < 1), scmp_cmp!($arg1 != 2)],
    )?;

    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1014),
        &[scmp_cmp!($arg0 >= 1), scmp_cmp!($arg1 >= 2)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1014),
        &[scmp_cmp!($arg0 != 1), scmp_cmp!($arg1 != 2)],
    )?;

    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1015),
        &[scmp_cmp!($arg0 == 4), scmp_cmp!($arg1 == 1)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1015),
        &[scmp_cmp!($arg0 == 4), scmp_cmp!($arg1 != 1)],
    )?;

    util_filter_output(&opts, &ctx)
}
