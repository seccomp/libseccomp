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
        &[
            scmp_cmp!($arg0 == 0),
            scmp_cmp!($arg1 == 1),
            scmp_cmp!($arg2 == 2),
        ],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1000),
        &[
            scmp_cmp!($arg0 == 0),
            scmp_cmp!($arg1 & 0x00ff == 1),
            scmp_cmp!($arg2 == 2),
        ],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1000),
        &[
            scmp_cmp!($arg0 == 0),
            scmp_cmp!($arg1 & 0xffff == 11),
            scmp_cmp!($arg2 == 2),
        ],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1000),
        &[
            scmp_cmp!($arg0 == 0),
            scmp_cmp!($arg1 & 0xffff == 111),
            scmp_cmp!($arg2 == 2),
        ],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(1000),
        &[
            scmp_cmp!($arg0 == 0),
            scmp_cmp!($arg1 & 0xff00 == 1000),
            scmp_cmp!($arg2 == 2),
        ],
    )?;

    util_filter_output(&opts, &ctx)
}
