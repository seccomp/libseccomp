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

    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(10),
        &[scmp_cmp!($arg0 == 11), scmp_cmp!($arg1 != 12)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from(20),
        &[
            scmp_cmp!($arg0 == 21),
            scmp_cmp!($arg1 != 22),
            scmp_cmp!($arg2 == 23),
        ],
    )?;

    util_filter_output(&opts, &ctx)
}
