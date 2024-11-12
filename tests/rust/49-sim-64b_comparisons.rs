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
        ScmpSyscall::from(1000),
        &[scmp_cmp!($arg0 < 0x123456789abc)],
    )?;

    util_filter_output(&opts, &ctx)
}
