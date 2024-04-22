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
    ctx.precompute()?;
    ctx.add_rule_exact(ScmpAction::KillThread, ScmpSyscall::from(1000))?;
    ctx.precompute()?;
    ctx.add_rule_exact(ScmpAction::KillThread, ScmpSyscall::from(1001))?;
    ctx.precompute()?;

    util_filter_output(&opts, &ctx)
}
