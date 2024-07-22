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

    ctx.remove_arch(ScmpArch::Native)?;
    // add x86-64 and x86 (in that order!) but explicitly leave out x32
    ctx.add_arch(ScmpArch::X8664)?;
    ctx.add_arch(ScmpArch::X86)?;
    ctx.add_rule(ScmpAction::Errno(1), ScmpSyscall::from_name("close")?)?;

    util_filter_output(&opts, &ctx)
}
