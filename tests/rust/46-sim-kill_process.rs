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
    set_api(3)?;
    let mut ctx = ScmpFilterContext::new(ScmpAction::KillProcess)?;

    ctx.remove_arch(ScmpArch::Native)?;

    ctx.add_arch(ScmpArch::X8664)?;

    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("read")?)?;
    ctx.add_rule(ScmpAction::Errno(5), ScmpSyscall::from_name("write")?)?;
    ctx.add_rule(ScmpAction::KillThread, ScmpSyscall::from_name("open")?)?;
    ctx.add_rule_conditional(
        ScmpAction::Errno(6),
        ScmpSyscall::from_name("close")?,
        &[scmp_cmp!($arg0 > 100)],
    )?;

    util_filter_output(&opts, &ctx)
}
