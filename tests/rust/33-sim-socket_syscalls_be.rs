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

    ctx.remove_arch(ScmpArch::Native)?;

    ctx.add_arch(ScmpArch::S390)?;
    ctx.add_arch(ScmpArch::S390X)?;
    ctx.add_arch(ScmpArch::Ppc)?;

    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("socket")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("connect")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("accept")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("accept4")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("shutdown")?)?;

    util_filter_output(&opts, &ctx)
}
