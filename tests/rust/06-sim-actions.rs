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

    set_api(3)?;

    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("read")?)?;
    ctx.add_rule(ScmpAction::Log, ScmpSyscall::from_name("rt_sigreturn")?)?;
    ctx.add_rule(
        ScmpAction::Errno(libc::EPERM),
        ScmpSyscall::from_name("write")?,
    )?;
    ctx.add_rule(ScmpAction::Trap, ScmpSyscall::from_name("close")?)?;
    ctx.add_rule(ScmpAction::Trace(1234), ScmpSyscall::from_name("openat")?)?;
    ctx.add_rule(ScmpAction::KillProcess, ScmpSyscall::from_name("fstatfs")?)?;

    util_filter_output(&opts, &ctx)
}
