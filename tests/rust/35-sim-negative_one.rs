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

    ctx.add_arch(ScmpArch::X86)?;
    ctx.add_arch(ScmpArch::X8664)?;

    ctx.set_filter_attr(ScmpFilterAttr::ApiTskip, 1)?;
    ctx.set_syscall_priority(ScmpSyscall::from(-1), 100)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from(-1))?;

    util_filter_output(&opts, &ctx)
}
